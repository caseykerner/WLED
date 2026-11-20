// HomeGlow cloud (test): lets the HomeGlow app reach this controller away from home.
//
// The controller keeps one encrypted connection OUT to a HomeGlow server (MQTT over TLS),
// so nothing on the home router has to be opened. The app sends commands to the server,
// which passes them down that connection.
//
//  - Off unless HomeGlow put /hgcloud.wsec.json on the controller (over the home network).
//    That file holds the server, this controller's own login and the certificate the server
//    must present. "wsec.json" in its name gives it the same protection as WLED's Wi-Fi
//    passwords: not listed, and never served back over HTTP.
//  - The server's certificate is checked against that pinned certificate (no other server).
//  - Remote commands are limited to everyday light control (on/off, brightness, looks,
//    playlists, segment colors and effects). Settings, files, restarts and updates are
//    removed before the command is applied, so they stay home-network only.
//  - Commands are queued and applied in the main loop (never from the network task).
//  - If the server can't be reached, nothing changes: the lights keep their own schedule.
//
// Topics: hg/<login>/cmd (in), hg/<login>/state (out, retained).
// Reported in /json/info as hgCloud.
#ifdef ARDUINO_ARCH_ESP32
#include "wled.h"
#include "mqtt_client.h"

#define HG_CLOUD_FILE  "/hgcloud.wsec.json"
#define HG_CLOUD_MAXCMD 2048
#define HG_STATE_EVERY 60000UL

static esp_mqtt_client_handle_t hgClient = nullptr;
static String hgUri, hgUser, hgPass, hgCa, hgCmdTopic, hgStateTopic;
static bool hgLoaded = false, hgEnabled = false;
static volatile bool hgConnected = false;
static char* hgPending = nullptr;
static portMUX_TYPE hgMux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t hgCmds = 0, hgRejected = 0, hgConnects = 0, hgLastState = 0;
static int32_t hgLastErr = 0;
static uint32_t hgHeapBefore = 0, hgHeapConnected = 0;
static volatile bool hgSendState = true;
static uint8_t hgLastBri = 0; static int16_t hgLastPs = -2;

static void hgLoad() {
  hgLoaded = true;
  File f = WLED_FS.open(HG_CLOUD_FILE, "r");
  if (!f) return;
  StaticJsonDocument<2048> doc;   // the certificate is ~600 bytes
  DeserializationError e = deserializeJson(doc, f);
  f.close();
  if (e) return;
  hgEnabled = doc["en"] | false;
  hgUri  = doc["uri"]  | "";
  hgUser = doc["user"] | "";
  hgPass = doc["pass"] | "";
  hgCa   = doc["ca"]   | "";
  if (hgUri.isEmpty() || hgUser.isEmpty() || hgPass.isEmpty() || hgCa.indexOf("BEGIN CERTIFICATE") < 0) hgEnabled = false;
  hgCmdTopic   = "hg/" + hgUser + "/cmd";
  hgStateTopic = "hg/" + hgUser + "/state";
}

static void hgEvent(void*, esp_event_base_t, int32_t id, void* data) {
  esp_mqtt_event_handle_t e = (esp_mqtt_event_handle_t)data;
  switch (id) {
    case MQTT_EVENT_CONNECTED:
      hgConnected = true;
      hgConnects++;
      hgHeapConnected = ESP.getFreeHeap();
      esp_mqtt_client_subscribe(hgClient, hgCmdTopic.c_str(), 1);
      hgSendState = true;
      break;
    case MQTT_EVENT_DISCONNECTED:
      hgConnected = false;
      break;
    case MQTT_EVENT_DATA: {
      // whole, small messages only (a command is a few hundred bytes)
      if (e->current_data_offset != 0 || e->data_len != e->total_data_len || e->data_len <= 0 || e->data_len > HG_CLOUD_MAXCMD) { hgRejected++; break; }
      char* buf = (char*)malloc(e->data_len + 1);
      if (!buf) { hgRejected++; break; }
      memcpy(buf, e->data, e->data_len);
      buf[e->data_len] = 0;
      portENTER_CRITICAL(&hgMux);
      char* old = hgPending;
      hgPending = buf;            // only the newest command matters
      portEXIT_CRITICAL(&hgMux);
      free(old);
      break;
    }
    case MQTT_EVENT_ERROR:
      if (e->error_handle) hgLastErr = e->error_handle->esp_tls_last_esp_err ? e->error_handle->esp_tls_last_esp_err : (int32_t)e->error_handle->error_type;
      break;
    default: break;
  }
}

static void hgStart() {
  hgHeapBefore = ESP.getFreeHeap();
  esp_mqtt_client_config_t cfg = {};
  cfg.uri = hgUri.c_str();
  cfg.username = hgUser.c_str();
  cfg.password = hgPass.c_str();
  cfg.client_id = hgUser.c_str();
  cfg.cert_pem = hgCa.c_str();                 // pinned: only this certificate authority
  cfg.skip_cert_common_name_check = false;
  cfg.keepalive = 60;
  cfg.reconnect_timeout_ms = 15000;
  cfg.network_timeout_ms = 10000;
  cfg.buffer_size = 1024;
  cfg.task_stack = 6144;
  cfg.lwt_topic = hgStateTopic.c_str();
  cfg.lwt_msg = "{\"online\":false}";
  cfg.lwt_retain = 1;
  cfg.lwt_qos = 1;
  hgClient = esp_mqtt_client_init(&cfg);
  if (!hgClient) { hgLastErr = -2; return; }
  esp_mqtt_client_register_event(hgClient, (esp_mqtt_event_id_t)ESP_EVENT_ANY_ID, hgEvent, nullptr);
  if (esp_mqtt_client_start(hgClient) != ESP_OK) hgLastErr = -3;
}

// Keeps only everyday light control; everything else stays home-network only.
static bool hgAllowedKey(const char* k) {
  static const char* const ok[] = {"on", "bri", "ps", "pl", "transition", "tt", "nl", "seg", "mainseg", "v"};
  for (const char* a : ok) if (!strcmp(k, a)) return true;
  return false;
}
static bool hgAllowedSegKey(const char* k) {
  static const char* const ok[] = {"id", "on", "bri", "col", "fx", "sx", "ix", "pal", "c1", "c2", "c3", "o1", "o2", "o3", "sel", "rev", "mi", "frz"};
  for (const char* a : ok) if (!strcmp(k, a)) return true;
  return false;
}

static void hgApply(char* cmd) {
  if (!requestJSONBufferLock(JSON_LOCK_REMOTE)) { hgRejected++; return; }
  DeserializationError err = deserializeJson(*pDoc, cmd);
  JsonObject root = pDoc->as<JsonObject>();
  if (err || root.isNull()) { releaseJSONBufferLock(); hgRejected++; return; }
  // drop anything that isn't everyday light control
  std::vector<String> drop;
  for (JsonPair kv : root) if (!hgAllowedKey(kv.key().c_str())) drop.push_back(kv.key().c_str());
  for (auto& k : drop) root.remove(k);
  auto cleanSeg = [](JsonObject s) {
    std::vector<String> d;
    for (JsonPair kv : s) if (!hgAllowedSegKey(kv.key().c_str())) d.push_back(kv.key().c_str());
    for (auto& k : d) s.remove(k);
  };
  if (root["seg"].is<JsonArray>()) for (JsonObject s : root["seg"].as<JsonArray>()) cleanSeg(s);
  else if (root["seg"].is<JsonObject>()) cleanSeg(root["seg"].as<JsonObject>());
  bool any = root.size() > 0;
  if (any) deserializeState(root, CALL_MODE_DIRECT_CHANGE);
  releaseJSONBufferLock();
  if (any) { hgCmds++; hgSendState = true; } else hgRejected++;
}

static void hgPublishState() {
  if (!hgClient || !hgConnected) return;
  char msg[256];
  snprintf(msg, sizeof(msg),
    "{\"online\":true,\"on\":%s,\"bri\":%u,\"ps\":%d,\"pl\":%d,\"heap\":%u,\"minHeap\":%u,\"up\":%lu,\"ver\":\"%s\"}",
    bri > 0 ? "true" : "false", bri, (int)currentPreset, (int)currentPlaylist,
    ESP.getFreeHeap(), ESP.getMinFreeHeap(), (unsigned long)(millis() / 1000), versionString);
  esp_mqtt_client_publish(hgClient, hgStateTopic.c_str(), msg, 0, 1, 1);
  hgLastState = millis();
  hgLastBri = bri; hgLastPs = currentPreset;
}

void hgCloudLoop() {
  if (!hgLoaded) hgLoad();
  if (!hgEnabled) return;
  if (!hgClient) {
    if (WLED_CONNECTED && toki.getTimeSource() >= TOKI_TS_SEC) hgStart();   // certificates need the right time
    return;
  }
  char* cmd = nullptr;
  portENTER_CRITICAL(&hgMux);
  cmd = hgPending; hgPending = nullptr;
  portEXIT_CRITICAL(&hgMux);
  if (cmd) { hgApply(cmd); free(cmd); }
  // state: after a command, when something changed here, and every minute
  if (hgConnected && (hgSendState || bri != hgLastBri || currentPreset != hgLastPs || millis() - hgLastState > HG_STATE_EVERY)) {
    hgSendState = false;
    hgPublishState();
  }
}

void hgCloudInfo(JsonObject root) {
  JsonObject c = root.createNestedObject(F("hgCloud"));
  c[F("en")] = hgEnabled;
  if (!hgEnabled) return;
  c[F("conn")] = (bool)hgConnected;
  c[F("connects")] = hgConnects;
  c[F("cmds")] = hgCmds;
  c[F("rejected")] = hgRejected;
  c[F("err")] = hgLastErr;
  c[F("heapBefore")] = hgHeapBefore;       // free memory just before the encrypted connection started
  c[F("heapConnected")] = hgHeapConnected; // free memory right after it connected
}
#endif
