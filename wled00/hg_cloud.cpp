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
// Encryption is BearSSL (ESP_SSLClient): WLED's ESP32 framework (Tasmota 2.0.18) is built
// with TLS switched off, so the built-in client can't be used. The connection runs in its own
// task, so the TLS handshake never stalls the lights.
//
// Topics: hg/<login>/cmd (in), hg/<login>/state (out, retained).
// Reported in /json/info as hgCloud.
#ifdef ARDUINO_ARCH_ESP32
#include "wled.h"
#include <WiFiClient.h>
// WLED builds everything with -DBEARSSL_SSL_BASIC (meant for ESP8266 boards), which turns off
// elliptic-curve keys in this header-only client. The test certificates are P-256, so turn it off here.
#undef BEARSSL_SSL_BASIC
#include <ESP_SSLClient.h>
#include <PubSubClient.h>

#define HG_CLOUD_FILE   "/hgcloud.wsec.json"
#define HG_CLOUD_MAXCMD 2048
#define HG_STATE_EVERY  60000UL

static String hgHost, hgUser, hgPass, hgCa, hgCert, hgKey, hgCmdTopic, hgStateTopic;
static uint16_t hgPort = 8883;
static bool hgLoaded = false, hgEnabled = false, hgStarted = false;
static volatile bool hgConnected = false;
static char* hgPending = nullptr;          // newest command, handed from the cloud task to the main loop
static char* hgOutState = nullptr;        // newest status, handed from the main loop to the cloud task
static portMUX_TYPE hgMux = portMUX_INITIALIZER_UNLOCKED;
static volatile uint32_t hgCmds = 0, hgRejected = 0, hgConnects = 0;
static volatile int32_t hgLastErr = 0;
static volatile uint32_t hgHeapBefore = 0, hgHeapConnected = 0;
static uint32_t hgLastState = 0;
static volatile bool hgSendState = true;
static uint8_t hgLastBri = 0; static int16_t hgLastPs = -2;

static WiFiClient* hgTcp = nullptr;
static ESP_SSLClient* hgTls = nullptr;
static PubSubClient* hgMqtt = nullptr;

static void hgLoad() {
  hgLoaded = true;
  File f = WLED_FS.open(HG_CLOUD_FILE, "r");
  if (!f) return;
  DynamicJsonDocument doc(6144);           // server certificate plus, for AWS, our own certificate and key
  DeserializationError e = deserializeJson(doc, f);
  f.close();
  if (e) return;
  hgEnabled = doc["en"] | false;
  String uri = doc["uri"] | "";             // mqtts://host:port
  hgUser = doc["user"] | "";
  hgPass = doc["pass"] | "";
  hgCa   = doc["ca"]   | "";
  hgCert = doc["cert"] | "";               // optional: this controller's own certificate and key
  hgKey  = doc["key"]  | "";               // (AWS IoT style login instead of a password)
  int s = uri.indexOf("://");
  String hp = s >= 0 ? uri.substring(s + 3) : uri;
  int c = hp.lastIndexOf(':');
  hgHost = c > 0 ? hp.substring(0, c) : hp;
  hgPort = c > 0 ? hp.substring(c + 1).toInt() : 8883;
  bool certLogin = hgCert.indexOf("BEGIN CERTIFICATE") >= 0 && hgKey.indexOf("PRIVATE KEY") >= 0;
  if (hgHost.isEmpty() || hgUser.isEmpty() || (hgPass.isEmpty() && !certLogin) || hgCa.indexOf("BEGIN CERTIFICATE") < 0) hgEnabled = false;
  if (!certLogin) { hgCert = ""; hgKey = ""; }
  hgCmdTopic   = "hg/" + hgUser + "/cmd";
  hgStateTopic = "hg/" + hgUser + "/state";
}

static void hgOnMessage(char* topic, uint8_t* payload, unsigned int len) {
  if (len == 0 || len > HG_CLOUD_MAXCMD) { hgRejected++; return; }
  char* buf = (char*)malloc(len + 1);
  if (!buf) { hgRejected++; return; }
  memcpy(buf, payload, len);
  buf[len] = 0;
  portENTER_CRITICAL(&hgMux);
  char* old = hgPending;
  hgPending = buf;                         // only the newest command matters
  portEXIT_CRITICAL(&hgMux);
  free(old);
}

// Connects (pinned certificate authority; the server's name is checked too when it's a
// name rather than an address) and logs in, then keeps the connection serviced.
static void hgTask(void*) {
  uint32_t nextTry = 0;
  for (;;) {
    if (!hgMqtt->connected()) {
      hgConnected = false;
      if ((int32_t)(millis() - nextTry) >= 0 && WLED_CONNECTED) {
        nextTry = millis() + 15000;
        hgHeapBefore = ESP.getFreeHeap();
        hgTls->stop();
        hgTls->setX509Time(toki.second());   // certificates are checked against the time
        IPAddress ip;
        // port 8883 is on the client's list of TLS ports, so connect() encrypts
        bool ok = ip.fromString(hgHost) ? hgTls->connect(ip, hgPort) : hgTls->connect(hgHost.c_str(), hgPort);
        if (!ok) { hgLastErr = -10; }
        else if (!(hgCert.length()
                   ? hgMqtt->connect(hgUser.c_str(), hgStateTopic.c_str(), 1, true, "{\"online\":false}")   // the certificate is the login
                   : hgMqtt->connect(hgUser.c_str(), hgUser.c_str(), hgPass.c_str(), hgStateTopic.c_str(), 1, true, "{\"online\":false}"))) {
          hgLastErr = hgMqtt->state();
          hgTls->stop();
        } else {
          hgMqtt->subscribe(hgCmdTopic.c_str(), 1);
          hgConnected = true;
          hgConnects++;
          hgLastErr = 0;
          hgHeapConnected = ESP.getFreeHeap();
          hgSendState = true;
        }
      }
    } else {
      hgMqtt->loop();
      char* out = nullptr;
      portENTER_CRITICAL(&hgMux);
      out = hgOutState; hgOutState = nullptr;
      portEXIT_CRITICAL(&hgMux);
      if (out) { hgMqtt->publish(hgStateTopic.c_str(), out, true); free(out); }
    }
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

static void hgStart() {
  hgStarted = true;
  hgTcp = new WiFiClient();
  hgTls = new ESP_SSLClient();
  hgTls->setClient(hgTcp);
  hgTls->setCACert(hgCa.c_str());          // pinned: only this certificate authority
  if (hgCert.length()) {
    hgTls->setCertificate(hgCert.c_str());
    if (hgKey.indexOf("EC PRIVATE KEY") >= 0)  // elliptic-curve key, certificate signed by an RSA authority (AWS)
      hgTls->setPrivateECKey(hgKey.c_str(), BR_KEYTYPE_SIGN, BR_KEYTYPE_RSA);
    else hgTls->setPrivateKey(hgKey.c_str());
  }
  hgTls->setBufferSizes(4096, 1024);
  hgTls->setTimeout(10000);
  hgTls->setDebugLevel(0);
  hgMqtt = new PubSubClient(*hgTls);
  hgMqtt->setServer(hgHost.c_str(), hgPort);
  hgMqtt->setCallback(hgOnMessage);
  hgMqtt->setBufferSize(HG_CLOUD_MAXCMD + 128);
  hgMqtt->setKeepAlive(60);
  hgMqtt->setSocketTimeout(10);
  if (xTaskCreatePinnedToCore(hgTask, "hgCloud", 10240, nullptr, 1, nullptr, 0) != pdPASS) hgLastErr = -3;
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

static void hgQueueState() {
  char msg[256];
  int n = snprintf(msg, sizeof(msg),
    "{\"online\":true,\"on\":%s,\"bri\":%u,\"ps\":%d,\"pl\":%d,\"heap\":%u,\"minHeap\":%u,\"up\":%lu,\"ver\":\"%s\"}",
    bri > 0 ? "true" : "false", bri, (int)currentPreset, (int)currentPlaylist,
    ESP.getFreeHeap(), ESP.getMinFreeHeap(), (unsigned long)(millis() / 1000), versionString);
  char* out = (char*)malloc(n + 1);
  if (!out) return;
  memcpy(out, msg, n + 1);
  portENTER_CRITICAL(&hgMux);
  char* old = hgOutState;
  hgOutState = out;
  portEXIT_CRITICAL(&hgMux);
  free(old);
  hgLastState = millis();
  hgLastBri = bri; hgLastPs = currentPreset;
}

void hgCloudLoop() {
  if (!hgLoaded) hgLoad();
  if (!hgEnabled) return;
  if (!hgStarted) {
    if (WLED_CONNECTED && toki.getTimeSource() >= TOKI_TS_SEC) hgStart();   // certificates need the right time
    return;
  }
  char* cmd = nullptr;
  portENTER_CRITICAL(&hgMux);
  cmd = hgPending; hgPending = nullptr;
  portEXIT_CRITICAL(&hgMux);
  if (cmd) { hgApply(cmd); free(cmd); }
  // status: after a command, when something changed here, and every minute
  if (hgConnected && (hgSendState || bri != hgLastBri || currentPreset != hgLastPs || millis() - hgLastState > HG_STATE_EVERY)) {
    hgSendState = false;
    hgQueueState();
  }
}

void hgCloudInfo(JsonObject root) {
  JsonObject c = root.createNestedObject(F("hgCloud"));
  c[F("en")] = hgEnabled;
  if (!hgEnabled) return;
  c[F("conn")] = (bool)hgConnected;
  c[F("login")] = hgCert.length() ? F("cert") : F("password");
  c[F("connects")] = hgConnects;
  c[F("cmds")] = hgCmds;
  c[F("rejected")] = hgRejected;
  c[F("err")] = hgLastErr;
  c[F("heapBefore")] = hgHeapBefore;       // free memory just before the encrypted connection started
  c[F("heapConnected")] = hgHeapConnected; // free memory right after it connected
}
#endif
