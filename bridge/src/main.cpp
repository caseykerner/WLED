// HomeGlow Bridge (prototype, Nov 2026)
//
// One small always-on device per home. It holds the single encrypted connection to the HomeGlow
// cloud (AWS IoT Core, certificate login) and talks to every WLED controller on the home network
// over WLED's normal local API. Controllers need no special firmware and spend no memory on the
// cloud. The app sends commands to hg/<controller>/cmd; the bridge passes them to that controller
// and publishes its status to hg/<controller>/state (retained).
//
//  - Wi-Fi setup: first boot (or no Wi-Fi) opens a "HomeGlow-Bridge" setup network.
//  - Controllers are found with mDNS (_wled._tcp) and checked every 5 minutes.
//  - Controllers that already hold their own cloud connection (hg firmware with the cloud on)
//    are left alone, so nothing is sent twice.
//  - Remote commands are limited to everyday light control, like the firmware module.
//  - Status light: blue = Wi-Fi setup, yellow = joining Wi-Fi, cyan = connecting to the cloud,
//    green = connected (dim), red = cloud trouble.
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <WiFiManager.h>
#include <LittleFS.h>
#include <vector>

// Cloud login, loaded onto each bridge after flashing (POST /provision from the home network),
// kept in /cloud.json. The firmware file itself holds no secrets.
static String cloudId, cloudEndpoint, cloudCa, cloudCert, cloudKey;
static bool provisioned = false;

#define BRIDGE_VERSION   "0.1.0"
#define CLOUD_FILE       "/cloud.json"
#define LED_PIN          48
#define POLL_EVERY_MS    30000UL
#define SCAN_EVERY_MS    300000UL
#define MAX_CMD          2048

struct Controller {
  String login;      // topic name: "house", "beerfridge"…
  String name;       // as set in WLED
  String ip;
  String mac;
  bool direct = false;     // holds its own cloud connection: leave it alone
  bool online = false;
  uint8_t misses = 0;
  uint32_t lastPoll = 0;
  bool pollSoon = true;
};

static std::vector<Controller> ctrls;
static WiFiClientSecure tls;
static PubSubClient mqtt(tls);
static WebServer web(80);
static uint32_t lastScan = 0, lastTry = 0;
static uint32_t cmdsIn = 0, cmdsSent = 0, cmdsRefused = 0, connects = 0;
static int lastMqttErr = 0;
static String stateTopicSelf;

struct Pending { String login; String body; };
static std::vector<Pending> pending;     // filled from mqtt.loop(), emptied in loop(): same task

static void led(uint8_t r, uint8_t g, uint8_t b) { neopixelWrite(LED_PIN, r, g, b); }

// The same names the app uses for its cloud logins.
static String loginFor(const String& name) {
  String n = name; n.toLowerCase();
  if (n.indexOf("house") >= 0) return "house";
  if (n.indexOf("beer") >= 0) return "beerfridge";
  if (n.indexOf("shop") >= 0) return "shop";
  if (n.indexOf("shed") >= 0) return "shed";
  if (n.indexOf("pergola") >= 0) return "pergola";
  String out;
  for (char c : n) if (isalnum((unsigned char)c)) out += c;
  return out.length() ? out : String("wled");
}

static Controller* byLogin(const String& login) {
  for (auto& c : ctrls) if (c.login == login) return &c;
  return nullptr;
}

// ---------- local WLED API ----------

static bool httpGetJson(const String& url, JsonDocument& doc, JsonDocument* filter = nullptr) {
  HTTPClient http;
  http.setTimeout(4000);
  http.setConnectTimeout(2500);
  if (!http.begin(url)) return false;
  int code = http.GET();
  bool ok = false;
  if (code == 200) {
    DeserializationError e = filter ? deserializeJson(doc, http.getStream(), DeserializationOption::Filter(*filter))
                                    : deserializeJson(doc, http.getStream());
    ok = !e;
  }
  http.end();
  return ok;
}

static bool httpPostJson(const String& url, const String& body) {
  HTTPClient http;
  http.setTimeout(4000);
  http.setConnectTimeout(2500);
  if (!http.begin(url)) return false;
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(body);
  http.end();
  return code == 200;
}

// Finds WLED controllers on the network and reads who they are.
static void scan() {
  lastScan = millis();
  int n = MDNS.queryService("wled", "tcp");
  for (int i = 0; i < n; i++) {
    String ip = MDNS.IP(i).toString();
    JsonDocument filter;
    filter["name"] = true; filter["mac"] = true; filter["hgCloud"]["en"] = true; filter["hgCloud"]["conn"] = true;
    JsonDocument info;
    if (!httpGetJson("http://" + ip + "/json/info", info, &filter)) continue;
    String mac = info["mac"] | "";
    String name = info["name"] | "WLED";
    bool direct = (info["hgCloud"]["en"] | false);
    Controller* c = nullptr;
    for (auto& x : ctrls) if (x.mac == mac && mac.length()) c = &x;
    if (!c) { ctrls.push_back(Controller()); c = &ctrls.back(); c->mac = mac; }
    c->ip = ip; c->name = name; c->login = loginFor(name); c->direct = direct;
    Serial.printf("[scan] %s %s login=%s%s\n", ip.c_str(), name.c_str(), c->login.c_str(), direct ? " (own cloud link: skipped)" : "");
  }
}

// ---------- cloud ----------

static bool allowedKey(const char* k) {
  static const char* const ok[] = {"on", "bri", "ps", "pl", "transition", "tt", "nl", "seg", "mainseg", "v"};
  for (const char* a : ok) if (!strcmp(k, a)) return true;
  return false;
}
static bool allowedSegKey(const char* k) {
  static const char* const ok[] = {"id", "on", "bri", "col", "fx", "sx", "ix", "pal", "c1", "c2", "c3", "o1", "o2", "o3", "sel", "rev", "mi", "frz"};
  for (const char* a : ok) if (!strcmp(k, a)) return true;
  return false;
}

static void onMessage(char* topic, uint8_t* payload, unsigned int len) {
  cmdsIn++;
  String t(topic);                         // hg/<login>/cmd
  int a = t.indexOf('/'), b = t.lastIndexOf('/');
  if (a < 0 || b <= a || len == 0 || len > MAX_CMD) { cmdsRefused++; return; }
  Pending p; p.login = t.substring(a + 1, b);
  p.body = String((const char*)payload, len);
  pending.push_back(p);
}

static void publishState(Controller& c, JsonDocument* state, JsonDocument* info) {
  if (!mqtt.connected()) return;
  JsonDocument out;
  out["online"] = c.online;
  out["via"] = "bridge";
  if (c.online && state) {
    out["on"] = (*state)["on"] | false;
    out["bri"] = (*state)["bri"] | 0;
    out["ps"] = (*state)["ps"] | -1;
    out["pl"] = (*state)["pl"] | -1;
  }
  if (c.online && info) {
    out["heap"] = (*info)["freeheap"] | 0;
    out["up"] = (*info)["uptime"] | 0;
    out["ver"] = (*info)["ver"] | "";
  }
  String s; serializeJson(out, s);
  mqtt.publish(("hg/" + c.login + "/state").c_str(), s.c_str(), true);
}

static void poll(Controller& c) {
  c.lastPoll = millis(); c.pollSoon = false;
  JsonDocument fs; fs["on"] = true; fs["bri"] = true; fs["ps"] = true; fs["pl"] = true;
  JsonDocument fi; fi["freeheap"] = true; fi["uptime"] = true; fi["ver"] = true; fi["hgCloud"]["en"] = true;
  JsonDocument state, info;
  bool ok = httpGetJson("http://" + c.ip + "/json/state", state, &fs) && httpGetJson("http://" + c.ip + "/json/info", info, &fi);
  if (ok) {
    c.misses = 0;
    c.direct = info["hgCloud"]["en"] | false;
    if (c.direct) return;                  // it speaks for itself
    bool was = c.online; c.online = true;
    publishState(c, &state, &info);
    if (!was) Serial.printf("[poll] %s online\n", c.login.c_str());
  } else if (++c.misses >= 3 && c.online) {
    c.online = false;
    publishState(c, nullptr, nullptr);
    Serial.printf("[poll] %s offline\n", c.login.c_str());
  }
}

static void apply(const Pending& p) {
  Controller* c = byLogin(p.login);
  if (!c || c->direct || c->ip.isEmpty()) { cmdsRefused++; return; }
  JsonDocument doc;
  if (deserializeJson(doc, p.body) || !doc.is<JsonObject>()) { cmdsRefused++; return; }
  JsonObject root = doc.as<JsonObject>();
  std::vector<String> drop;
  for (JsonPair kv : root) if (!allowedKey(kv.key().c_str())) drop.push_back(kv.key().c_str());
  for (auto& k : drop) root.remove(k);
  auto cleanSeg = [](JsonObject s) {
    std::vector<String> d;
    for (JsonPair kv : s) if (!allowedSegKey(kv.key().c_str())) d.push_back(kv.key().c_str());
    for (auto& k : d) s.remove(k);
  };
  if (root["seg"].is<JsonArray>()) for (JsonObject s : root["seg"].as<JsonArray>()) cleanSeg(s);
  else if (root["seg"].is<JsonObject>()) cleanSeg(root["seg"].as<JsonObject>());
  if (root.size() == 0) { cmdsRefused++; return; }
  String body; serializeJson(root, body);
  if (httpPostJson("http://" + c->ip + "/json/state", body)) cmdsSent++; else cmdsRefused++;
  c->pollSoon = true;                      // report the new state right away
}

static void connectCloud() {
  lastTry = millis();
  led(0, 40, 40);
  mqtt.setServer(cloudEndpoint.c_str(), 8883);
  String willTopic = stateTopicSelf;
  if (mqtt.connect(cloudId.c_str(), willTopic.c_str(), 1, true, "{\"online\":false}")) {
    connects++; lastMqttErr = 0;
    mqtt.subscribe("hg/+/cmd", 1);
    JsonDocument me; me["online"] = true; me["ver"] = BRIDGE_VERSION; me["ip"] = WiFi.localIP().toString();
    String s; serializeJson(me, s);
    mqtt.publish(stateTopicSelf.c_str(), s.c_str(), true);
    for (auto& c : ctrls) c.pollSoon = true;
    led(0, 12, 0);
    Serial.println("[cloud] connected");
  } else {
    lastMqttErr = mqtt.state();
    led(40, 0, 0);
    Serial.printf("[cloud] failed (%d)\n", lastMqttErr);
  }
}

// ---------- local status page and firmware update ----------

static void webRoot() {
  String h = "<!doctype html><meta name=viewport content='width=device-width'><title>HomeGlow Bridge</title>"
             "<style>body{font:15px -apple-system,sans-serif;background:#111;color:#eee;padding:16px}td{padding:4px 10px}</style>"
             "<h2>HomeGlow Bridge " BRIDGE_VERSION "</h2><p>Cloud: ";
  h += !provisioned ? String("needs its cloud login") : (mqtt.connected() ? String("connected") : ("not connected (" + String(lastMqttErr) + ")"));
  h += "<br>Free memory: " + String(ESP.getFreeHeap() / 1024) + " KB · extra memory: " + String(ESP.getFreePsram() / 1024) + " KB";
  h += "<br>Commands: " + String(cmdsIn) + " in, " + String(cmdsSent) + " passed on, " + String(cmdsRefused) + " refused</p><table>";
  for (auto& c : ctrls) {
    h += "<tr><td>" + c.name + "</td><td>" + c.ip + "</td><td>" + c.login + "</td><td>" +
         (c.direct ? "own cloud link" : (c.online ? "online" : "offline")) + "</td></tr>";
  }
  h += "</table><p><form method=POST action=/update enctype=multipart/form-data><input type=file name=fw> <button>Update firmware</button></form>";
  web.send(200, "text/html", h);
}

static void webUpdateDone() {
  web.send(200, "text/plain", Update.hasError() ? "Update failed" : "Updated, restarting");
  delay(500);
  if (!Update.hasError()) ESP.restart();
}

static void webUpdateChunk() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) Update.begin(UPDATE_SIZE_UNKNOWN);
  else if (u.status == UPLOAD_FILE_WRITE) Update.write(u.buf, u.currentSize);
  else if (u.status == UPLOAD_FILE_END) Update.end(true);
}

static void webStatusJson() {
  JsonDocument d;
  d["ver"] = BRIDGE_VERSION; d["id"] = cloudId; d["provisioned"] = provisioned; d["cloud"] = mqtt.connected(); d["err"] = lastMqttErr;
  d["connects"] = connects; d["in"] = cmdsIn; d["sent"] = cmdsSent; d["refused"] = cmdsRefused;
  d["heap"] = ESP.getFreeHeap(); d["psram"] = ESP.getFreePsram(); d["up"] = millis() / 1000;
  JsonArray a = d["controllers"].to<JsonArray>();
  for (auto& c : ctrls) {
    JsonObject o = a.add<JsonObject>();
    o["name"] = c.name; o["ip"] = c.ip; o["login"] = c.login; o["online"] = c.online; o["direct"] = c.direct;
  }
  String s; serializeJson(d, s);
  web.sendHeader("Access-Control-Allow-Origin", "*");
  web.send(200, "application/json", s);
}

static bool loadCloud() {
  File f = LittleFS.open(CLOUD_FILE, "r");
  if (!f) return false;
  JsonDocument d;
  bool ok = !deserializeJson(d, f);
  f.close();
  if (!ok) return false;
  cloudId = d["id"] | ""; cloudEndpoint = d["endpoint"] | "";
  cloudCa = d["ca"] | ""; cloudCert = d["cert"] | ""; cloudKey = d["key"] | "";
  return cloudId.length() && cloudEndpoint.length() && cloudCa.indexOf("BEGIN") >= 0 &&
         cloudCert.indexOf("BEGIN") >= 0 && cloudKey.indexOf("PRIVATE KEY") >= 0;
}

// Prototype: accepted from the home network. A shipping bridge would only take this during setup
// (button held, or straight after Wi-Fi setup) so nobody else on the network can swap the login.
static void webProvision() {
  String body = web.arg("plain");
  JsonDocument d;
  if (deserializeJson(d, body) || !(d["cert"].is<const char*>())) { web.send(400, "text/plain", "bad"); return; }
  File f = LittleFS.open(CLOUD_FILE, "w");
  if (!f) { web.send(500, "text/plain", "storage"); return; }
  f.print(body); f.close();
  web.sendHeader("Access-Control-Allow-Origin", "*");
  web.send(200, "text/plain", "saved, restarting");
  delay(500);
  ESP.restart();
}

static void webCors() {
  web.sendHeader("Access-Control-Allow-Origin", "*");
  web.sendHeader("Access-Control-Allow-Methods", "GET, POST");
  web.sendHeader("Access-Control-Allow-Headers", "Content-Type");
  web.send(204);
}

// ---------- setup / loop ----------

void setup() {
  Serial.begin(115200);
  led(0, 0, 40);
  LittleFS.begin(true);
  provisioned = loadCloud();
  stateTopicSelf = String("hg/") + (cloudId.length() ? cloudId : String("bridge")) + "/state";

  WiFi.mode(WIFI_STA);
  WiFi.setHostname("homeglow-bridge");
  WiFiManager wm;
  wm.setConfigPortalTimeout(600);
  wm.setTitle("HomeGlow Bridge");
  led(40, 30, 0);
  if (!wm.autoConnect("HomeGlow-Bridge")) ESP.restart();
  WiFi.setSleep(false);

  MDNS.begin("homeglow-bridge");
  MDNS.addService("http", "tcp", 80);

  // The bridge checks the cloud's certificate against Amazon Root CA 1 only, and logs in with its own.
  if (provisioned) {
    tls.setCACert(cloudCa.c_str());
    tls.setCertificate(cloudCert.c_str());
    tls.setPrivateKey(cloudKey.c_str());
  }
  mqtt.setBufferSize(MAX_CMD + 256);
  mqtt.setKeepAlive(60);
  mqtt.setCallback(onMessage);

  web.on("/", webRoot);
  web.on("/json", webStatusJson);
  web.on("/update", HTTP_POST, webUpdateDone, webUpdateChunk);
  web.on("/provision", HTTP_POST, webProvision);
  web.on("/provision", HTTP_OPTIONS, webCors);
  web.begin();

  scan();
  if (provisioned) connectCloud(); else led(40, 0, 40);   // purple: needs its cloud login
}

void loop() {
  web.handleClient();
  if (WiFi.status() != WL_CONNECTED) { led(40, 30, 0); delay(200); return; }
  if (!provisioned) { /* waiting for /provision */ }
  else if (!mqtt.connected()) {
    if (millis() - lastTry > 15000) connectCloud();
  } else mqtt.loop();

  std::vector<Pending> todo;
  todo.swap(pending);
  for (auto& p : todo) apply(p);

  if (millis() - lastScan > SCAN_EVERY_MS) scan();
  for (auto& c : ctrls) {
    if (c.pollSoon || millis() - c.lastPoll > POLL_EVERY_MS) { poll(c); break; }   // one per pass keeps it responsive
  }
  delay(5);
}
