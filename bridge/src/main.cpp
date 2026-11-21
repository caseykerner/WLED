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
//  - Tunnel (0.2): the app can also make its normal home-network requests through the bridge
//    (read and save looks, schedules, zones...) so every HomeGlow feature works away from home.
//    Requests arrive on hg/req/<controller>, answers go to hg/resp/<app client>, both split into
//    parts of up to 48 KB. Wi-Fi, network, firmware and password settings are never passed on.
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
#include <string>
#include <algorithm>

// Cloud login, loaded onto each bridge after flashing (POST /provision from the home network),
// kept in /cloud.json. The firmware file itself holds no secrets.
static String cloudId, cloudEndpoint, cloudCa, cloudCert, cloudKey;
static bool provisioned = false;

#define BRIDGE_VERSION   "0.2.1"
#define TUN_PART         48000
#define TUN_MAX_BODY     (200 * 1024)
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

// A tunnelled HTTP request, collected from its parts.
struct TunReq {
  String id, reply, login, method, path, ct;
  int parts = 1, got = 0;
  bool bad = false;
  std::string body;
  uint32_t started = 0;
};
static std::vector<TunReq> tunIn;        // still collecting parts
static std::vector<TunReq> tunReady;     // complete, waiting to run
static uint32_t tunDone = 0, tunRefused = 0;
static std::vector<String> tunRefusedLog;   // last few refused requests, for the status page
static void noteRefused(const String& what) {
  tunRefusedLog.push_back(what);
  if (tunRefusedLog.size() > 12) tunRefusedLog.erase(tunRefusedLog.begin());
}

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

static void onTunnel(const String& login, uint8_t* payload, unsigned int len) {
  unsigned int nl = 0;
  while (nl < len && payload[nl] != '\n') nl++;
  if (nl >= len) { tunRefused++; return; }
  JsonDocument h;
  if (deserializeJson(h, (const char*)payload, nl)) { tunRefused++; return; }
  String id = h["id"] | "";
  if (id.isEmpty()) { tunRefused++; return; }
  int part = h["i"] | 0, parts = h["n"] | 1;
  TunReq* r = nullptr;
  for (auto& x : tunIn) if (x.id == id) r = &x;
  if (!r) {
    if (part != 0) { tunRefused++; return; }
    tunIn.push_back(TunReq()); r = &tunIn.back();
    r->id = id; r->reply = h["c"] | ""; r->login = login; r->method = h["m"] | "GET";
    r->path = h["p"] | "/"; r->ct = h["ct"] | ""; r->parts = parts < 1 ? 1 : parts; r->started = millis();
  }
  if (part != r->got || r->body.size() + (len - nl - 1) > TUN_MAX_BODY) r->bad = true;
  else r->body.append((const char*)payload + nl + 1, len - nl - 1);
  r->got++;
  if (r->got >= r->parts) {
    tunReady.push_back(*r);
    for (size_t i = 0; i < tunIn.size(); i++) if (tunIn[i].id == id) { tunIn.erase(tunIn.begin() + i); break; }
  }
}

static void onMessage(char* topic, uint8_t* payload, unsigned int len) {
  String tt(topic);
  if (tt.startsWith("hg/req/")) { onTunnel(tt.substring(7), payload, len); return; }
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

// What the tunnel passes on. The app needs to read and write looks, schedules, zones and light
// settings; it never needs Wi-Fi, network, access-point, firmware or password settings.
static bool tunAllowed(TunReq& r) {
  String p = r.path, bare = p;
  int q = bare.indexOf('?'); if (q >= 0) bare = bare.substring(0, q);
  String lower = p; lower.toLowerCase();
  if (lower.indexOf("sec") >= 0 || lower.indexOf("update") >= 0 || lower.indexOf("reset") >= 0 ||
      lower.indexOf("settings") >= 0 || lower.indexOf("..") >= 0) return false;
  if (r.method == "GET") {
    if (bare.startsWith("/json")) return true;
    if (bare.endsWith(".json") && lower.indexOf("cfg") < 0) return true;
    if (bare == "/edit") {
      if (lower.indexOf("list=") >= 0) return true;
      if (lower.indexOf("func=delete") >= 0 && lower.indexOf(".json") >= 0 && lower.indexOf("cfg") < 0) return true;
    }
    return false;
  }
  if (r.method == "DELETE") return bare == "/edit" && lower.indexOf("cfg") < 0 &&
                                   String(r.body.c_str()).indexOf(".json") >= 0 && String(r.body.c_str()).indexOf("cfg") < 0;
  if (r.method != "POST") return false;
  if (bare == "/json/state" || bare == "/json/si" || bare == "/json") return true;
  if (bare == "/json/cfg") {                 // light settings yes; network, Wi-Fi, AP and update settings never
    JsonDocument d;
    if (deserializeJson(d, r.body)) return false;
    const char* blocked[] = {"nw", "ap", "eth", "ota", "wifi"};
    for (const char* k : blocked) d.remove(k);
    r.body.clear();
    serializeJson(d, r.body);
    return true;
  }
  if (bare == "/upload") {                   // only HomeGlow's own data files
    String b = String(r.body.substr(0, 600).c_str());
    int f = b.indexOf("filename=\"");
    if (f < 0) return false;
    int e = b.indexOf('"', f + 10);
    String name = b.substring(f + 10, e); name.toLowerCase();
    return name.endsWith(".json") && name.indexOf("cfg") < 0 && name.indexOf("sec") < 0;
  }
  return false;
}

static void tunReply(const TunReq& r, int status, const String& ct, const std::string& body) {
  if (!mqtt.connected() || r.reply.isEmpty()) return;
  String topic = "hg/resp/" + r.reply;
  int parts = body.empty() ? 1 : (int)((body.size() + TUN_PART - 1) / TUN_PART);
  for (int i = 0; i < parts; i++) {
    JsonDocument h;
    h["id"] = r.id; h["s"] = status; h["i"] = i; h["n"] = parts;
    if (i == 0 && ct.length()) h["ct"] = ct;
    String head; serializeJson(h, head); head += '\n';
    size_t off = (size_t)i * TUN_PART, n = body.empty() ? 0 : std::min((size_t)TUN_PART, body.size() - off);
    mqtt.beginPublish(topic.c_str(), head.length() + n, false);
    mqtt.write((const uint8_t*)head.c_str(), head.length());
    if (n) mqtt.write((const uint8_t*)body.data() + off, n);
    mqtt.endPublish();
    mqtt.loop();
  }
}

static void tunRun(TunReq& r) {
  Controller* c = byLogin(r.login);
  if (r.bad || !c || c->ip.isEmpty()) { tunRefused++; noteRefused(r.method + " " + r.login + r.path + (r.bad ? " (parts)" : " (unknown controller)")); tunReply(r, r.bad ? 413 : 404, "", ""); return; }
  if (!tunAllowed(r)) { tunRefused++; noteRefused(r.method + " " + r.login + r.path); tunReply(r, 403, "", ""); return; }
  HTTPClient http;
  http.setTimeout(r.body.size() > 20000 ? 30000 : 6000);
  http.setConnectTimeout(3000);
  if (!http.begin("http://" + c->ip + r.path)) { tunReply(r, 502, "", ""); return; }
  if (r.ct.length()) http.addHeader("Content-Type", r.ct);
  const char* keys[] = {"Content-Type"};
  http.collectHeaders(keys, 1);
  int code = r.body.empty() && r.method == "GET" ? http.GET()
           : http.sendRequest(r.method.c_str(), (uint8_t*)r.body.data(), r.body.size());
  std::string out;
  String ct;
  if (code > 0) {
    ct = http.header("Content-Type");
    WiFiClient* s = http.getStreamPtr();
    int total = http.getSize();
    uint8_t buf[1024];
    uint32_t t0 = millis();
    while (http.connected() && (total < 0 || (int)out.size() < total) && millis() - t0 < 30000) {
      int a = s->available();
      if (a <= 0) { delay(2); continue; }
      int n = s->readBytes(buf, std::min(a, (int)sizeof(buf)));
      out.append((const char*)buf, n);
      if (out.size() > TUN_MAX_BODY) break;
    }
  }
  http.end();
  tunDone++;
  tunReply(r, code > 0 ? code : 504, ct, out);
  if (r.method != "GET") c->pollSoon = true;
}

static void connectCloud() {
  lastTry = millis();
  led(0, 40, 40);
  mqtt.setServer(cloudEndpoint.c_str(), 8883);
  String willTopic = stateTopicSelf;
  if (mqtt.connect(cloudId.c_str(), willTopic.c_str(), 1, true, "{\"online\":false}")) {
    connects++; lastMqttErr = 0;
    mqtt.subscribe("hg/+/cmd", 1);
    mqtt.subscribe("hg/req/+", 0);
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
  d["tunnel"] = tunDone; d["tunnelRefused"] = tunRefused;
  JsonArray rl = d["refusedLog"].to<JsonArray>();
  for (auto& x : tunRefusedLog) rl.add(x);
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
  mqtt.setBufferSize(TUN_PART + 2048);     // in the 8 MB PSRAM
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
  if (!tunReady.empty()) {                 // one tunnelled request per pass
    TunReq r = tunReady.front();
    tunReady.erase(tunReady.begin());
    tunRun(r);
  }
  for (size_t i = 0; i < tunIn.size(); i++)  // parts that never all arrived
    if (millis() - tunIn[i].started > 30000) { tunIn.erase(tunIn.begin() + i); break; }

  if (millis() - lastScan > SCAN_EVERY_MS) scan();
  for (auto& c : ctrls) {
    if (c.pollSoon || millis() - c.lastPoll > POLL_EVERY_MS) { poll(c); break; }   // one per pass keeps it responsive
  }
  delay(5);
}
