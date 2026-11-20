// HomeGlow diagnostics for ESP32 boards (all chip types):
//  - why the controller last restarted, plus a short restart history (/bootlog.txt),
//    stamped with the time once the clock is set
//  - where it crashed and the call chain (Xtensa chips) or the crash address (RISC-V),
//    saved in RTC memory during the crash and written to /crashlog.txt on the next boot
// Reported in /json/info as hgReset, hgBootLog, hgCrashLog and hgFw. Nothing here
// changes how WLED behaves. Crash capture is hooked in with -Wl,--wrap=esp_panic_handler.
#ifdef ARDUINO_ARCH_ESP32
#include "wled.h"
#include "esp_attr.h"
#include "esp_system.h"
#include "esp_private/panic_internal.h"
#include "esp_ota_ops.h"
#if defined(__XTENSA__)
  #include "esp_debug_helpers.h"
  #include "freertos/xtensa_context.h"
#else
  #include "riscv/rvruntime-frames.h"
#endif

#define HG_BOOTLOG      "/bootlog.txt"
#define HG_BOOTLOG_MAX  25
#define HG_CRASHLOG     "/crashlog.txt"
#define HG_CRASHLOG_MAX 6
#define HG_MAGIC        0x4B43C0DEu
#define HG_BT_DEPTH     16

typedef struct {
  uint32_t magic;
  int32_t  core;
  uint32_t exception;
  uint32_t cause;      // Xtensa EXCCAUSE / RISC-V mcause
  uint32_t vaddr;      // Xtensa EXCVADDR / RISC-V mtval (the bad address)
  uint32_t addr;
  const char* reason;
  uint32_t twdt;
  uint32_t depth;
  uint32_t bt[HG_BT_DEPTH];
} hg_crash_t;

static RTC_NOINIT_ATTR hg_crash_t hgCrash;
static RTC_NOINIT_ATTR uint32_t   hgTwdtFlag;
static int16_t hgRst = -1;
static bool hgStamped = false;
static bool hgCrashThisBoot = false;

#if defined(__XTENSA__)
static inline uint32_t IRAM_ATTR hgStackPc(uint32_t pc) {
  if (pc & 0x80000000) pc = (pc & 0x3fffffff) | 0x40000000;
  return pc - 3;
}
#endif

extern "C" void __real_esp_panic_handler(panic_info_t *info);

extern "C" void IRAM_ATTR __wrap_esp_panic_handler(panic_info_t *info) {
  if (info && hgCrash.magic != HG_MAGIC) {   // keep the first crash until it's logged
    hgCrash.core = info->core;
    hgCrash.exception = (uint32_t)info->exception;
    hgCrash.addr = (uint32_t)info->addr;
    hgCrash.reason = info->reason;
    hgCrash.twdt = (hgTwdtFlag == HG_MAGIC) ? 1 : 0;
    hgCrash.depth = 0; hgCrash.cause = 0; hgCrash.vaddr = 0;
    #if defined(__XTENSA__)
    const XtExcFrame *f = (const XtExcFrame *)info->frame;
    if (f) {
      hgCrash.cause = f->exccause;
      hgCrash.vaddr = f->excvaddr;
      esp_backtrace_frame_t bt;
      bt.pc = f->pc; bt.sp = f->a1; bt.next_pc = f->a0;
      hgCrash.bt[hgCrash.depth++] = bt.pc;
      while (hgCrash.depth < HG_BT_DEPTH && bt.next_pc != 0) {
        if (!esp_backtrace_get_next_frame(&bt)) break;
        hgCrash.bt[hgCrash.depth++] = hgStackPc(bt.pc);
      }
    }
    #else
    const RvExcFrame *f = (const RvExcFrame *)info->frame;
    if (f) {
      hgCrash.cause = f->mcause;
      hgCrash.vaddr = f->mtval;
      hgCrash.bt[hgCrash.depth++] = f->mepc;
      hgCrash.bt[hgCrash.depth++] = f->ra;    // the caller
    }
    #endif
    hgCrash.magic = HG_MAGIC;
  }
  hgTwdtFlag = 0;
  __real_esp_panic_handler(info);
}

// called by ESP-IDF from the task-watchdog interrupt, right before it aborts
extern "C" void IRAM_ATTR esp_task_wdt_isr_user_handler(void) {
  hgTwdtFlag = HG_MAGIC;
}

static String hgRead(const char* name) {
  String s;
  File f = WLED_FS.open(name, "r");
  if (f) { s = f.readString(); f.close(); }
  return s;
}

static void hgWrite(const char* name, const String& s) {
  File f = WLED_FS.open(name, "w");
  if (!f) return;
  f.print(s);
  f.close();
}

static void hgTrim(String& log, int maxLines) {
  int lines = 0;
  for (unsigned i = 0; i < log.length(); i++) if (log[i] == '\n') lines++;
  while (lines >= maxLines) { int nl = log.indexOf('\n'); if (nl < 0) break; log.remove(0, nl + 1); lines--; }
}

const char* hgResetText() {
  switch (hgRst) {
    case ESP_RST_POWERON:   return "power-on";
    case ESP_RST_BROWNOUT:  return "brownout";
    case ESP_RST_EXT:       return "external-pin";
    case ESP_RST_SW:        return "software";
    case ESP_RST_PANIC:     return "crash-panic";
    case ESP_RST_INT_WDT:   return "crash-interrupt-watchdog";
    case ESP_RST_TASK_WDT:  return "crash-task-watchdog";
    case ESP_RST_WDT:       return "crash-other-watchdog";
    case ESP_RST_DEEPSLEEP: return "deepsleep";
    default:                return "unknown";
  }
}

// short id of the running firmware, to match a crash to the right .elf for decoding
String hgFirmwareId() {
  const esp_app_desc_t* d = esp_ota_get_app_description();
  char id[17];
  for (int i = 0; i < 8; i++) sprintf(id + i*2, "%02x", d->app_elf_sha256[i]);
  id[16] = 0;
  return String(id);
}

static void hgCrashBoot(bool wasCrash) {
  if (hgCrash.magic != HG_MAGIC) { hgTwdtFlag = 0; return; }
  if (!wasCrash) { hgCrash.magic = 0; hgTwdtFlag = 0; return; }   // stale data after a power loss
  String log = hgRead(HG_CRASHLOG);
  hgTrim(log, HG_CRASHLOG_MAX);
  String line = F("0 fw:");
  line += hgFirmwareId();
  line += F(" core:"); line += hgCrash.core;
  line += F(" exc:");  line += hgCrash.exception;
  line += F(" cause:"); line += hgCrash.cause;
  line += F(" twdt:"); line += hgCrash.twdt;
  char hex[12];
  sprintf(hex, "%08x", hgCrash.addr);  line += F(" addr:0x");  line += hex;
  sprintf(hex, "%08x", hgCrash.vaddr); line += F(" vaddr:0x"); line += hex;
  uint32_t r = (uint32_t)hgCrash.reason;
  if (r >= 0x3C000000 && r < 0x3F800000) { line += F(" reason:\""); line += String(hgCrash.reason).substring(0, 48); line += '"'; }
  line += F(" bt:");
  for (uint32_t i = 0; i < hgCrash.depth && i < HG_BT_DEPTH; i++) {
    sprintf(hex, "0x%08x", hgCrash.bt[i]); line += hex; if (i + 1 < hgCrash.depth) line += ' ';
  }
  line += '\n';
  log += line;
  hgWrite(HG_CRASHLOG, log);
  hgCrash.magic = 0;
  hgTwdtFlag = 0;
}

// once at boot, after the file system is mounted
void hgDiagBoot() {
  hgRst = (int16_t)esp_reset_reason();
  String log = hgRead(HG_BOOTLOG);
  hgTrim(log, HG_BOOTLOG_MAX);
  char line[64];
  // "<epoch or 0> <reason> rst=<n>"; the epoch is filled in once the clock is set
  snprintf_P(line, sizeof(line), PSTR("0 %s rst=%d\n"), hgResetText(), (int)hgRst);
  log += line;
  hgWrite(HG_BOOTLOG, log);
  hgCrashThisBoot = (hgRst == ESP_RST_PANIC || hgRst == ESP_RST_INT_WDT || hgRst == ESP_RST_TASK_WDT || hgRst == ESP_RST_WDT);
  hgCrashBoot(hgCrashThisBoot);
}

static void hgStampNewest(const char* name, uint32_t epoch) {
  String s = hgRead(name);
  int last = s.lastIndexOf('\n', s.length() >= 2 ? s.length() - 2 : 0);
  int start = (last < 0) ? 0 : last + 1;
  if (s.length() > (unsigned)start + 2 && s[start] == '0' && s[start + 1] == ' ') {
    hgWrite(name, s.substring(0, start) + String(epoch) + s.substring(start + 1));
  }
}

// from the main loop: once the clock is set, stamp this boot's lines with the boot time (once)
void hgDiagLoop() {
  if (hgStamped || hgRst < 0) return;
  if (toki.getTimeSource() < TOKI_TS_SEC) return;
  hgStamped = true;
  uint32_t bootEpoch = toki.second() - (millis() / 1000);
  hgStampNewest(HG_BOOTLOG, bootEpoch);
  if (hgCrashThisBoot) hgStampNewest(HG_CRASHLOG, bootEpoch);
}

void hgDiagInfo(JsonObject root) {
  root[F("hgReset")]    = hgResetText();
  root[F("hgMinHeap")]  = ESP.getMinFreeHeap();
  root[F("hgBootLog")]  = hgRead(HG_BOOTLOG);
  root[F("hgCrashLog")] = hgRead(HG_CRASHLOG);
  root[F("hgFw")]       = hgFirmwareId();
}
#endif
