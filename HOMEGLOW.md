# WLED 16.0.1 + HomeGlow fixes (16.0.1-hg2)

This is official WLED 16.0.1 with a few fixes for ESP32 boards, built and offered by the
[HomeGlow](https://apps.apple.com/app/id6821318234) app until the fixes are in an official WLED release.
It is not an official WLED release. Everything else is unchanged, and you can go back to
official WLED at any time with a normal update.

## What's changed

1. **mDNS crash fix** (`wled00/hg_mdns/`). ESP-IDF 4.4's mDNS code can read through a null
   pointer in `_mdns_remove_scheduled_answer()` (mdns.c:1504, LoadProhibited at address 0x4)
   when a queued reply has no answers left. Any mDNS traffic on the network (phones, Home
   Assistant, other controllers) can trigger it, and several controllers on the same network
   tend to crash in the same second. The fix adds the null check Espressif's current mdns
   component has. This patched copy of `mdns.c` (from the exact ESP-IDF commit the core is built
   from, 8ba0dc0bc3) is compiled into the firmware, so it is used instead of the precompiled one.
   Confirmed on 6 controllers (ESP32 and ESP32-S3) on two networks: 9 crashes, all at that line,
   none since the fix.
2. **Clock jump fix** (`Toki.h`). If the clock was set by the web API (another task) between
   reading `millis()` and using the stored reference point, the unsigned difference wrapped and
   the clock jumped exactly 2^32 ms (49.7 days) ahead, so timers fired on the wrong days. The
   difference is now checked before use. Also: `adjust()` now carries a full 1000 ms.
3. **Internet time fix** (`ntp.cpp`). A late or mismatched reply could report a server delay
   longer than the roundtrip, wrapping the offset to about 24.8 days. It now falls back to 0.
4. **Sync receive fix** (`udp.cpp`, wled/WLED#5929). A controller's own sync broadcast is now
   discarded, so it keeps receiving sync afterwards.
5. **Restart and crash history** (`wled00/hg_diag.cpp`, ESP32 only). `/json/info` reports
   `hgReset` (why it last restarted: power-on, brownout, software, crash…), `hgBootLog` (the last
   25 restarts with times), `hgCrashLog` (the last 6 crashes with the crash address and call
   chain) and `hgFw` (the build's id, to decode a crash). It changes nothing about how WLED runs.
6. **Clock guard** (`wled00/hg_diag.cpp`, `Toki.h`, new in hg2). Every 30 seconds the clock is
   compared with where it should be: carried forward from the last look, or from the last time
   something deliberately set it (internet time, the app, a sync packet). If it is more than
   2 minutes off, that is a jump nobody asked for (any cause, including ones not found yet): the
   time is put back, internet time is asked again, and it is logged. `/json/info` reports
   `hgClockLog` (the last 12 clock jumps and large deliberate changes) and `hgClockFixes` (jumps
   undone since the last restart). Deliberate changes are logged, never undone.

Only ESP32-family boards are built (ESP32, ESP32-S2, -S3, -C3). ESP8266 boards don't have the
mDNS bug and stay on official WLED.

## License

WLED is licensed under the EUPL v1.2 (see LICENSE); these changes are under the same license.
The patched mDNS file is from Espressif's ESP-IDF, Apache License 2.0.
