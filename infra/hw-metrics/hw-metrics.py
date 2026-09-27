#!/usr/bin/env python3
"""Hardware-Kennzahlen als eine JSON-Zeile pro Lauf, fuer den Wazuh-Agent (log_format json)."""
import json, subprocess, time, os, shutil

def run(cmd):
    return json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout or "{}")

out = {"hw": {"host": os.uname().nodename, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")}}
try:
    s = run(["sensors", "-j"])
    temps = [v["temp1_input"] for chip in s.values() if isinstance(chip, dict)
             for k, v in chip.items() if k.startswith(("Package", "Tctl", "Tdie")) and "temp1_input" in v]
    cores = [v2 for chip in s.values() if isinstance(chip, dict) for k, v in chip.items()
             if k.startswith(("Core", "Tccd")) for k2, v2 in v.items() if k2.endswith("_input")]
    out["hw"]["cpu_temp_c"] = round(max(temps or cores or [0]), 1)
    out["hw"]["cpu_core_max_c"] = round(max(cores or [0]), 1)
except Exception as e:
    out["hw"]["sensors_error"] = str(e)
try:
    sm = run(["smartctl", "-j", "-a", os.environ.get("HW_DISK", "/dev/nvme0")])
    h = sm.get("nvme_smart_health_information_log", {})
    out["hw"]["nvme"] = {
        "temp_c": h.get("temperature"), "percentage_used": h.get("percentage_used"),
        "available_spare": h.get("available_spare"), "media_errors": h.get("media_errors"),
        "power_on_hours": h.get("power_on_hours"), "critical_warning": h.get("critical_warning"),
        "smart_passed": sm.get("smart_status", {}).get("passed"),
    }
except Exception as e:
    out["hw"]["smart_error"] = str(e)
try:
    import glob
    gpus = []
    for dev in sorted(glob.glob("/sys/class/drm/card[0-9]/device")):
        hw = glob.glob(dev + "/hwmon/hwmon*")
        if not hw:
            continue
        def rd(path, scale=1.0):
            try: return round(int(open(path).read().strip()) / scale, 1)
            except Exception: return None
        gpus.append({"card": dev.split("/")[4],
                     "temp_c": rd(hw[0] + "/temp1_input", 1000),
                     "busy_pct": rd(dev + "/gpu_busy_percent"),
                     "vram_used_mb": rd(dev + "/mem_info_vram_used", 1024 * 1024),
                     "vram_total_mb": rd(dev + "/mem_info_vram_total", 1024 * 1024),
                     "power_w": rd(hw[0] + "/power1_average", 1000000)})
    if gpus:
        out["hw"]["gpu"] = gpus[0] if len(gpus) == 1 else gpus
        out["hw"]["gpu_temp_c"] = max(g["temp_c"] or 0 for g in gpus)
except Exception as e:
    out["hw"]["gpu_error"] = str(e)
try:
    la = os.getloadavg()
    st = shutil.disk_usage("/")
    out["hw"]["load5"] = round(la[1], 2)
    out["hw"]["root_used_pct"] = round(st.used * 100 / st.total, 1)
except Exception:
    pass
with open("/var/log/hw-metrics/hw-metrics.log", "a", encoding="utf-8") as fh:
    fh.write(json.dumps(out) + "\n")
