#!/usr/bin/env python3
"""Haengt die FRITZ!DECT-200-Metriken an die metrics.json des fritzbox_exporter (sberk).
   Dienst X_AVM-DE_Homeauto:1, GetGenericDeviceInfos mit festem Index 0 und 1.
   Rohwerte der Box: Power in 0.01 W, Energy in Wh, Temperature in 0.1 C.
   Aufruf: python3 add-dect-metrics.py /etc/fritzbox_exporter/metrics.json
   Schreibt metrics.json.new daneben; ersetzt nichts."""
import json
import sys

p = sys.argv[1]
metrics = json.load(open(p, encoding="utf-8"))
assert isinstance(metrics, list)
if any(m.get("service", "").endswith("X_AVM-DE_Homeauto:1") for m in metrics):
    sys.exit("Homeauto-Eintraege sind schon drin")

FIELDS = [
    ("MultimeterPower", "gateway_dect_power_centiwatt", "current power of the DECT socket in 0.01 W"),
    ("MultimeterEnergy", "gateway_dect_energy_wh", "energy counter of the DECT socket in Wh"),
    ("TemperatureCelsius", "gateway_dect_temperature_decicelsius", "temperature at the DECT socket in 0.1 C"),
    ("Present", "gateway_dect_present", "is the DECT socket connected"),
    ("SwitchState", "gateway_dect_switch_on", "is the DECT socket switched on"),
]
for idx in (0, 1):
    for result, name, help_ in FIELDS:
        entry = {
            "service": "urn:dslforum-org:service:X_AVM-DE_Homeauto:1",
            "action": "GetGenericDeviceInfos",
            "actionArgument": {"name": "NewIndex", "isIndex": False, "value": str(idx)},
            "result": result,
            "promDesc": {"fqName": name, "help": help_, "varLabels": ["gateway", "DeviceName", "AIN"]},
            "promType": "GaugeValue",
        }
        if result == "Present":
            entry["okValue"] = "CONNECTED"
        if result == "SwitchState":
            entry["okValue"] = "ON"
        metrics.append(entry)

out = p + ".new"
json.dump(metrics, open(out, "w", encoding="utf-8"), indent=2)
print("ok:", out, len(metrics), "Eintraege")
