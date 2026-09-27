# LLM-Server (Ollama, Vulkan)

Eigener Rechner (Ryzen 5 3600, 48 GB, Radeon RX 5700 XT 8 GB), Ubuntu 24.04. Die Karte (RDNA1) wird von
ROCm nicht mehr unterstützt; Ollama läuft über Vulkan mit Mesa RADV (`mesa-vulkan-drivers`, kein
AMD-Treiberpaket). Ollama-Override: `OLLAMA_VULKAN=1`, `OLLAMA_HOST=0.0.0.0:11434`, `SupplementaryGroups=render video`.
`ollama ps` muss `100% GPU` zeigen. Modell für die Alert-Triage: `qwen2.5:7b` (Q4, ~4,7 GB VRAM).
Kein Auth an der API, deshalb ufw: 11434 nur vom Wazuh-Manager. Sensoren via `hw-metrics.py`
(k10temp für Ryzen, amdgpu-hwmon für GPU-Temperatur/VRAM/Last), Regel 110112 ab 90 °C GPU.
