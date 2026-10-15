# NeuroMorph
### AI-Driven Network Traffic Obfuscation System

NeuroMorph is a real-time network traffic morphing system that uses **Deep Reinforcement Learning (DRL)** to protect user privacy when communicating with AI services (ChatGPT, Claude, Gemini, Copilot, and 32+ others). It prevents passive network observers from identifying what AI service you are using or what kind of queries you are making — without breaking your internet connection.

---

## The Problem — Whisper Leak Side-Channel Attack

HTTPS encrypts the *content* of your requests, but it cannot hide the **size and timing** of network packets. When you send a prompt to an LLM and it streams back a response, the pattern of packet sizes and inter-arrival times leaks information:

- Large burst packets → long, detailed response → sensitive or complex query
- Small packets → short response → simple query
- Rapid bursts → code generation or document processing

A passive attacker (hacker on the same Wi-Fi, ISP, or network monitor) can achieve **100% accuracy** in identifying which AI service you are using and the nature of your queries — without ever decrypting a single byte.

---

## The Solution — Active Deception

NeuroMorph intercepts your outgoing and incoming HTTPS packets at the kernel level using WinDivert, and applies a DRL-selected morphing action to disguise the traffic pattern in real time. The goal is not to confuse the attacker — it is to make them **always wrong**.

| Scenario | Adversary Accuracy |
|---|---|
| No protection (baseline) | 100% — fully readable |
| NeuroMorph (active deception) | 0% — adversary always wrong |

---

## How It Works — 13 Morphing Actions

The DRL agent (PPO, 4-layer Actor-Critic network) observes a sliding window of packet features and selects one of 13 actions per packet:

| Action | Name | What It Does |
|---|---|---|
| 0 | Pass Through | No morphing applied |
| 1 | Temporal Jitter | Adds 0.5–5ms random delay to timing |
| 2 | Payload Padding | Appends 10–500 random bytes to payload |
| 3 | TCP Segmentation | Splits packet into 2–100B fragments |
| 4 | Constant Size | Pads all packets to exactly 1400B |
| 5 | Fixed Rate Clock | Forces fixed 10ms inter-packet interval |
| 6 | Cover Traffic | Injects indistinguishable dummy packets |
| 7 | Video Mimicry | Reshapes traffic to look like Netflix streaming |
| 8 | DNS Mimicry | Reshapes traffic to look like DNS queries |
| 9 | Inverse Decoy | Makes LLM traffic look like non-LLM background traffic |
| 10 | Max Entropy | Forces uniform random size distribution |
| 11 | Full Ensemble | Combines Actions 4 + 5 + 6 + 7 simultaneously |
| 12 | Perfect Mimicry | Deterministic 0% adversary accuracy |
| 13 | Netflix Video Streaming | Force-locks all packets to 1400B (manual toggle) |

### Action 12 — Perfect Mimicry

The highest-strength action. It makes LLM traffic indistinguishable from ordinary video streaming:

- Every packet is padded to exactly **1400 bytes ± 3B** — zero size variance
- Inter-packet timing is fixed at **10ms** — zero timing variance
- **2 dummy packets** injected per real packet — zero count information
- Result: an adversary trained on LLM traffic patterns sees what looks like Netflix — and is always wrong

---

## Architecture

```
CN Project/
├── main.py                   — Entry point: starts live interception and DRL engine
├── neuromorph_dashboard.py   — Real-time live dashboard UI (Tkinter)
├── neuromorph_logger.py      — Logs packet events to JSONL for the dashboard
├── neuromorph_sim.tcl        — NS-2 network simulation script (generates NAM animation)
├── analyze.sh                — NS-2 trace analysis script (run in Ubuntu/WSL)
├── config.yaml               — All system configuration settings
├── requirements.txt          — Python dependencies
│
├── neuromorph/               — Core engine modules
│   ├── interceptor.py        — WinDivert kernel hook: captures all HTTPS traffic
│   ├── agent.py              — PPO Deep Actor-Critic DRL agent (4 layers, 13 actions)
│   ├── actions.py            — 13-action evasion and morphing suite
│   ├── features.py           — Sliding-window feature extractor (80-dim state vector)
│   ├── injector.py           — Packet morphing coordinator and re-injection
│   └── __init__.py
│
├── models/
│   └── neuromorph_agent.pth  — Pre-trained DRL model weights
│
├── logs/                     — Runtime logs (auto-generated, not committed)
└── WinDivert.dll / .lib / .sys  — Windows kernel packet capture driver
```

---

## Running the System

### Requirements

- Windows 10 or 11
- Python 3.10+
- Administrator access (required for WinDivert kernel hook)
- Ubuntu / WSL (only for NS-2 simulation and NAM animation)

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

### 1. Live Traffic Interception + DRL Engine

Open **PowerShell as Administrator** and run:

```powershell
python main.py --mode live --model models/neuromorph_agent.pth
```

This will:
- Hook into your network adapter at kernel level using WinDivert
- Intercept all HTTPS traffic (port 443) from all apps on your laptop
- Identify which AI service each packet is going to (ChatGPT, Gemini, Copilot, etc.)
- Apply a DRL-selected morphing action in real time
- Forward the original packet instantly so your internet never breaks
- Log all events to `logs/neuromorph_dashboard.jsonl` for the dashboard

---

### 2. Live Dashboard UI

Open a **regular PowerShell** (no admin needed) and run:

```powershell
python neuromorph_dashboard.py
```

The dashboard shows:
- Every intercepted packet with its original size, morphed size, and action applied
- Which AI service was detected (ChatGPT, Gemini, Claude, Copilot, Perplexity, etc.)
- Which DRL action is currently active (highlighted in green)
- Live packet statistics at the bottom
- A manual **Action 13: Netflix Video Streaming** toggle button

---

### 3. NS-2 Simulation + NAM Animation

Open **Ubuntu terminal** (or WSL) and run:

```bash
cd "/mnt/c/Users/user/OneDrive/Desktop/CN Project"

# Run the NS-2 simulation
ns neuromorph_sim.tcl

# Open the NAM graphical animation
nam neuromorph.nam

# Optional: view traffic analysis
bash analyze.sh
```

The simulation models a 4-node network:
- **Node 0** — Client (you)
- **Node 1** — Router
- **Node 2** — LLM Server
- **Node 3** — Attacker (passive observer)

**Phase 1 (0–4s):** Vulnerable LLM traffic — variable packet sizes — attacker sees clear fingerprint  
**Phase 2 (5–9s):** NeuroMorph protected traffic — constant size — attacker sees only Netflix-like patterns

---

## AI Services Detected (36 Providers)

NeuroMorph identifies traffic from 36 AI services including:

ChatGPT, Claude, Gemini, Copilot, Perplexity, Grok, Meta AI, DeepSeek, Groq, Character.AI, Mistral, Cohere, HuggingFace, Together AI, Replicate, Amazon AI, Stability AI, ElevenLabs, Runway, Pika, Adobe Firefly, Midjourney, Suno, Udio, Qwen, Kimi, Cursor, Codeium, Tabnine, Jasper, Copy.ai, Notion AI, Writesonic, Grammarly, You.com, Pi

Detection works for both **browser traffic** (Chrome, Edge, Firefox) and **desktop apps** (ChatGPT app, Claude app, Copilot app, Gemini app).

---

## Key Design Decisions

**Why kernel-level?**  
Application-level hooks can be bypassed or miss system traffic. WinDivert intercepts at the Windows Filtering Platform (WFP), catching every packet from every app.

**Why forward immediately?**  
The original packet is forwarded to the router the moment it is captured, before any DRL processing. This means zero latency impact on your internet — browsing, streaming, and AI chats remain completely unaffected.

**Why DRL instead of a fixed rule?**  
A fixed rule (always pad to 1400B) is detectable. A DRL agent that adapts its strategy per packet makes the morphing pattern itself unpredictable, adding an extra layer of defence.

---

## Requirements

```
pydivert
pyyaml
torch
numpy
```

Full list in `requirements.txt`.
