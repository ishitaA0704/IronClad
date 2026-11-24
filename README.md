# IronClad — Blast-Radius-Aware MCP Security Proxy

> **Hackathon MVP** — 100% local, zero cloud, runs with `python app.py`.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  AI Agent (Claude / Gemini / Custom)                        │
│  issues MCP tool calls via JSON-RPC                         │
└─────────────────────┬───────────────────────────────────────┘
                      │  POST /mcp/call
┌─────────────────────▼───────────────────────────────────────┐
│  IronClad FastAPI Proxy  (app.py)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐ │
│  │ Blast-Radius │  │ Taint Tracker│  │  ECDSA P-256      │ │
│  │  Classifier  │  │ (session     │  │  Enclave          │ │
│  │ GREEN/YEL/RED│  │  state)      │  │  (sign+verify)    │ │
│  └──────────────┘  └──────────────┘  └───────────────────┘ │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Hash-Chained SQLite Black Box                        │   │
│  │ SHA-256 chain + ECDSA signatures per row             │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ ElevenLabs TTS (cached .mp3 by text hash)            │   │
│  │ Falls back to window.speechSynthesis automatically   │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────┬──────────────────────┬───────────────────────────┘
           │  WebSocket /ws       │  NDJSON Serial (--serial)
┌──────────▼──────┐    ┌──────────▼──────────────────────────┐
│  Browser        │    │  Real ESP32 Hardware Wallet          │
│  static/index   │    │  R307 Fingerprint + SSD1306 OLED     │
│  .html          │    │  GPIO32 Leash + GPIO0 Kill           │
│  (Tailwind)     │    │  firmware/ironclad_esp32.ino         │
└─────────────────┘    └─────────────────────────────────────┘
```

---

## Blast-Radius Zones

| Zone       | Trigger                                               | Hardware Required         |
|------------|-------------------------------------------------------|---------------------------|
| 🟢 GREEN   | Read tools (`list_emails`, `read_file`, etc.)         | None — zero-touch auto-run|
| 🟡 YELLOW  | Bulk mutations (`bulk_archive_emails`)                | Hold Dead-Man's Leash     |
| 🔴 RED     | Outbound writes / deletes (`send_email`, `delete_file`)| Leash + Enrolled Finger   |

**Taint propagation:** Reading an email from a non-allowlisted domain flips the session to `TAINTED`. Any subsequent RED-zone action triggers Verbal Diffing via ElevenLabs.

---

## Quick Start

### 1. Install dependencies
```powershell
cd C:\Users\Admin\Desktop\HACKATHONS\IronClad
pip install -r requirements.txt
```

### 2. Configure `.env` (already set)
```
ELEVENLABS_API_KEY=sk_...
ELEVENLABS_VOICE_ID=21m00Tcm4TlvDq8ikWAM
GEMINI_API_KEY=...
```

### 3. Run
```powershell
python app.py
```
Open **http://localhost:8000** in your browser.

---

## Demo Script (4 scenarios)

### Scenario 1 — 🟢 Green Zone: Triage 5 Trusted Emails
Click **"1 — Triage 5 Trusted Emails"**. Watch the MCP Inspector show 5 `read_email` calls execute silently with no hardware prompt. Session stays `CLEAN`. Black Box logs 5 GREEN entries in <2s.

### Scenario 2 — 🔴 Red Zone: Poisoned Invoice Hijack
Click **"2 — Poisoned Invoice Hijack"**.
1. Reads `invoice-bot@unknown.com` → session flips `TAINTED`
2. Proxy attempts `send_email` → **FROZEN mid-flight**
3. OLED shows `ACTION: GMAIL_SEND / TO: attacker@evil.com`
4. LED strobes red
5. ElevenLabs speaks the verbal diff automatically (*"Warning: Untrusted email from invoice-bot…"*)
6. **To approve:** Hold Leash Pad + click **Scan Enrolled Finger**
7. **To abort:** Click **Kill Switch**

### Scenario 3 — 🟡 Yellow Zone: Bulk Archive 15 Promo Emails
1. Hold **Leash Pad** (or Spacebar) — button turns green
2. Click **▶ EXECUTE BULK ARCHIVE**
3. Watch `1/15`, `2/15`… progress stream in
4. **Release Leash mid-way** — abort fires in <50ms with `LEASH_RELEASED — HALTED AT ITEM #X`

### Scenario 4 — 🔴 Red Zone: Delete passwords.pdf
Click **"4 — Delete passwords.pdf"** — demonstrates Two-Hand Interlock and cryptographic receipt.

### Tamper Demo
Click **"⚠ Simulate Log Tamper"** — one SQLite row is corrupted, chain badge flips to `⚡ CHAIN BROKEN`. Click **↺ Reset Demo** to repair.

---

## Hack Day: Real ESP32 Hardware Mode

### Wiring
```
ESP32 DevKit V1
├── GPIO21 (SDA) → SSD1306 OLED SDA
├── GPIO22 (SCL) → SSD1306 OLED SCL
├── GPIO16 (RX2) → R307 TX (yellow)
├── GPIO17 (TX2) → R307 RX (green)
├── GPIO32       → Momentary button → 3.3V  (leash)
├── GPIO0  (BOOT)→ Ground via button         (kill)
├── GPIO25       → LED Red anode (via 220Ω)
└── GPIO26       → LED Green anode (via 220Ω)
```

### Flash firmware
1. Install [Arduino IDE 2.x](https://www.arduino.cc/en/software)
2. Add ESP32 board: `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
3. Install libraries: `Adafruit SSD1306`, `Adafruit GFX`, `Adafruit Fingerprint Sensor Library`, `ArduinoJson`
4. Open `firmware/ironclad_esp32.ino`
5. Select **ESP32 Dev Module**, flash
6. Enroll fingerprint with the Adafruit enrollment example sketch (slot 1)

### Run with real hardware
```powershell
python app.py --serial
```
The proxy will route hardware events from the ESP32 serial port to the same WebSocket dashboard.

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp/call` | POST | Main MCP tool proxy |
| `/api/session` | GET | Current taint & vault state |
| `/api/reset-demo` | POST | Full reset (files + DB + session) |
| `/api/blackbox` | GET | Fetch Black Box log |
| `/api/verify-chain` | GET | Hash chain integrity check |
| `/api/simulate-tamper` | POST | Corrupt one row (demo) |
| `/api/hardware/fingerprint-scan` | POST | Biometric scan |
| `/api/hardware/kill-switch` | POST | Abort pending call |
| `/api/hardware/vault-toggle` | POST | Plug/unplug USB vault |
| `/api/tts` | POST | ElevenLabs TTS (with cache) |
| `/api/agent` | POST | Intent router (Gemini + offline) |
| `/ws` | WebSocket | Real-time events + leash control |

### WebSocket Messages (Client → Server)
```json
{ "type": "leash_heartbeat" }   // sent every 100ms while leash held
{ "type": "leash_release" }     // sent immediately on release (<50ms abort)
```

---

## Threat Model

**Protected:** Prompt-injection hijacks, supply-chain MCP tool poisoning, unattended AI exfiltration, bulk destructive mutations.

**Not in scope (MVP):** Network-level MitM, compromised OS, physical device theft.

**Crypto:** ECDSA P-256 (SECP256R1) — same curve as FIDO2 / WebAuthn.

---

## File Structure
```
IronClad/
├── app.py                     # FastAPI backend (all logic)
├── requirements.txt
├── .env                       # API keys (gitignore this!)
├── ironclad_blackbox.db       # Auto-created SQLite Black Box
├── tts_cache/                 # ElevenLabs .mp3 cache (by text hash)
├── demo_files/                # Sandboxed file system (auto-restored on reset)
│   ├── passwords.pdf
│   ├── hackathon_budget.xlsx
│   └── notes.txt
├── static/
│   └── index.html             # Single-file dashboard (Tailwind CDN)
└── firmware/
    └── ironclad_esp32.ino     # Arduino C++ firmware stub
```
