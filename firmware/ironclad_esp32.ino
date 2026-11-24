/**
 * IronClad — ESP32 Hardware Wallet Firmware
 * Target: ESP32 DevKit V1
 * Sensors: R307 Optical Fingerprint (UART) + 0.96" SSD1306 OLED (I2C)
 * GPIO32: Capacitive Dead-Man's Leash (INPUT_PULLDOWN)
 * GPIO0:  BOOT Kill-Switch (INPUT_PULLUP, active LOW)
 *
 * Serial Protocol: NDJSON (newline-delimited JSON) at 115200 baud.
 * Each outgoing message is a single JSON line followed by '\n'.
 * Each incoming command from the host is a single JSON line followed by '\n'.
 *
 * Libraries required (install via Arduino Library Manager):
 *   - Adafruit SSD1306        (1.3.0+)
 *   - Adafruit GFX Library    (1.11.0+)
 *   - Adafruit Fingerprint Sensor Library (2.1.0+)
 *   - ArduinoJson             (6.21.0+)
 *
 * To use with IronClad proxy: python app.py --serial
 */

#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_Fingerprint.h>
#include <HardwareSerial.h>
#include <ArduinoJson.h>

// ─────────────────── Pin Definitions ───────────────────────────
#define OLED_SDA      21
#define OLED_SCL      22
#define OLED_WIDTH    128
#define OLED_HEIGHT    32   // 0.96" SSD1306 is 128×64; we use 32 for 2-line display area
#define OLED_RESET    -1
#define OLED_I2C_ADDR 0x3C

#define R307_RX       16    // ESP32 RX2 ← R307 TX
#define R307_TX       17    // ESP32 TX2 → R307 RX
#define R307_BAUD     57600

#define GPIO_LEASH    32    // Capacitive touch or momentary button (INPUT_PULLDOWN)
#define GPIO_KILL     0     // BOOT button (INPUT_PULLUP, active LOW)
#define GPIO_LED_R    25    // Status LED Red   (or single RGB LED)
#define GPIO_LED_G    26    // Status LED Green

// ─────────────────── Constants ─────────────────────────────────
#define HEARTBEAT_INTERVAL_MS   100   // leash heartbeat period
#define LEASH_DEBOUNCE_MS        20   // debounce for GPIO32
#define ENROLLED_SLOT             1   // enrolled finger slot ID in R307

// ─────────────────── Globals ───────────────────────────────────
Adafruit_SSD1306   display(OLED_WIDTH, 64, &Wire, OLED_RESET);
HardwareSerial     fpSerial(2);           // UART2 for R307
Adafruit_Fingerprint finger(&fpSerial);

bool leashHeld       = false;
bool killPending     = false;
bool vaultConnected  = true;
unsigned long lastHeartbeat = 0;
unsigned long lastKillCheck  = 0;

String oledLine1 = "IRONCLAD READY";
String oledLine2 = "ZERO TOUCH MODE";

// LED state machine
enum LedState { LED_GREEN, LED_RED_STROBE, LED_YELLOW, LED_GREEN_PULSE, LED_OFF };
LedState ledState   = LED_GREEN;
unsigned long ledTs = 0;
bool          ledOn = true;

// ─────────────────── OLED Helpers ──────────────────────────────
void oledClear() {
  display.clearDisplay();
}

void oledUpdate() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 4);
  display.println(oledLine1.c_str());
  display.setCursor(0, 20);
  display.println(oledLine2.c_str());
  display.display();
}

void setOLED(const char* l1, const char* l2) {
  oledLine1 = l1;
  oledLine2 = l2;
  oledUpdate();
}

// ─────────────────── LED Helpers ───────────────────────────────
void ledWrite(bool r, bool g) {
  digitalWrite(GPIO_LED_R, r ? HIGH : LOW);
  digitalWrite(GPIO_LED_G, g ? HIGH : LOW);
}

void updateLED() {
  unsigned long now = millis();
  switch (ledState) {
    case LED_GREEN:       ledWrite(false, true); break;
    case LED_OFF:         ledWrite(false, false); break;
    case LED_RED_STROBE:
      if (now - ledTs > 100) { ledOn = !ledOn; ledTs = now; }
      ledWrite(ledOn, false); break;
    case LED_YELLOW:
      if (now - ledTs > 300) { ledOn = !ledOn; ledTs = now; }
      ledWrite(ledOn, ledOn); break;
    case LED_GREEN_PULSE:
      if (now - ledTs > 400) { ledOn = !ledOn; ledTs = now; }
      ledWrite(false, ledOn); break;
  }
}

void setLED(const char* state) {
  String s = state;
  if      (s == "green")       ledState = LED_GREEN;
  else if (s == "red_strobe")  ledState = LED_RED_STROBE;
  else if (s == "yellow")      ledState = LED_YELLOW;
  else if (s == "green_pulse") ledState = LED_GREEN_PULSE;
  else                         ledState = LED_OFF;
}

// ─────────────────── JSON Output ───────────────────────────────
void sendJSON(StaticJsonDocument<256>& doc) {
  String out;
  serializeJson(doc, out);
  Serial.println(out);
}

void sendEvent(const char* type, const char* msg) {
  StaticJsonDocument<256> doc;
  doc["type"] = type;
  doc["msg"]  = msg;
  doc["ts"]   = millis();
  sendJSON(doc);
}

void sendLeashHeartbeat(bool held) {
  StaticJsonDocument<128> doc;
  doc["type"]  = "leash_heartbeat";
  doc["held"]  = held;
  doc["ts"]    = millis();
  sendJSON(doc);
}

void sendLeashRelease() {
  StaticJsonDocument<128> doc;
  doc["type"] = "leash_release";
  doc["ts"]   = millis();
  sendJSON(doc);
}

void sendFingerprintResult(int slot, bool ok, const char* msg) {
  StaticJsonDocument<128> doc;
  doc["type"] = "fingerprint_scan";
  doc["slot"] = slot;
  doc["ok"]   = ok;
  doc["msg"]  = msg;
  doc["ts"]   = millis();
  sendJSON(doc);
}

void sendKillSwitch() {
  StaticJsonDocument<64> doc;
  doc["type"] = "kill_switch";
  doc["ts"]   = millis();
  sendJSON(doc);
}

// ─────────────────── R307 Fingerprint ──────────────────────────
int getFingerprintID() {
  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) return -2;   // no finger
  if (p != FINGERPRINT_OK)       return -1;   // error

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) return -1;

  p = finger.fingerSearch();
  if (p == FINGERPRINT_OK)       return finger.fingerID;
  if (p == FINGERPRINT_NOTFOUND) return 0;    // 0 = not matched
  return -1;
}

void checkFingerprint() {
  int id = getFingerprintID();
  if (id == -2) return;  // no finger placed

  if (id == ENROLLED_SLOT) {
    setOLED("FINGER OK", "SLOT 1 VERIFIED");
    setLED("green_pulse");
    sendFingerprintResult(1, true, "Enrolled finger verified");
  } else if (id == 0) {
    setOLED("BIOMETRIC", "REJECTED");
    setLED("red_strobe");
    sendFingerprintResult(99, false, "BIOMETRIC REJECTED — UNAUTHORIZED FINGER");
    delay(1500);
  } else {
    setOLED("SCAN ERROR", "RETRY");
    setLED("red_strobe");
    sendFingerprintResult(-1, false, "Sensor error — retry");
  }
}

// ─────────────────── Host Command Parser ───────────────────────
void parseHostCommand(const String& line) {
  StaticJsonDocument<512> doc;
  DeserializationError err = deserializeJson(doc, line);
  if (err) return;  // ignore malformed

  const char* cmd = doc["cmd"] | "";

  if (strcmp(cmd, "oled_update") == 0) {
    const char* l1 = doc["line1"] | "IRONCLAD";
    const char* l2 = doc["line2"] | "";
    setOLED(l1, l2);
    if (doc.containsKey("led")) setLED(doc["led"]);
  }
  else if (strcmp(cmd, "set_led") == 0) {
    setLED(doc["state"] | "green");
  }
  else if (strcmp(cmd, "ping") == 0) {
    sendEvent("pong", "Hardware wallet alive");
  }
  else if (strcmp(cmd, "get_status") == 0) {
    StaticJsonDocument<256> resp;
    resp["type"]  = "status";
    resp["leash"] = leashHeld;
    resp["vault"] = vaultConnected;
    resp["fw"]    = "ironclad_esp32.ino v1.0";
    resp["ts"]    = millis();
    sendJSON(resp);
  }
}

// ─────────────────── Setup ─────────────────────────────────────
void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);

  // GPIO
  pinMode(GPIO_LEASH, INPUT_PULLDOWN);   // GPIO32 capacitive leash
  pinMode(GPIO_KILL,  INPUT_PULLUP);     // GPIO0  BOOT kill (active LOW)
  pinMode(GPIO_LED_R, OUTPUT);
  pinMode(GPIO_LED_G, OUTPUT);

  // OLED
  Wire.begin(OLED_SDA, OLED_SCL);
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_I2C_ADDR)) {
    Serial.println(F("{\"type\":\"error\",\"msg\":\"OLED init failed\"}"));
    // Continue without OLED
  }
  display.setRotation(0);
  display.clearDisplay();
  display.display();

  // R307 fingerprint sensor
  fpSerial.begin(R307_BAUD, SERIAL_8N1, R307_RX, R307_TX);
  finger.begin(R307_BAUD);
  if (finger.verifyPassword()) {
    sendEvent("sensor_ok", "R307 fingerprint sensor verified");
  } else {
    sendEvent("sensor_error", "R307 fingerprint sensor NOT found — check wiring");
  }

  // Initial display
  setOLED("IRONCLAD READY", "ZERO TOUCH MODE");
  ledState = LED_GREEN;

  // Boot message
  StaticJsonDocument<256> bootDoc;
  bootDoc["type"]    = "boot";
  bootDoc["fw"]      = "ironclad_esp32.ino v1.0";
  bootDoc["gpio_leash"] = GPIO_LEASH;
  bootDoc["gpio_kill"]  = GPIO_KILL;
  bootDoc["protocol"]   = "NDJSON/115200";
  sendJSON(bootDoc);
}

// ─────────────────── Main Loop ─────────────────────────────────
void loop() {
  unsigned long now = millis();

  // ── 1. Update LED animation ──────────────────────────────────
  updateLED();

  // ── 2. Dead-Man's Leash (GPIO32) ────────────────────────────
  bool leashPin = (digitalRead(GPIO_LEASH) == HIGH);
  if (leashPin != leashHeld) {
    delay(LEASH_DEBOUNCE_MS);
    leashPin = (digitalRead(GPIO_LEASH) == HIGH);
    if (leashPin != leashHeld) {
      leashHeld = leashPin;
      if (!leashHeld) {
        // Immediate release — send right away
        sendLeashRelease();
        setOLED("LEASH RELEASED", "HALTED");
      }
    }
  }
  if (leashHeld && (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS)) {
    sendLeashHeartbeat(true);
    lastHeartbeat = now;
  }

  // ── 3. BOOT Kill-Switch (GPIO0, active LOW) ──────────────────
  if (digitalRead(GPIO_KILL) == LOW && !killPending) {
    killPending = true;
    delay(50);  // debounce
    if (digitalRead(GPIO_KILL) == LOW) {
      sendKillSwitch();
      setOLED("KILL SWITCH", "ACTIVATED");
      setLED("off");
    }
  }
  if (digitalRead(GPIO_KILL) == HIGH) killPending = false;

  // ── 4. R307 Fingerprint scan (polls continuously) ────────────
  checkFingerprint();

  // ── 5. Host command parser (NDJSON from app.py --serial) ─────
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.length() > 0) parseHostCommand(line);
  }

  delay(10);  // 100Hz tick
}

/*
 * ─────────────────── Enrollment Sketch (run once) ───────────────
 * To enroll finger slot 1, run this once separately via Serial Monitor:
 *
 *   finger.enroll(1);   // enroll into slot 1
 *
 * Or use the Adafruit fingerprint enrollment example sketch.
 * ──────────────────────────────────────────────────────────────────
 */
