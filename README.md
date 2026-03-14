# tuya-meter

Minimal Rust tool to read [AT4P-W](https://www.aliexpress.com/item/1005007218498498.html) (and similar) Tuya smart power meters **locally**, without cloud access. Includes an MQTT bridge with Home Assistant / OpenHAB auto-discovery.

## Features

- Direct LAN communication via Tuya protocol 3.3 / 3.4 / 3.5
- No Python, no dependencies — single static binary (~400 KB)
- Reads all meter data: voltage, current, power, energy, frequency, power factor, leakage current, temperature
- MQTT bridge with [Home Assistant MQTT Discovery](https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery)
- Switch control (on/off) via MQTT commands
- IPv6 support

## Supported data points

| DP  | Name            | Unit  | Scale |
|-----|-----------------|-------|-------|
| 1   | Switch          | bool  | —     |
| 17  | Session Energy  | kWh   | /100  |
| 18  | Current         | A     | /1000 |
| 19  | Power           | W     | /10   |
| 20  | Voltage         | V     | /100  |
| 102 | Cost            |       | /100  |
| 123 | Total Energy    | kWh   | /100  |
| 124 | Leakage Current | mA    | raw   |
| 133 | Frequency       | Hz    | /100  |
| 134 | Power Factor    |       | /100  |
| 135 | CPU Temperature | °C    | raw   |

## Build

```bash
cargo build --release
# Binary: target/release/tuya-meter (~400 KB)
```

### Cross-compile for ARM (e.g. OpenWrt router)

```bash
# Install target
rustup target add aarch64-unknown-linux-musl
# or for 32-bit: armv7-unknown-linux-musleabihf

cargo build --release --target aarch64-unknown-linux-musl
```

## Usage

### Configuration

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your device credentials
```

### CLI commands

```bash
# Human-readable status (default)
tuya-meter config.yaml status

# JSON output (for scripting)
tuya-meter config.yaml json

# Control switch
tuya-meter config.yaml on
tuya-meter config.yaml off
```

### MQTT bridge

```bash
# Start MQTT bridge (runs forever, polls every N seconds)
tuya-meter config.yaml mqtt
```

The bridge:
1. Publishes HA discovery configs so sensors appear automatically
2. Polls the meter and publishes state to `home/<node_id>/state`
3. Subscribes to `home/<node_id>/switch/set` for ON/OFF commands
4. Publishes availability to `home/<node_id>/availability` (with LWT)

## Getting your `local_key`

The `local_key` is a 16-character AES key that Tuya devices use for local encryption. It's assigned when the device is paired and **cannot be read from the device itself** — you must extract it from the Tuya cloud.

### Method 1: Tuya IoT Platform (recommended)

This is the official way. You create a free developer account and link your Tuya app to it.

**Step 1: Create Tuya IoT developer account**

1. Go to [Tuya IoT Platform](https://iot.tuya.com/) and register
2. Create a new **Cloud Project** (Industry → Smart Home)
3. Select your data center (e.g., Central Europe, Western America) — must match your Tuya/Smart Life app region
4. Under **API Products**, subscribe to:
   - IoT Core
   - Authorization Token Management

**Step 2: Link your Tuya app account**

1. In your cloud project, go to **Devices** → **Link Tuya App Account**
2. Click **Add App Account** — a QR code appears
3. Open the **Tuya Smart** or **Smart Life** app on your phone
4. Go to **Profile** → tap the scan icon (top right) → scan the QR code
5. Your devices should appear in the IoT Platform device list

**Step 3: Get the local_key**

1. Go to **Devices** → **All Devices**
2. Find your power meter in the list
3. Click on it — the device details show:
   - **Device ID** — use this as `id` in config
   - **Local Key** — use this as `local_key` in config

> The `local_key` changes if you re-pair the device. If the key stops working, repeat Step 3.

**Step 4: Find the device IP**

The meter must be on the same LAN. Find its IP via your router's DHCP table, or:

```bash
# Scan for Tuya devices (they listen on port 6668)
nmap -p 6668 192.168.1.0/24

# Or use ARP after pinging broadcast
ping -c 1 192.168.1.255
arp -a | grep -i "DEVICE_MAC_PREFIX"
```

### Method 2: tinytuya wizard (alternative)

If you have Python available:

```bash
pip install tinytuya
python -m tinytuya wizard
```

Follow the prompts — it will ask for your Tuya IoT Platform API keys and dump all device info including `local_key`. See [tinytuya documentation](https://github.com/jasonacox/tinytuya#setup-wizard).

### Method 3: MITM / packet capture

For advanced users: intercept the pairing traffic between the Tuya app and cloud to extract the key. Tools like [tuya-convert](https://github.com/ct-Open-Source/tuya-convert) or mitmproxy can help, though this is more complex and fragile.

### Useful links

- [tinytuya](https://github.com/jasonacox/tinytuya) — Python library for local Tuya control (reference implementation)
- [Tuya IoT Platform](https://iot.tuya.com/) — official developer portal
- [LocalTuya](https://github.com/rospogriern/localtuya) — Home Assistant integration for local Tuya control
- [Tuya protocol documentation](https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n/wiki) — official embedded SDK docs
- [TuyAPI](https://github.com/codetheweb/tuyapi) — Node.js Tuya library with protocol details

## Protocol notes

Tuya devices communicate over TCP port 6668 using a custom binary protocol:

- **3.3**: AES-128-ECB encryption, CRC32 integrity check
- **3.4**: AES-128-ECB with session key negotiation and HMAC-SHA256
- **3.5**: AES-128-GCM with session key negotiation (most secure, used by newer firmware)

The AT4P-W typically uses protocol **3.5**. The session key is negotiated on each connection using a nonce exchange authenticated with HMAC-SHA256, then a derived key is used for AES-GCM encryption of all subsequent messages.

## License

MIT
