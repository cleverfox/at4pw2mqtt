# tuya-meter

Minimal Rust tool to read Tuya smart power meters **locally**, without cloud access. Supports [AT4P-W](https://www.aliexpress.com/item/1005007218498498.html) plug meter and SA1 CT clamp meter. Includes MQTT bridge with Home Assistant / OpenHAB auto-discovery and JSONL logging with rotation.

## Features

- Direct LAN communication via Tuya protocol 3.3 / 3.4 / 3.5
- No Python, no dependencies — single static binary
- Supports AT4P-W plug meter and SA1 CT clamp meter (auto-detected)
- Reads voltage, current, power, energy, frequency, power factor, temperature
- Server mode with MQTT and/or JSONL logging (can run both simultaneously)
- [Home Assistant MQTT Discovery](https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery) (works with OpenHAB too)
- JSONL log rotation by line count and/or time interval
- Switch control (on/off) via MQTT commands (AT4P-W only)
- Persistent connection with heartbeats and auto-reconnect
- IPv6 support

## Supported devices

### AT4P-W (plug meter, category `cz`)

| DP  | Name            | Unit | Scale |
|-----|-----------------|------|-------|
| 1   | Switch          | bool | --    |
| 17  | Session Energy  | kWh  | /100  |
| 18  | Current         | A    | /1000 |
| 19  | Power           | W    | /100  |
| 20  | Voltage         | V    | /100  |
| 102 | Cost            |      | /100  |
| 123 | Total Energy    | kWh  | /100  |
| 124 | Leakage Current | mA   | raw   |
| 133 | Frequency       | Hz   | /100  |
| 134 | Power Factor    |      | /100  |
| 135 | Temperature     | C    | raw   |

### SA1 CT (clamp meter, category `dlq`)

| DP  | Name           | Unit | Scale                    |
|-----|----------------|------|--------------------------|
| 1   | Total Energy   | kWh  | /100                     |
| 6   | Phase A (Raw)  | --   | base64: V/10, mA, W     |
| 32  | Frequency      | Hz   | /100                     |
| 50  | Power Factor   |      | /100                     |
| 131 | Temperature    | C    | /10                      |

DP 6 is a base64-encoded 8-byte blob: `[uint16 voltage*10][uint24 current_mA][uint24 power_W]`. It only streams when a persistent TCP connection is maintained (the device needs heartbeats to keep sending updates).

## Build

```bash
cargo build --release
# Binary: target/release/tuya-meter
```

### Cross-compile for ARM (e.g. OpenWrt router)

```bash
rustup target add aarch64-unknown-linux-musl
# or: armv7-unknown-linux-musleabihf

cargo build --release --target aarch64-unknown-linux-musl
```

## Configuration

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your device credentials
```

```yaml
device:
  ip: 192.168.1.100
  id: your_device_id_here
  local_key: your_local_key
  version: "3.5"
  # device_type: at4pw       # optional: "at4pw" or "ct" (auto-detected)

poll_secs: 10                 # polling interval for server mode

# MQTT bridge (optional, for server mode)
mqtt:
  host: "192.168.1.1"
  port: 1883
  node_id: at4pw

# JSONL logging (optional, for server mode)
log:
  file: /var/log/tuya-meter.jsonl   # may contain date patterns, e.g. tuya-meter_%Y-%m-%d.jsonl
  max_lines: 10000            # rotate after N lines
  rotate_interval: "24h"      # rotate every interval: "5h", "1d", "30m", "3600s"
```

## Usage

### CLI commands

```bash
# Human-readable status (default)
tuya-meter config.yaml status

# JSON output (for scripting)
tuya-meter config.yaml json

# Control switch (AT4P-W only)
tuya-meter config.yaml on
tuya-meter config.yaml off
```

### Server mode

```bash
tuya-meter config.yaml server
```

Server mode maintains a persistent TCP connection to the device, receives data pushes, and forwards them to MQTT and/or a JSONL log file. Requires at least one of `mqtt` or `log` in the config.

**MQTT bridge:**
- Publishes HA discovery configs so sensors appear automatically in Home Assistant / OpenHAB
- Publishes state to `home/<node_id>/state` on every poll cycle
- Subscribes to `home/<node_id>/switch/set` for ON/OFF commands (AT4P-W only)
- Publishes availability to `home/<node_id>/availability` (with LWT for offline detection)

**JSONL logging:**
- Writes one JSON line per poll cycle: `{"t":1712678400,"data":{"voltage":"230.1","current":"0.158","power":"34.0",...}}`
- Rotation by line count (`max_lines`) and/or time interval (`rotate_interval`)
- Keeps up to 3 rotated files (`.1`, `.2`, `.3`)
- Supported intervals: `"30m"`, `"5h"`, `"1d"`, `"3600s"`
- Date-based filenames: `file` may contain `%Y %m %d %H %M %S` patterns (local time),
  e.g. `meter_%Y-%m-%d.jsonl` starts a new file at midnight — no renaming, old files
  are kept as-is

### Example: log-only (no MQTT)

```yaml
device:
  ip: 192.168.1.100
  id: your_device_id
  local_key: your_key

poll_secs: 30

log:
  file: meter.jsonl
  max_lines: 5000
  rotate_interval: "6h"
```

### Example: MQTT-only (no log)

```yaml
device:
  ip: 192.168.1.100
  id: your_device_id
  local_key: your_key

poll_secs: 10

mqtt:
  host: "192.168.1.1"
  port: 1883
  node_id: meter1
```

## Getting your `local_key`

The `local_key` is a 16-character AES key used for local encryption. It's assigned when the device is paired and **cannot be read from the device itself** -- you must extract it from the Tuya cloud.

### Method 1: Tuya IoT Platform (recommended)

1. Register at [Tuya IoT Platform](https://iot.tuya.com/)
2. Create a **Cloud Project** (Industry -> Smart Home)
3. Select your data center -- must match your Tuya/Smart Life app region
4. Subscribe to API products: **IoT Core**, **Authorization Token Management**
5. Go to **Devices** -> **Link Tuya App Account** -> scan QR code with the Smart Life app
6. Find your device in **All Devices** -- it shows **Device ID** and **Local Key**

> The `local_key` changes if you re-pair the device.

### Method 2: tinytuya wizard

```bash
pip install tinytuya
python -m tinytuya wizard
```

It will ask for your Tuya IoT Platform API keys and dump all device info including `local_key`. See [tinytuya docs](https://github.com/jasonacox/tinytuya#setup-wizard).

### Finding the device IP

```bash
# Scan for Tuya devices (they listen on port 6668)
nmap -p 6668 192.168.1.0/24

# Or check your router's DHCP table
```

### Auto-discovery (DHCP-friendly)

Set `ip: auto` in the config and the tool will resolve the IP at startup. Two strategies, tried in order:

1. **MAC lookup** (when `mac:` is set in the config) — reads the system ARP table, sweeps the local /24 to refresh stale entries, then matches the device's MAC. This is fast and works for devices that don't broadcast.
2. **UDP broadcast** — listens on UDP **6666** (v3.1–3.4, AES-ECB) and **7000** (v3.5, AES-GCM) and matches by `id` (`gwId`). Devices broadcast every ~5–10 s when active; some firmwares broadcast rarely or only at boot.

```yaml
device:
  ip: auto
  id: your_device_id_here
  local_key: your_local_key
  version: "3.5"
  mac: "aa:bb:cc:dd:ee:ff"   # optional, enables ARP-based lookup
```

In server mode the IP is also re-resolved after a connect failure, so devices that move across DHCP leases keep working without a config edit.

If your LAN isn't a /24 (the default assumption), set the subnet-directed broadcast explicitly:

```yaml
bcast_addr: 10.0.255.255    # for a /16; use whatever matches your subnet mask
```

This is also a useful workaround on FreeBSD/Linux, where the kernel won't L2-broadcast `255.255.255.255` without a hint and would otherwise unicast the probe to the default gateway.

## Protocol notes

Tuya devices communicate over TCP port 6668 using a custom binary protocol:

- **3.3**: AES-128-ECB encryption, CRC32 integrity check
- **3.4**: AES-128-ECB with session key negotiation and HMAC-SHA256
- **3.5**: AES-128-GCM with session key negotiation (most secure, used by newer firmware)

Session key negotiation: local nonce exchange authenticated with HMAC-SHA256, XOR-derived key used for AES-GCM encryption of all subsequent messages.

## Links

- [tinytuya](https://github.com/jasonacox/tinytuya) -- Python library for local Tuya control
- [Tuya IoT Platform](https://iot.tuya.com/) -- official developer portal
- [LocalTuya](https://github.com/rospogriern/localtuya) -- Home Assistant integration
- [TuyAPI](https://github.com/codetheweb/tuyapi) -- Node.js Tuya library with protocol details

## License

MIT
