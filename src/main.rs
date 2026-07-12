use aes::Aes128;
use aes_gcm::{aead::KeyInit as GcmKeyInit, AeadInPlace, Aes128Gcm, Nonce as GcmNonce};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use crc32fast::Hasher as Crc32Hasher;
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use rumqttc::{Client, MqttOptions, QoS};
use sha2::Sha256;
use std::env;
use std::fs;
use std::io::{Read, Write, BufWriter, BufRead, BufReader};
use std::net::{TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Base64 decoding (minimal, no extra dep)
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 128] = &{
        let mut t = [255u8; 128];
        let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            t[alpha[i] as usize] = i as u8;
            i += 1;
        }
        t
    };
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    let chunks = bytes.len() / 4;
    for i in 0..chunks {
        let a = *T.get(*bytes.get(i * 4)? as usize)? as u32;
        let b = *T.get(*bytes.get(i * 4 + 1)? as usize)? as u32;
        let c = *T.get(*bytes.get(i * 4 + 2)? as usize)? as u32;
        let d = *T.get(*bytes.get(i * 4 + 3)? as usize)? as u32;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
    }
    let rem = bytes.len() % 4;
    if rem == 2 {
        let a = *T.get(*bytes.get(chunks * 4)? as usize)? as u32;
        let b = *T.get(*bytes.get(chunks * 4 + 1)? as usize)? as u32;
        let n = (a << 18) | (b << 12);
        out.push((n >> 16) as u8);
    } else if rem == 3 {
        let a = *T.get(*bytes.get(chunks * 4)? as usize)? as u32;
        let b = *T.get(*bytes.get(chunks * 4 + 1)? as usize)? as u32;
        let c = *T.get(*bytes.get(chunks * 4 + 2)? as usize)? as u32;
        let n = (a << 18) | (b << 12) | (c << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    }
    Some(out)
}

type HmacSha256 = Hmac<Sha256>;
type Aes128EcbEnc = ecb::Encryptor<Aes128>;
type Aes128EcbDec = ecb::Decryptor<Aes128>;

const PREFIX_55AA: u32 = 0x000055AA;
const SUFFIX_55AA: u32 = 0x0000AA55;
const PREFIX_6699: u32 = 0x00006699;
const SUFFIX_6699: u32 = 0x00009966;

const CMD_SESS_KEY_NEG_START: u32 = 3;
const CMD_SESS_KEY_NEG_FINISH: u32 = 5;
const CMD_CONTROL: u32 = 7;
const CMD_DP_QUERY: u32 = 10;
const CMD_CONTROL_NEW: u32 = 13;
const CMD_DP_QUERY_NEW: u32 = 16;
const CMD_UPDATEDPS: u32 = 18;

// All known DPs across AT4P-W and SA1 CT
const ALL_DPS: &[u32] = &[
    1, 6, 9, 11, 12, 13, 14, 17, 18, 19, 20, 32, 50,
    101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
    111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
    126, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ── AES-ECB helpers ──

fn aes_ecb_encrypt(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; data.len() + 16];
    buf[..data.len()].copy_from_slice(data);
    let ct = Aes128EcbEnc::new(key.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .unwrap();
    ct.to_vec()
}

fn aes_ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    let pt = Aes128EcbDec::new(key.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .unwrap();
    pt.to_vec()
}

fn aes_ecb_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::BlockEncrypt;
    let cipher = <Aes128 as KeyInit>::new(key.into());
    let mut out = aes::Block::clone_from_slice(block);
    cipher.encrypt_block(&mut out);
    let mut result = [0u8; 16];
    result.copy_from_slice(&out);
    result
}

fn aes_ecb_decrypt_safe(key: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        return None;
    }
    let mut buf = data.to_vec();
    Aes128EcbDec::new(key.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .ok()
        .map(|s| s.to_vec())
}

// ── CRC32 ──

fn crc32(data: &[u8]) -> u32 {
    let mut h = Crc32Hasher::new();
    h.update(data);
    h.finalize()
}

// ── HMAC-SHA256 ──

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

// ── UDP discovery ──
//
// Tuya devices broadcast their presence on:
//   UDP 6666 — AES-ECB encrypted (v3.1–3.4)
//   UDP 7000 — AES-GCM encrypted (v3.5)
// Both use a fixed key derived from a hardcoded constant.

const AUTO_IP_DISCOVERY_TIMEOUT_SECS: u64 = 60;

fn tuya_udp_key() -> [u8; 16] {
    let mut h = Md5::new();
    h.update(b"yGAdlopoPVldABfn");
    let r = h.finalize();
    let mut k = [0u8; 16];
    k.copy_from_slice(&r);
    k
}

fn parse_55aa_broadcast(pkt: &[u8], key: &[u8; 16]) -> Option<Vec<u8>> {
    // Header(16) = prefix(4) + seq(4) + cmd(4) + length(4)
    // length covers payload + CRC(4) + suffix(4); broadcasts have no retcode.
    if pkt.len() < 24 {
        return None;
    }
    let prefix = u32::from_be_bytes(pkt[0..4].try_into().ok()?);
    if prefix != PREFIX_55AA {
        return None;
    }
    let length = u32::from_be_bytes(pkt[12..16].try_into().ok()?) as usize;
    if length < 8 || 16 + length > pkt.len() {
        return None;
    }
    let enc_end = 16 + length - 8;
    let enc = &pkt[16..enc_end];
    aes_ecb_decrypt_safe(key, enc)
}

fn parse_6699_broadcast(pkt: &[u8], key: &[u8; 16]) -> Option<Vec<u8>> {
    // Header(18) = prefix(4) + reserved(2) + seq(4) + cmd(4) + length(4)
    // After header: IV(12) + ciphertext + tag(16); then suffix(4).
    if pkt.len() < 22 {
        return None;
    }
    let prefix = u32::from_be_bytes(pkt[0..4].try_into().ok()?);
    if prefix != PREFIX_6699 {
        return None;
    }
    let length = u32::from_be_bytes(pkt[14..18].try_into().ok()?) as usize;
    if length < 28 || 18 + length + 4 > pkt.len() {
        return None;
    }
    let iv = &pkt[18..30];
    let aad = &pkt[4..18];
    let ct_end = 18 + length - 16;
    let ct = &pkt[30..ct_end];
    let tag = &pkt[ct_end..ct_end + 16];

    let gcm = Aes128Gcm::new(key.into());
    let nonce = GcmNonce::from_slice(iv);
    let mut buf = ct.to_vec();
    use aes_gcm::aead::generic_array::GenericArray;
    let tag_arr = GenericArray::clone_from_slice(tag);
    gcm.decrypt_in_place_detached(nonce, aad, &mut buf, &tag_arr)
        .ok()?;
    Some(buf)
}

fn extract_broadcast_json(payload: &[u8]) -> Option<serde_json::Value> {
    use serde::Deserialize;
    let start = payload.iter().position(|&b| b == b'{')?;
    let mut de = serde_json::Deserializer::from_slice(&payload[start..]);
    serde_json::Value::deserialize(&mut de).ok()
}

const CMD_REQ_DEVINFO: u32 = 0x25;

/// Build a v3.5 discovery probe packet (cmd 0x25, AES-GCM with udpkey).
/// v3.5 devices answer this with their broadcast info on UDP 7000.
fn build_discovery_probe(self_ip: &str, key: &[u8; 16]) -> Vec<u8> {
    let payload = format!("{{\"from\":\"app\",\"ip\":\"{self_ip}\"}}");
    let payload_bytes = payload.into_bytes();

    let ts = format!("{}", (now_secs() as f64 * 10.0) as u64);
    let iv_bytes: Vec<u8> = ts.bytes().take(12).collect();
    let mut iv = [0u8; 12];
    let copy_len = iv_bytes.len().min(12);
    iv[..copy_len].copy_from_slice(&iv_bytes[..copy_len]);

    let length = payload_bytes.len() as u32 + 16 + 12;

    let mut header = Vec::with_capacity(18);
    header.extend_from_slice(&PREFIX_6699.to_be_bytes());
    header.extend_from_slice(&0u16.to_be_bytes());
    header.extend_from_slice(&0u32.to_be_bytes()); // seqno = 0
    header.extend_from_slice(&CMD_REQ_DEVINFO.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());

    let aad = header[4..18].to_vec();

    let gcm = Aes128Gcm::new(key.into());
    let nonce = GcmNonce::from_slice(&iv);
    let mut buffer = payload_bytes;
    let tag = gcm
        .encrypt_in_place_detached(nonce, &aad, &mut buffer)
        .unwrap();

    let mut msg = header;
    msg.extend_from_slice(&iv);
    msg.extend_from_slice(&buffer);
    msg.extend_from_slice(&tag);
    msg.extend_from_slice(&SUFFIX_6699.to_be_bytes());
    msg
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let s = s.trim().to_lowercase().replace('-', ":");
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

fn lookup_ip_by_mac(target: [u8; 6]) -> Option<String> {
    let out = std::process::Command::new("arp")
        .args(["-an"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let ip = match (line.find('('), line.find(')')) {
            (Some(a), Some(b)) if b > a + 1 => &line[a + 1..b],
            _ => continue,
        };
        let after_at = match line.find(" at ") {
            Some(idx) => &line[idx + 4..],
            None => continue,
        };
        let mac_str = after_at.split_whitespace().next().unwrap_or("");
        if let Some(mac) = parse_mac(mac_str) {
            if mac == target {
                if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

fn local_ipv4() -> Option<std::net::Ipv4Addr> {
    // Connecting a UDP socket gives us the source IP the kernel would use for that route.
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:53").ok()?;
    match sock.local_addr().ok()? {
        std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    }
}

/// Send a tiny UDP packet to every host on our /24, prompting the kernel to
/// resolve each MAC. Online hosts populate the ARP cache; offline hosts time
/// out silently. Returns once packets are sent and a brief settle delay elapses.
fn refresh_arp_cache() {
    let my_ip = match local_ipv4() {
        Some(ip) => ip,
        None => return,
    };
    let o = my_ip.octets();
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    for i in 1u8..255 {
        if i == o[3] {
            continue;
        }
        let dst = format!("{}.{}.{}.{}:9", o[0], o[1], o[2], i);
        let _ = sock.send_to(&[0u8], dst);
    }
    std::thread::sleep(Duration::from_millis(1500));
}

fn discover_via_udp(
    device_id: &str,
    bcast_override: Option<&str>,
    timeout_secs: u64,
) -> Result<String, String> {
    let key = tuya_udp_key();

    let sock_6666 = UdpSocket::bind("0.0.0.0:6666")
        .map_err(|e| format!("bind UDP 6666: {e}"))?;
    sock_6666
        .set_read_timeout(Some(Duration::from_millis(250)))
        .ok();
    sock_6666.set_broadcast(true).ok();

    let sock_7000 = UdpSocket::bind("0.0.0.0:7000")
        .map_err(|e| format!("bind UDP 7000: {e}"))?;
    sock_7000
        .set_read_timeout(Some(Duration::from_millis(250)))
        .ok();
    sock_7000.set_broadcast(true).ok();

    // Sender socket on an ephemeral port — broadcast a v3.5 REQ_DEVINFO probe so
    // devices that don't auto-broadcast (or only broadcast at boot) reply with
    // their info. tinytuya does the same on a 6 s cadence.
    //
    // Bind to the local interface IP rather than 0.0.0.0: on FreeBSD/Linux the
    // limited broadcast 255.255.255.255 has no obvious interface and the kernel
    // routes it via the default gateway (sending to the gateway's unicast MAC
    // instead of ff:ff:ff:ff:ff:ff). Binding pins the egress interface; sending
    // to the subnet-directed broadcast (e.g. 192.168.1.255) ensures L2 broadcast.
    let self_ipv4 = local_ipv4().unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let probe_sock = UdpSocket::bind((self_ipv4, 0u16))
        .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
        .map_err(|e| format!("bind ephemeral UDP: {e}"))?;
    probe_sock.set_broadcast(true).ok();
    let probe = build_discovery_probe(&self_ipv4.to_string(), &key);

    let mut probe_targets: Vec<String> = vec!["255.255.255.255:7000".into()];
    if let Some(b) = bcast_override {
        probe_targets.push(format!("{b}:7000"));
    } else if self_ipv4.octets()[0] != 0 {
        let o = self_ipv4.octets();
        // Assume /24 — covers virtually every home LAN.
        probe_targets.push(format!("{}.{}.{}.255:7000", o[0], o[1], o[2]));
    }
    let probe_interval = Duration::from_secs(5);

    let send_probe = |sock: &UdpSocket| {
        for t in &probe_targets {
            let _ = sock.send_to(&probe, t);
        }
    };

    eprintln!(
        "Probing for {device_id} on UDP 6666/7000 (active scan, up to {timeout_secs}s)..."
    );
    send_probe(&probe_sock);
    let mut last_probe = SystemTime::now();

    let deadline = SystemTime::now() + Duration::from_secs(timeout_secs);
    let mut buf = [0u8; 4096];

    loop {
        let now = SystemTime::now();
        if now > deadline {
            return Err(format!(
                "no broadcast received from device {device_id} within {timeout_secs}s"
            ));
        }
        if now.duration_since(last_probe).unwrap_or_default() >= probe_interval {
            send_probe(&probe_sock);
            last_probe = now;
        }

        for (sock, port, decode) in [
            (
                &sock_6666,
                6666u16,
                parse_55aa_broadcast as fn(&[u8], &[u8; 16]) -> Option<Vec<u8>>,
            ),
            (&sock_7000, 7000u16, parse_6699_broadcast),
        ] {
            if let Ok((n, addr)) = sock.recv_from(&mut buf) {
                let payload = match decode(&buf[..n], &key) {
                    Some(p) => p,
                    None => continue,
                };
                let json = match extract_broadcast_json(&payload) {
                    Some(j) => j,
                    None => continue,
                };
                let gw_id = json.get("gwId").and_then(|v| v.as_str()).unwrap_or("");
                if gw_id == device_id {
                    let ip = match addr.ip() {
                        std::net::IpAddr::V4(v4) => v4.to_string(),
                        std::net::IpAddr::V6(v6) => v6.to_string(),
                    };
                    eprintln!("Found {device_id} at {ip} (UDP {port})");
                    return Ok(ip);
                }
            }
        }
    }
}

fn discover_device_ip(
    device_id: &str,
    mac: Option<&str>,
    bcast_override: Option<&str>,
    udp_timeout_secs: u64,
) -> Result<String, String> {
    if let Some(mac_str) = mac {
        if let Some(target) = parse_mac(mac_str) {
            if let Some(ip) = lookup_ip_by_mac(target) {
                eprintln!("Found {device_id} at {ip} (ARP cache, MAC {mac_str})");
                return Ok(ip);
            }
            eprintln!("MAC {mac_str} not in ARP cache; sweeping subnet...");
            refresh_arp_cache();
            if let Some(ip) = lookup_ip_by_mac(target) {
                eprintln!("Found {device_id} at {ip} (ARP after sweep, MAC {mac_str})");
                return Ok(ip);
            }
            eprintln!("MAC not found via ARP; falling back to UDP broadcast");
        } else {
            eprintln!("Invalid mac '{mac_str}' in config; skipping ARP lookup");
        }
    }
    discover_via_udp(device_id, bcast_override, udp_timeout_secs)
}

// ── Config ──

#[derive(Debug, serde::Deserialize)]
struct Config {
    device: DeviceConfig,
    #[serde(default)]
    mqtt: Option<MqttConfig>,
    #[serde(default)]
    log: Option<LogConfig>,
    #[serde(default = "default_poll_secs")]
    poll_secs: Option<u64>,
    /// Override the subnet-directed broadcast address used by `ip: auto`
    /// discovery. Defaults to a /24 derived from the local interface IP.
    #[serde(default)]
    bcast_addr: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum DeviceType {
    At4pw,
    Ct,
}

#[derive(Debug, serde::Deserialize)]
struct DeviceConfig {
    ip: String,
    id: String,
    local_key: String,
    #[serde(default = "default_version")]
    version: String,
    #[serde(default)]
    device_type: Option<DeviceType>,
    #[serde(default)]
    mac: Option<String>,
}

fn default_version() -> String {
    "3.5".to_string()
}

#[derive(Debug, serde::Deserialize)]
struct MqttConfig {
    host: String,
    #[serde(default = "default_mqtt_port")]
    port: u16,
    #[serde(default = "default_node_id")]
    node_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct LogConfig {
    file: String,
    #[serde(default)]
    max_lines: Option<u64>,
    #[serde(default)]
    rotate_interval: Option<String>, // e.g. "5h", "1d", "30m"
}

fn default_mqtt_port() -> u16 {
    1883
}
fn default_poll_secs() -> Option<u64> {
    Some(10)
}
fn default_node_id() -> String {
    "at4pw".to_string()
}

/// Parse duration string like "5h", "30m", "1d", "3600s" into seconds
fn parse_interval(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty interval".into());
    }
    let (num, suffix) = if s.ends_with('d') {
        (&s[..s.len()-1], 86400u64)
    } else if s.ends_with('h') {
        (&s[..s.len()-1], 3600u64)
    } else if s.ends_with('m') {
        (&s[..s.len()-1], 60u64)
    } else if s.ends_with('s') {
        (&s[..s.len()-1], 1u64)
    } else {
        (s, 1u64) // bare number = seconds
    };
    let n: u64 = num.parse().map_err(|e| format!("bad interval '{s}': {e}"))?;
    Ok(n * suffix)
}

// ── Date formatting for log filenames (strftime-style, no extra deps) ──

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Local UTC offset in seconds, via `date +%z` (e.g. "+0300"). Falls back to UTC.
fn local_utc_offset_secs() -> i64 {
    if let Ok(out) = std::process::Command::new("date").arg("+%z").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        let s = s.trim();
        if s.len() == 5 {
            let sign = if s.starts_with('-') { -1 } else { 1 };
            if let (Ok(h), Ok(m)) = (s[1..3].parse::<i64>(), s[3..5].parse::<i64>()) {
                return sign * (h * 3600 + m * 60);
            }
        }
    }
    0
}

/// Expand %Y %m %d %H %M %S (and %%) in a log file pattern using local time.
fn format_log_path(pattern: &str, epoch_secs: u64, tz_offset_secs: i64) -> String {
    let t = epoch_secs as i64 + tz_offset_secs;
    let (year, month, day) = civil_from_days(t.div_euclid(86400));
    let secs = t.rem_euclid(86400);
    let (hh, mm, ss) = (secs / 3600, (secs / 60) % 60, secs % 60);

    let mut out = String::with_capacity(pattern.len() + 8);
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{year:04}")),
            Some('m') => out.push_str(&format!("{month:02}")),
            Some('d') => out.push_str(&format!("{day:02}")),
            Some('H') => out.push_str(&format!("{hh:02}")),
            Some('M') => out.push_str(&format!("{mm:02}")),
            Some('S') => out.push_str(&format!("{ss:02}")),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

// ── JSONL Logger with rotation ──

struct JsonlLogger {
    pattern: String,
    dated: bool, // pattern contains % specifiers
    tz_offset_secs: i64,
    path: PathBuf,
    max_lines: Option<u64>,
    rotate_interval_secs: Option<u64>,
    current_lines: u64,
    last_interval_n: u64,
    writer: Option<BufWriter<fs::File>>,
}

impl JsonlLogger {
    fn new(cfg: &LogConfig) -> Result<Self, String> {
        let interval_secs = cfg.rotate_interval.as_ref()
            .map(|s| parse_interval(s))
            .transpose()?;

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap().as_secs();
        let interval_n = interval_secs.map(|i| now_secs / i).unwrap_or(0);

        let dated = cfg.file.contains('%');
        let tz_offset_secs = if dated { local_utc_offset_secs() } else { 0 };
        let path = PathBuf::from(format_log_path(&cfg.file, now_secs, tz_offset_secs));
        let mut logger = JsonlLogger {
            pattern: cfg.file.clone(),
            dated,
            tz_offset_secs,
            path,
            max_lines: cfg.max_lines,
            rotate_interval_secs: interval_secs,
            current_lines: 0,
            last_interval_n: interval_n,
            writer: None,
        };
        logger.open_or_resume()?;
        Ok(logger)
    }

    fn open_or_resume(&mut self) -> Result<(), String> {
        // Count existing lines if file exists
        if self.path.exists() {
            let f = fs::File::open(&self.path)
                .map_err(|e| format!("open {}: {e}", self.path.display()))?;
            self.current_lines = BufReader::new(f).lines().count() as u64;
        } else {
            self.current_lines = 0;
        }
        let file = fs::OpenOptions::new()
            .create(true).append(true)
            .open(&self.path)
            .map_err(|e| format!("open {}: {e}", self.path.display()))?;
        self.writer = Some(BufWriter::new(file));
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), String> {
        // Close current writer
        self.writer = None;

        // Rename current → .1, shifting existing rotations
        let base = self.path.to_string_lossy().to_string();
        // Remove old .3 if exists
        let _ = fs::remove_file(format!("{base}.3"));
        for i in (1..=2).rev() {
            let from = if i == 1 { base.clone() } else { format!("{base}.{}", i - 1) };
            let to = format!("{base}.{i}");
            let _ = fs::rename(&from, &to);
        }

        eprintln!("Log rotated: {}", self.path.display());
        self.current_lines = 0;
        let file = fs::OpenOptions::new()
            .create(true).append(true)
            .open(&self.path)
            .map_err(|e| format!("create {}: {e}", self.path.display()))?;
        self.writer = Some(BufWriter::new(file));
        Ok(())
    }

    fn check_rotation(&mut self) -> Result<(), String> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Date-patterned filename: switch to the new file when the name changes
        if self.dated {
            let new_path = PathBuf::from(format_log_path(
                &self.pattern, now_secs, self.tz_offset_secs,
            ));
            if new_path != self.path {
                self.writer = None;
                eprintln!(
                    "Log file switched: {} -> {}",
                    self.path.display(), new_path.display()
                );
                self.path = new_path;
                self.open_or_resume()?;
            }
        }
        // Check time-based rotation
        if let Some(interval) = self.rotate_interval_secs {
            let interval_n = now_secs / interval;
            if interval_n != self.last_interval_n {
                self.last_interval_n = interval_n;
                self.rotate()?;
                return Ok(());
            }
        }
        // Check line-count rotation
        if let Some(max) = self.max_lines {
            if self.current_lines >= max {
                self.rotate()?;
            }
        }
        Ok(())
    }

    fn write_line(&mut self, json: &str) -> Result<(), String> {
        self.check_rotation()?;
        if let Some(ref mut w) = self.writer {
            writeln!(w, "{json}").map_err(|e| format!("write: {e}"))?;
            w.flush().map_err(|e| format!("flush: {e}"))?;
            self.current_lines += 1;
        }
        Ok(())
    }

    fn log_state(&mut self, state: &serde_json::Value) -> Result<(), String> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap().as_secs();
        let entry = serde_json::json!({
            "t": ts,
            "data": state,
        });
        self.write_line(&serde_json::to_string(&entry).unwrap())
    }
}

fn parse_version(s: &str) -> ProtoVer {
    match s {
        "3.3" => ProtoVer::V33,
        "3.4" => ProtoVer::V34,
        "3.5" => ProtoVer::V35,
        _ => {
            eprintln!("Unknown protocol version: {s}, using 3.5");
            ProtoVer::V35
        }
    }
}

fn load_config(path: &str) -> Result<Config, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    serde_yaml::from_str(&content).map_err(|e| format!("parse {path}: {e}"))
}

// ── Protocol version ──

#[derive(Debug, Clone, Copy, PartialEq)]
enum ProtoVer {
    V33,
    V34,
    V35,
}

struct TuyaDevice {
    stream: TcpStream,
    dev_id: String,
    local_key: [u8; 16],
    version: ProtoVer,
    session_key: Option<[u8; 16]>,
    seqno: u32,
}

impl TuyaDevice {
    fn connect(ip: &str, dev_id: &str, local_key: &str, version: ProtoVer) -> Result<Self, String> {
        let mut key = [0u8; 16];
        let kb = local_key.as_bytes();
        if kb.len() < 16 {
            return Err(format!("local_key must be at least 16 bytes, got {}", kb.len()));
        }
        key.copy_from_slice(&kb[..16]);

        let addr = format!("{}:6668", ip);
        let stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("bad addr: {e}"))?,
            Duration::from_secs(5),
        )
        .map_err(|e| format!("connect failed: {e}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_nodelay(true).ok();

        let mut dev = TuyaDevice {
            stream,
            dev_id: dev_id.to_string(),
            local_key: key,
            version,
            session_key: None,
            seqno: 0,
        };

        if version == ProtoVer::V34 || version == ProtoVer::V35 {
            dev.negotiate_session()?;
        }

        Ok(dev)
    }

    fn enc_key(&self) -> &[u8; 16] {
        self.session_key.as_ref().unwrap_or(&self.local_key)
    }

    fn next_seq(&mut self) -> u32 {
        self.seqno += 1;
        self.seqno
    }

    // ── Message building ──

    fn build_msg_55aa(&mut self, cmd: u32, payload: &[u8], hmac_key: &[u8; 16]) -> Vec<u8> {
        let seq = self.next_seq();
        let use_hmac = self.version == ProtoVer::V34;
        let suffix_len: u32 = if use_hmac { 32 + 4 } else { 4 + 4 };
        let length = payload.len() as u32 + suffix_len;

        let mut msg = Vec::with_capacity(16 + payload.len() + suffix_len as usize);
        msg.extend_from_slice(&PREFIX_55AA.to_be_bytes());
        msg.extend_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(&cmd.to_be_bytes());
        msg.extend_from_slice(&length.to_be_bytes());
        msg.extend_from_slice(payload);

        if use_hmac {
            let hmac = hmac_sha256(hmac_key, &msg);
            msg.extend_from_slice(&hmac);
        } else {
            let crc = crc32(&msg);
            msg.extend_from_slice(&crc.to_be_bytes());
        }
        msg.extend_from_slice(&SUFFIX_55AA.to_be_bytes());
        msg
    }

    fn build_msg_6699(&mut self, cmd: u32, payload: &[u8], enc_key: &[u8; 16]) -> Vec<u8> {
        let seq = self.next_seq();
        let ts = format!("{}", (now_secs() as f64 * 10.0) as u64);
        let iv_bytes: Vec<u8> = ts.bytes().take(12).collect();
        let mut iv = [0u8; 12];
        let copy_len = iv_bytes.len().min(12);
        iv[..copy_len].copy_from_slice(&iv_bytes[..copy_len]);

        let length = payload.len() as u32 + 16 + 12;

        let mut header = Vec::with_capacity(18);
        header.extend_from_slice(&PREFIX_6699.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&seq.to_be_bytes());
        header.extend_from_slice(&cmd.to_be_bytes());
        header.extend_from_slice(&length.to_be_bytes());

        let aad = header[4..18].to_vec();

        let gcm = Aes128Gcm::new(enc_key.into());
        let nonce = GcmNonce::from_slice(&iv);
        let mut buffer = payload.to_vec();
        let tag = gcm
            .encrypt_in_place_detached(nonce, &aad, &mut buffer)
            .unwrap();

        let mut msg = header;
        msg.extend_from_slice(&iv);
        msg.extend_from_slice(&buffer);
        msg.extend_from_slice(&tag);
        msg.extend_from_slice(&SUFFIX_6699.to_be_bytes());
        msg
    }

    fn send_raw(&mut self, data: &[u8]) -> Result<(), String> {
        self.stream.write_all(data).map_err(|e| format!("write: {e}"))
    }

    fn recv_raw(&mut self) -> Result<Vec<u8>, String> {
        let mut buf = [0u8; 4096];
        let n = self.stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        Ok(buf[..n].to_vec())
    }

    // ── Parse received messages ──

    fn parse_55aa(&self, data: &[u8]) -> Result<(u32, Vec<u8>), String> {
        if data.len() < 20 {
            return Err("message too short".into());
        }
        let prefix = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if prefix != PREFIX_55AA {
            return Err(format!("bad prefix: {prefix:#x}"));
        }
        let cmd = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let length = u32::from_be_bytes(data[12..16].try_into().unwrap()) as usize;

        let suffix_size = if self.version == ProtoVer::V34 { 36 } else { 8 };
        let payload_len = length.saturating_sub(suffix_size);
        // retcode is first 4 bytes of payload area
        let payload_start = 16 + 4;
        let payload_end = 16 + payload_len;

        if payload_end > data.len() {
            return Err(format!("truncated: end={payload_end} len={}", data.len()));
        }

        let payload = if payload_start <= payload_end {
            data[payload_start..payload_end].to_vec()
        } else {
            vec![]
        };

        Ok((cmd, payload))
    }

    fn parse_6699(&self, data: &[u8], dec_key: &[u8; 16]) -> Result<(u32, Vec<u8>), String> {
        if data.len() < 22 {
            return Err("6699 message too short".into());
        }
        let prefix = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if prefix != PREFIX_6699 {
            return Err(format!("bad prefix: {prefix:#x}"));
        }
        let cmd = u32::from_be_bytes(data[10..14].try_into().unwrap());
        let length = u32::from_be_bytes(data[14..18].try_into().unwrap()) as usize;

        let enc_start = 18;
        let enc_end = 18 + length;
        if enc_end + 4 > data.len() {
            return Err("6699 message truncated".into());
        }

        let iv = &data[enc_start..enc_start + 12];
        let tag_start = enc_end - 16;
        let ct = &data[enc_start + 12..tag_start];
        let tag = &data[tag_start..enc_end];
        let aad = &data[4..18];

        let gcm = Aes128Gcm::new(dec_key.into());
        let nonce = GcmNonce::from_slice(iv);
        let mut buffer = ct.to_vec();

        use aes_gcm::aead::generic_array::GenericArray;
        let tag_arr = GenericArray::clone_from_slice(tag);
        gcm.decrypt_in_place_detached(nonce, aad, &mut buffer, &tag_arr)
            .map_err(|e| format!("GCM decrypt failed: {e}"))?;

        // Strip version header ("3.5\0...") or retcode prefix
        let payload = if buffer.len() >= 15 && buffer.starts_with(b"3.5") {
            // Version header: "3.5" + 12 zero bytes, then optional 4-byte retcode
            let after_hdr = &buffer[15..];
            if after_hdr.len() >= 4 && after_hdr[0] != b'{' {
                after_hdr[4..].to_vec()
            } else {
                after_hdr.to_vec()
            }
        } else if !buffer.is_empty() && buffer[0] != b'{' && buffer.len() > 4 {
            buffer[4..].to_vec()
        } else {
            buffer
        };

        Ok((cmd, payload))
    }

    fn decrypt_payload(&self, encrypted: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.enc_key();
        let decrypted = aes_ecb_decrypt(key, encrypted);
        // Strip version header ("3.3\0..." or "3.4\0...")
        if decrypted.len() >= 15
            && (decrypted.starts_with(b"3.3") || decrypted.starts_with(b"3.4"))
        {
            Ok(decrypted[15..].to_vec())
        } else {
            Ok(decrypted)
        }
    }

    fn send_and_recv(&mut self, msg: &[u8]) -> Result<(u32, Vec<u8>), String> {
        self.send_raw(msg)?;
        let resp = self.recv_raw()?;

        if resp.len() < 4 {
            return Err("response too short".into());
        }

        let prefix = u32::from_be_bytes(resp[0..4].try_into().unwrap());
        match prefix {
            PREFIX_55AA => {
                let (cmd, payload) = self.parse_55aa(&resp)?;
                if (self.version == ProtoVer::V33 || self.version == ProtoVer::V34) && !payload.is_empty() {
                    let dec = self.decrypt_payload(&payload)?;
                    Ok((cmd, dec))
                } else {
                    Ok((cmd, payload))
                }
            }
            PREFIX_6699 => {
                let key = *self.enc_key();
                self.parse_6699(&resp, &key)
            }
            _ => Err(format!("unknown prefix: {prefix:#x}")),
        }
    }

    // ── Session key negotiation (3.4 / 3.5) ──

    fn negotiate_session(&mut self) -> Result<(), String> {
        let local_nonce: [u8; 16] = *b"0123456789abcdef";

        // Step 1: Send SESS_KEY_NEG_START with local_nonce
        let key = self.local_key;
        let msg = if self.version == ProtoVer::V35 {
            self.build_msg_6699(CMD_SESS_KEY_NEG_START, &local_nonce, &key)
        } else {
            self.build_msg_55aa(CMD_SESS_KEY_NEG_START, &local_nonce, &key)
        };
        self.send_raw(&msg)?;

        // Step 2: Receive SESS_KEY_NEG_RESP
        let resp_data = self.recv_raw()?;
        let prefix = u32::from_be_bytes(resp_data[0..4].try_into().unwrap());

        let payload = match prefix {
            PREFIX_55AA => {
                let (_, enc_payload) = self.parse_55aa(&resp_data)?;
                aes_ecb_decrypt(&self.local_key, &enc_payload)
            }
            PREFIX_6699 => {
                let (_, p) = self.parse_6699(&resp_data, &self.local_key)?;
                p
            }
            _ => return Err(format!("unexpected prefix: {prefix:#x}")),
        };

        if payload.len() < 48 {
            return Err(format!("session response too short: {} bytes", payload.len()));
        }

        let remote_nonce: [u8; 16] = payload[0..16].try_into().unwrap();
        let expected_hmac = hmac_sha256(&self.local_key, &local_nonce);
        if payload[16..48] != expected_hmac {
            return Err("HMAC verification of local_nonce failed".into());
        }

        // Step 3: Send SESS_KEY_NEG_FINISH with HMAC of remote_nonce
        let resp_hmac = hmac_sha256(&self.local_key, &remote_nonce);
        let key = self.local_key;
        let finish_msg = if self.version == ProtoVer::V35 {
            self.build_msg_6699(CMD_SESS_KEY_NEG_FINISH, &resp_hmac, &key)
        } else {
            self.build_msg_55aa(CMD_SESS_KEY_NEG_FINISH, &resp_hmac, &key)
        };
        self.send_raw(&finish_msg)?;

        // Derive session key
        let mut xored = [0u8; 16];
        for i in 0..16 {
            xored[i] = local_nonce[i] ^ remote_nonce[i];
        }

        let session_key = if self.version == ProtoVer::V35 {
            let gcm = Aes128Gcm::new((&self.local_key).into());
            let iv = GcmNonce::from_slice(&local_nonce[..12]);
            let mut buf = xored.to_vec();
            gcm.encrypt_in_place_detached(iv, &[], &mut buf)
                .map_err(|e| format!("GCM session key derivation: {e}"))?;
            let mut sk = [0u8; 16];
            sk.copy_from_slice(&buf[..16]);
            sk
        } else {
            aes_ecb_encrypt_block(&self.local_key, &xored)
        };

        self.session_key = Some(session_key);
        eprintln!("Session negotiated OK");

        // Consume any extra ack
        let _ = self.recv_raw();

        Ok(())
    }

    // ── Heartbeat ──

    const CMD_HEART_BEAT: u32 = 9;

    fn send_heartbeat(&mut self) -> Result<(), String> {
        let msg = match self.version {
            ProtoVer::V33 => {
                let key = self.local_key;
                self.build_msg_55aa(Self::CMD_HEART_BEAT, b"", &key)
            }
            ProtoVer::V34 => {
                let key = *self.enc_key();
                self.build_msg_55aa(Self::CMD_HEART_BEAT, b"", &key)
            }
            ProtoVer::V35 => {
                let key = *self.enc_key();
                self.build_msg_6699(Self::CMD_HEART_BEAT, b"", &key)
            }
        };
        self.send_raw(&msg)
    }

    /// Try to receive and decode one message (non-blocking if timeout is set)
    fn recv_one(&mut self) -> Result<Option<serde_json::Value>, String> {
        let resp = match self.recv_raw() {
            Ok(r) => r,
            Err(_) => return Ok(None), // timeout
        };
        if resp.len() < 4 {
            return Ok(None);
        }
        let prefix = u32::from_be_bytes(resp[0..4].try_into().unwrap());
        let payload = match prefix {
            PREFIX_55AA => {
                let (_, p) = self.parse_55aa(&resp)?;
                if !p.is_empty() {
                    self.decrypt_payload(&p)?
                } else {
                    return Ok(None);
                }
            }
            PREFIX_6699 => {
                let key = *self.enc_key();
                let (_, p) = self.parse_6699(&resp, &key)?;
                p
            }
            _ => return Ok(None),
        };
        match Self::parse_dps_response(&payload) {
            Ok(dps) => Ok(Some(dps)),
            Err(_) => Ok(None),
        }
    }

    // ── Query device status ──

    fn send_cmd(&mut self, cmd: u32, payload: &[u8]) -> Result<(u32, Vec<u8>), String> {
        let (actual_cmd, payload_bytes) = match self.version {
            ProtoVer::V33 => {
                let encrypted = aes_ecb_encrypt(&self.local_key, payload);
                (cmd, encrypted)
            }
            ProtoVer::V34 => {
                let encrypted = aes_ecb_encrypt(self.enc_key(), payload);
                (cmd, encrypted)
            }
            ProtoVer::V35 => (cmd, payload.to_vec()),
        };

        let msg = match self.version {
            ProtoVer::V33 => {
                let key = self.local_key;
                self.build_msg_55aa(actual_cmd, &payload_bytes, &key)
            }
            ProtoVer::V34 => {
                let key = *self.enc_key();
                self.build_msg_55aa(actual_cmd, &payload_bytes, &key)
            }
            ProtoVer::V35 => {
                let key = *self.enc_key();
                self.build_msg_6699(actual_cmd, &payload_bytes, &key)
            }
        };

        self.send_and_recv(&msg)
    }

    fn extract_dps(val: &serde_json::Value) -> Option<serde_json::Value> {
        if let Some(data) = val.get("data") {
            if let Some(dps) = data.get("dps") {
                return Some(dps.clone());
            }
        }
        if let Some(dps) = val.get("dps") {
            return Some(dps.clone());
        }
        None
    }

    fn parse_dps_response(data: &[u8]) -> Result<serde_json::Value, String> {
        // Find the start of JSON (skip version header / retcode if present)
        let json_start = data.iter().position(|&b| b == b'{').unwrap_or(0);
        let json_bytes = &data[json_start..];
        let json_str = String::from_utf8(json_bytes.to_vec()).map_err(|e| format!("utf8: {e}"))?;
        let val: serde_json::Value =
            serde_json::from_str(&json_str).map_err(|e| format!("json: {e}: {json_str}"))?;
        Ok(Self::extract_dps(&val).unwrap_or(val))
    }

    /// Request refresh of specific DPs via UPDATEDPS, then collect responses
    fn request_all_dps(&mut self) -> Result<serde_json::Value, String> {
        // First, send UPDATEDPS to ask device to refresh all DPs
        let dp_list: Vec<u32> = ALL_DPS.to_vec();
        let update_payload = serde_json::json!({"dpId": dp_list});
        let update_bytes = serde_json::to_vec(&update_payload).unwrap();

        // UPDATEDPS is in NO_PROTOCOL_HEADER_CMDS, no version header needed
        let msg = match self.version {
            ProtoVer::V33 => {
                let encrypted = aes_ecb_encrypt(&self.local_key, &update_bytes);
                let key = self.local_key;
                self.build_msg_55aa(CMD_UPDATEDPS, &encrypted, &key)
            }
            ProtoVer::V34 => {
                let encrypted = aes_ecb_encrypt(self.enc_key(), &update_bytes);
                let key = *self.enc_key();
                self.build_msg_55aa(CMD_UPDATEDPS, &encrypted, &key)
            }
            ProtoVer::V35 => {
                let key = *self.enc_key();
                self.build_msg_6699(CMD_UPDATEDPS, &update_bytes, &key)
            }
        };
        self.send_raw(&msg)?;

        // Collect responses — device sends STATUS pushes in bursts every ~5s
        let mut merged = serde_json::Map::new();

        // Wait up to 6 seconds for responses (covers at least one full push cycle)
        self.stream.set_read_timeout(Some(Duration::from_secs(6))).ok();

        let deadline = SystemTime::now() + Duration::from_secs(8);
        loop {
            if SystemTime::now() > deadline {
                break;
            }
            match self.recv_raw() {
                Ok(resp) => {
                    if resp.len() < 4 {
                        continue;
                    }
                    let prefix = u32::from_be_bytes(resp[0..4].try_into().unwrap());
                    let payload = match prefix {
                        PREFIX_55AA => {
                            let (_, p) = self.parse_55aa(&resp)?;
                            if !p.is_empty() {
                                self.decrypt_payload(&p)?
                            } else {
                                continue;
                            }
                        }
                        PREFIX_6699 => {
                            let key = *self.enc_key();
                            let (_, p) = self.parse_6699(&resp, &key)?;
                            p
                        }
                        _ => continue,
                    };
                    if let Ok(dps) = Self::parse_dps_response(&payload) {
                        if let Some(obj) = dps.as_object() {
                            for (k, v) in obj {
                                merged.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
                Err(_) => break, // timeout = no more data
            }
        }

        // Restore timeout
        self.stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        if merged.is_empty() {
            Err("no DPs received".into())
        } else {
            Ok(serde_json::Value::Object(merged))
        }
    }

    fn query_dps(&mut self) -> Result<serde_json::Value, String> {
        let cmd = match self.version {
            ProtoVer::V33 => CMD_DP_QUERY,
            _ => CMD_DP_QUERY_NEW,
        };

        let payload = match self.version {
            ProtoVer::V33 => format!(
                r#"{{"gwId":"{}","devId":"{}","uid":"{}","t":"{}"}}"#,
                self.dev_id, self.dev_id, self.dev_id, now_secs()
            ).into_bytes(),
            _ => b"{}".to_vec(),
        };

        let (_, resp) = self.send_cmd(cmd, &payload)?;
        let initial = Self::parse_dps_response(&resp)?;

        // Request ALL DPs via UPDATEDPS and merge everything
        let mut merged = serde_json::Map::new();

        // Start with initial query results
        if let Some(obj) = initial.as_object() {
            for (k, v) in obj {
                merged.insert(k.clone(), v.clone());
            }
        }

        // Merge UPDATEDPS results (overwrites initial for same keys)
        if let Ok(all) = self.request_all_dps() {
            if let Some(obj) = all.as_object() {
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }

        Ok(serde_json::Value::Object(merged))
    }

    fn set_dp(&mut self, dp: &str, value: serde_json::Value) -> Result<(), String> {
        let mut dps = serde_json::Map::new();
        dps.insert(dp.to_string(), value);

        let (cmd, payload_bytes) = match self.version {
            ProtoVer::V33 => {
                let payload = serde_json::json!({
                    "devId": self.dev_id, "uid": self.dev_id,
                    "t": now_secs().to_string(), "dps": dps,
                });
                let mut with_hdr = Vec::from(b"3.3" as &[u8]);
                with_hdr.extend_from_slice(&[0u8; 12]);
                with_hdr.extend_from_slice(serde_json::to_string(&payload).unwrap().as_bytes());
                (CMD_CONTROL, aes_ecb_encrypt(&self.local_key, &with_hdr))
            }
            ProtoVer::V34 => {
                let payload = serde_json::json!({
                    "protocol": 5, "t": now_secs(), "data": {"dps": dps},
                });
                let mut with_hdr = Vec::from(b"3.4" as &[u8]);
                with_hdr.extend_from_slice(&[0u8; 12]);
                with_hdr.extend_from_slice(serde_json::to_string(&payload).unwrap().as_bytes());
                (CMD_CONTROL_NEW, aes_ecb_encrypt(self.enc_key(), &with_hdr))
            }
            ProtoVer::V35 => {
                let payload = serde_json::json!({
                    "protocol": 5, "t": now_secs(), "data": {"dps": dps},
                });
                let mut with_hdr = Vec::from(b"3.5" as &[u8]);
                with_hdr.extend_from_slice(&[0u8; 12]);
                with_hdr.extend_from_slice(serde_json::to_string(&payload).unwrap().as_bytes());
                (CMD_CONTROL_NEW, with_hdr)
            }
        };

        let msg = match self.version {
            ProtoVer::V33 => {
                let key = self.local_key;
                self.build_msg_55aa(cmd, &payload_bytes, &key)
            }
            ProtoVer::V34 => {
                let key = *self.enc_key();
                self.build_msg_55aa(cmd, &payload_bytes, &key)
            }
            ProtoVer::V35 => {
                let key = *self.enc_key();
                self.build_msg_6699(cmd, &payload_bytes, &key)
            }
        };

        self.send_and_recv(&msg)?;
        Ok(())
    }
}

/// Decode CT phase_a Raw dp 6: base64 → 8 bytes
/// [0-1] voltage (V * 10), [2-4] current (mA), [5-7] power (W)
fn decode_phase_a(b64: &str) -> Option<(f64, f64, f64)> {
    let raw = b64_decode(b64)?;
    if raw.len() < 8 {
        return None;
    }
    let voltage = u16::from_be_bytes([raw[0], raw[1]]) as f64 / 10.0;
    let current = u32::from_be_bytes([0, raw[2], raw[3], raw[4]]) as f64 / 1000.0;
    let power = u32::from_be_bytes([0, raw[5], raw[6], raw[7]]) as f64;
    Some((voltage, current, power))
}

fn detect_device_type(dps: &serde_json::Value) -> DeviceType {
    // AT4P-W uses dp 20 (cur_voltage), CT uses dp 6 (phase_a) or dp 32 (supply_frequency) without dp 20
    if dps.get("20").is_some() || dps.get("18").is_some() {
        DeviceType::At4pw
    } else {
        DeviceType::Ct
    }
}

fn print_meter(dps: &serde_json::Value, dev_type: DeviceType) {
    let get = |k: &str| dps.get(k).and_then(|v| v.as_f64());

    match dev_type {
        DeviceType::At4pw => {
            println!("=== AT4P-W Power Meter ===");
            if let Some(v) = get("20") {
                println!("  Voltage:        {:.1} V", v / 100.0);
            }
            if let Some(v) = get("18") {
                println!("  Current:        {:.3} A", v / 1000.0);
            }
            if let Some(v) = get("19") {
                println!("  Power:          {:.1} W", v / 100.0);
            }
            if let Some(v) = get("133") {
                println!("  Frequency:      {:.2} Hz", v / 100.0);
            }
            if let Some(v) = get("134") {
                println!("  Power Factor:   {:.2}", v / 100.0);
            }
            if let Some(v) = get("123") {
                println!("  Total Energy:   {:.2} kWh", v / 100.0);
            }
            if let Some(v) = get("17") {
                println!("  Session Energy: {:.2} kWh", v / 100.0);
            }
            if let Some(v) = get("102") {
                println!("  Cost:           {:.2}", v / 100.0);
            }
            if let Some(v) = get("135") {
                println!("  CPU Temp:       {} C", v as u32);
            }
            if let Some(v) = get("124") {
                println!("  Leakage:        {} mA", v as u32);
            }
            if let Some(v) = dps.get("1") {
                println!(
                    "  Switch:         {}",
                    if v.as_bool().unwrap_or(false) { "ON" } else { "OFF" }
                );
            }
        }
        DeviceType::Ct => {
            println!("=== SA1 CT Power Meter ===");
            // dp 6 (phase_a Raw) contains V/I/P but is only pushed when app is active
            if let Some(b64) = dps.get("6").and_then(|v| v.as_str()) {
                if let Some((v, i, p)) = decode_phase_a(b64) {
                    println!("  Voltage:        {:.1} V", v);
                    println!("  Current:        {:.3} A", i);
                    println!("  Power:          {} W", p as u32);
                }
            }
            if let Some(v) = get("32") {
                println!("  Frequency:      {:.2} Hz", v / 100.0);
            }
            if let Some(v) = get("50") {
                println!("  Power Factor:   {:.2}", v / 100.0);
            }
            if let Some(v) = get("1") {
                println!("  Total Energy:   {:.2} kWh", v / 100.0);
            }
            if let Some(v) = get("131") {
                println!("  Temperature:    {:.1} C", v / 10.0);
            }
        }
    }
}

// ── Server: MQTT bridge + JSONL logging ──

struct Server {
    dev: DeviceConfig,
    mqtt: Option<MqttConfig>,
    logger: Option<JsonlLogger>,
    dev_type: DeviceType,
    poll_secs: u64,
    auto_ip: bool,
    bcast_addr: Option<String>,
}

impl Server {
    fn ha_discovery_configs(&self) -> Vec<(String, serde_json::Value)> {
        let mqtt = match self.mqtt {
            Some(ref m) => m,
            None => return Vec::new(),
        };
        let node_id = &mqtt.node_id;
        let (dev_name, dev_model) = match self.dev_type {
            DeviceType::At4pw => ("AT4P-W Power Meter", "AT4P-W"),
            DeviceType::Ct => ("SA1 CT Power Meter", "SA1"),
        };
        let device = serde_json::json!({
            "identifiers": [node_id],
            "name": dev_name,
            "model": dev_model,
            "manufacturer": "Tuya"
        });
        let state_topic = format!("home/{}/state", node_id);
        let avail_topic = format!("home/{}/availability", node_id);

        // Common sensors for both device types
        let sensors: Vec<(&str, &str, &str, &str, &str)> = vec![
            ("voltage",      "Voltage",      "voltage",      "V",   "voltage"),
            ("current",      "Current",      "current",      "A",   "current"),
            ("power",        "Power",        "power",        "W",   "power"),
            ("energy",       "Total Energy", "energy",       "kWh", "energy"),
            ("frequency",    "Frequency",    "frequency",    "Hz",  "frequency"),
            ("power_factor", "Power Factor", "power_factor", "",    "power_factor"),
            ("temperature",  "Temperature",  "temperature",  "°C",  "temperature"),
        ];

        // Extra sensors only for AT4P-W
        let at4pw_extra: Vec<(&str, &str, &str, &str, &str)> = vec![
            ("session_energy", "Session Energy", "energy",  "kWh", "session_energy"),
            ("cost",           "Cost",           "monetary", "",   "cost"),
            ("leakage",        "Leakage Current","current",  "mA", "leakage_ma"),
        ];

        let mut all_sensors = sensors;
        if self.dev_type == DeviceType::At4pw {
            all_sensors.extend(at4pw_extra);
        }

        let mut configs = Vec::new();

        for (obj_id, name, dev_class, unit, field) in &all_sensors {
            let topic = format!("homeassistant/sensor/{}/{}/config", node_id, obj_id);
            let mut config = serde_json::json!({
                "name": name,
                "device_class": dev_class,
                "state_topic": &state_topic,
                "availability_topic": &avail_topic,
                "unique_id": format!("{}_{}", node_id, obj_id),
                "device": &device,
                "value_template": format!("{{{{ value_json.{} }}}}", field),
            });
            if !unit.is_empty() {
                config["unit_of_measurement"] = serde_json::json!(unit);
            }
            if *dev_class == "energy" {
                config["state_class"] = serde_json::json!("total_increasing");
            } else {
                config["state_class"] = serde_json::json!("measurement");
            }
            configs.push((topic, config));
        }

        // Switch only for AT4P-W (CT doesn't have a relay)
        if self.dev_type == DeviceType::At4pw {
            let switch_topic = format!("homeassistant/switch/{}/switch/config", node_id);
            let cmd_topic = format!("home/{}/switch/set", node_id);
            configs.push((
                switch_topic,
                serde_json::json!({
                    "name": "Switch",
                    "device_class": "switch",
                    "state_topic": &state_topic,
                    "command_topic": &cmd_topic,
                    "availability_topic": &avail_topic,
                    "unique_id": format!("{}_switch", node_id),
                    "device": &device,
                    "value_template": "{{ value_json.switch }}",
                    "payload_on": "ON",
                    "payload_off": "OFF",
                    "state_on": "ON",
                    "state_off": "OFF",
                }),
            ));
        }

        configs
    }

    fn dps_to_state(dps: &serde_json::Value, dev_type: DeviceType) -> serde_json::Value {
        let get = |k: &str| dps.get(k).and_then(|v| v.as_f64());
        let mut state = serde_json::Map::new();

        match dev_type {
            DeviceType::At4pw => {
                if let Some(v) = get("20") {
                    state.insert("voltage".into(), serde_json::json!(format!("{:.1}", v / 100.0)));
                }
                if let Some(v) = get("18") {
                    state.insert("current".into(), serde_json::json!(format!("{:.3}", v / 1000.0)));
                }
                if let Some(v) = get("19") {
                    state.insert("power".into(), serde_json::json!(format!("{:.1}", v / 100.0)));
                }
                if let Some(v) = get("123") {
                    state.insert("energy".into(), serde_json::json!(format!("{:.2}", v / 100.0)));
                }
                if let Some(v) = get("17") {
                    state.insert("session_energy".into(), serde_json::json!(format!("{:.2}", v / 100.0)));
                }
                if let Some(v) = get("133") {
                    state.insert("frequency".into(), serde_json::json!(format!("{:.2}", v / 100.0)));
                }
                if let Some(v) = get("134") {
                    state.insert("power_factor".into(), serde_json::json!(format!("{:.2}", v / 100.0)));
                }
                if let Some(v) = get("102") {
                    state.insert("cost".into(), serde_json::json!(format!("{:.2}", v / 100.0)));
                }
                if let Some(v) = get("135") {
                    state.insert("temperature".into(), serde_json::json!(v as i64));
                }
                if let Some(v) = get("124") {
                    state.insert("leakage_ma".into(), serde_json::json!(v as i64));
                }
                if let Some(v) = dps.get("1") {
                    state.insert(
                        "switch".into(),
                        serde_json::json!(if v.as_bool().unwrap_or(false) { "ON" } else { "OFF" }),
                    );
                }
            }
            DeviceType::Ct => {
                // dp 6 (phase_a Raw) contains V/I/P but only when app is active
                if let Some(b64) = dps.get("6").and_then(|v| v.as_str()) {
                    if let Some((v, i, p)) = decode_phase_a(b64) {
                        state.insert("voltage".into(), serde_json::json!(format!("{:.1}", v)));
                        state.insert("current".into(), serde_json::json!(format!("{:.3}", i)));
                        state.insert("power".into(), serde_json::json!(format!("{:.0}", p)));
                    }
                }
                if let Some(v) = get("32") {
                    state.insert("frequency".into(), serde_json::json!(format!("{:.2}", v / 100.0)));
                }
                if let Some(v) = get("50") {
                    state.insert("power_factor".into(), serde_json::json!(format!("{:.2}", v / 100.0)));
                }
                if let Some(v) = get("1") {
                    state.insert("energy".into(), serde_json::json!(format!("{:.2}", v / 100.0)));
                }
                if let Some(v) = get("131") {
                    state.insert("temperature".into(), serde_json::json!(format!("{:.1}", v / 10.0)));
                }
            }
        }
        serde_json::Value::Object(state)
    }

    fn run(&mut self) {
        let version = parse_version(&self.dev.version);
        let poll_secs = self.poll_secs;
        let dev_type = self.dev_type;

        // Set up MQTT if configured
        let mut mqtt_client: Option<Client> = None;
        let mut avail_topic = String::new();
        let mut state_topic = String::new();
        #[allow(unused_assignments)]
        let mut cmd_topic = String::new();
        let (switch_tx, switch_rx) = std::sync::mpsc::channel::<bool>();

        if let Some(ref mqtt) = self.mqtt {
            let mqtt_host = mqtt.host.trim_start_matches('[').trim_end_matches(']');
            let mut mqttopts = MqttOptions::new(
                format!("at4pw-{}", &mqtt.node_id),
                mqtt_host,
                mqtt.port,
            );
            mqttopts.set_keep_alive(Duration::from_secs(30));

            avail_topic = format!("home/{}/availability", mqtt.node_id);
            state_topic = format!("home/{}/state", mqtt.node_id);
            cmd_topic = format!("home/{}/switch/set", mqtt.node_id);

            mqttopts.set_last_will(rumqttc::LastWill::new(
                &avail_topic,
                "offline",
                QoS::AtLeastOnce,
                true,
            ));

            let (client, mut connection) = Client::new(mqttopts, 32);

            // Publish HA discovery configs
            for (topic, config) in self.ha_discovery_configs() {
                let payload = serde_json::to_string(&config).unwrap();
                client
                    .publish(&topic, QoS::AtLeastOnce, true, payload)
                    .ok();
            }

            // Mark online
            client
                .publish(&avail_topic, QoS::AtLeastOnce, true, "online")
                .ok();

            // Subscribe to switch commands (AT4P-W only)
            if self.dev_type == DeviceType::At4pw {
                client.subscribe(&cmd_topic, QoS::AtLeastOnce).ok();
            }

            // Spawn MQTT event loop in background
            let cmd_topic_clone = cmd_topic.clone();
            let switch_tx_clone = switch_tx.clone();
            std::thread::spawn(move || {
                for notification in connection.iter() {
                    if let Ok(rumqttc::Event::Incoming(rumqttc::Packet::Publish(msg))) = notification {
                        if msg.topic == cmd_topic_clone {
                            let payload = String::from_utf8_lossy(&msg.payload);
                            match payload.as_ref() {
                                "ON" => { switch_tx_clone.send(true).ok(); }
                                "OFF" => { switch_tx_clone.send(false).ok(); }
                                _ => {}
                            }
                        }
                    }
                }
            });

            eprintln!(
                "MQTT: {}:{} node_id={}",
                mqtt.host, mqtt.port, mqtt.node_id
            );
            mqtt_client = Some(client);
        }

        if self.logger.is_some() {
            eprintln!("JSONL log enabled");
        }

        eprintln!(
            "Server started (persistent connection, poll every {}s)",
            poll_secs
        );

        // Persistent connection loop with auto-reconnect
        loop {
            eprintln!("Connecting to {}...", self.dev.ip);
            let mut dev = match TuyaDevice::connect(
                &self.dev.ip, &self.dev.id, &self.dev.local_key, version,
            ) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Connect failed: {e}");
                    if let Some(ref client) = mqtt_client {
                        client
                            .publish(&avail_topic, QoS::AtLeastOnce, true, "offline")
                            .ok();
                    }
                    if self.auto_ip {
                        match discover_device_ip(
                            &self.dev.id,
                            self.dev.mac.as_deref(),
                            self.bcast_addr.as_deref(),
                            AUTO_IP_DISCOVERY_TIMEOUT_SECS,
                        ) {
                            Ok(ip) => {
                                if ip != self.dev.ip {
                                    eprintln!("IP changed: {} -> {ip}", self.dev.ip);
                                }
                                self.dev.ip = ip;
                            }
                            Err(de) => eprintln!("Re-discovery failed: {de}"),
                        }
                    }
                    std::thread::sleep(Duration::from_secs(poll_secs));
                    continue;
                }
            };

            if let Some(ref client) = mqtt_client {
                client
                    .publish(&avail_topic, QoS::AtLeastOnce, true, "online")
                    .ok();
            }

            // Initial query to get all DPs
            let mut state = serde_json::Map::new();
            if let Ok(dps) = dev.query_dps() {
                if let Some(obj) = dps.as_object() {
                    for (k, v) in obj {
                        state.insert(k.clone(), v.clone());
                    }
                }
                let converted = Self::dps_to_state(
                    &serde_json::Value::Object(state.clone()), dev_type,
                );
                let payload = serde_json::to_string(&converted).unwrap();
                eprintln!("Initial: {payload}");
                if let Some(ref client) = mqtt_client {
                    client
                        .publish(&state_topic, QoS::AtLeastOnce, false, payload.clone())
                        .ok();
                }
                if let Some(ref mut logger) = self.logger {
                    if let Err(e) = logger.log_state(&converted) {
                        eprintln!("Log error: {e}");
                    }
                }
            }

            // Short read timeout so heartbeats are sent frequently enough
            // (CT devices drop the connection after ~15s idle)
            let recv_timeout = std::cmp::min(poll_secs, 5);
            dev.stream
                .set_read_timeout(Some(Duration::from_secs(recv_timeout)))
                .ok();

            // Send first heartbeat immediately to trigger dp 6 streaming
            if let Err(e) = dev.send_heartbeat() {
                eprintln!("Initial heartbeat failed: {e}");
                continue;
            }

            let mut last_heartbeat = SystemTime::now();
            let mut last_publish = SystemTime::now();
            // Heartbeat every 7s to keep CT devices alive (they timeout at ~15s)
            let heartbeat_interval = Duration::from_secs(std::cmp::min(poll_secs, 7));
            let publish_interval = Duration::from_secs(poll_secs);

            // Main loop: receive STATUS pushes, send heartbeats, publish
            loop {
                // Handle switch commands from MQTT
                while let Ok(on) = switch_rx.try_recv() {
                    eprintln!("Switch command: {}", if on { "ON" } else { "OFF" });
                    if let Err(e) = dev.set_dp("1", serde_json::json!(on)) {
                        eprintln!("Set switch failed: {e}");
                    }
                }

                // Receive device data
                match dev.recv_one() {
                    Ok(Some(dps)) => {
                        if let Some(obj) = dps.as_object() {
                            for (k, v) in obj {
                                state.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    Ok(None) => {} // timeout, no data
                    Err(e) => {
                        eprintln!("Connection lost: {e}");
                        if let Some(ref client) = mqtt_client {
                            client
                                .publish(&avail_topic, QoS::AtLeastOnce, true, "offline")
                                .ok();
                        }
                        break; // reconnect
                    }
                }

                // Send heartbeat periodically
                let now = SystemTime::now();
                if now.duration_since(last_heartbeat).unwrap_or_default() >= heartbeat_interval {
                    if let Err(e) = dev.send_heartbeat() {
                        eprintln!("Heartbeat failed: {e}");
                        break; // reconnect
                    }
                    last_heartbeat = now;
                }

                // Publish state periodically
                if now.duration_since(last_publish).unwrap_or_default() >= publish_interval {
                    if !state.is_empty() {
                        let converted = Self::dps_to_state(
                            &serde_json::Value::Object(state.clone()), dev_type,
                        );
                        let payload = serde_json::to_string(&converted).unwrap();
                        eprintln!("Publish: {payload}");
                        if let Some(ref client) = mqtt_client {
                            client
                                .publish(&state_topic, QoS::AtLeastOnce, false, payload.clone())
                                .ok();
                        }
                        if let Some(ref mut logger) = self.logger {
                            if let Err(e) = logger.log_state(&converted) {
                                eprintln!("Log error: {e}");
                            }
                        }
                    }
                    last_publish = now;
                }
            }

            // Wait before reconnecting
            std::thread::sleep(Duration::from_secs(5));
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let config_path = args.get(1).map(|s| s.as_str()).unwrap_or("config.yaml");
    let command = args.get(2).map(|s| s.as_str()).unwrap_or("status");

    let mut cfg = match load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Usage: tuya-meter [config.yaml] [command]");
            eprintln!("  command: status (default), json, on, off, server");
            std::process::exit(1);
        }
    };

    let version = parse_version(&cfg.device.version);
    let poll_secs = cfg.poll_secs.unwrap_or(10);
    let auto_ip = cfg.device.ip.eq_ignore_ascii_case("auto");

    if auto_ip {
        match discover_device_ip(
            &cfg.device.id,
            cfg.device.mac.as_deref(),
            cfg.bcast_addr.as_deref(),
            AUTO_IP_DISCOVERY_TIMEOUT_SECS,
        ) {
            Ok(ip) => {
                eprintln!("Resolved {} -> {ip}", cfg.device.id);
                cfg.device.ip = ip;
            }
            Err(e) => {
                eprintln!("Auto IP discovery failed: {e}");
                std::process::exit(1);
            }
        }
    }

    if command == "server" || command == "mqtt" {
        if cfg.mqtt.is_none() && cfg.log.is_none() {
            eprintln!("Error: server mode requires 'mqtt' and/or 'log' section in config");
            std::process::exit(1);
        }

        // Set up logger if configured
        let logger = match cfg.log {
            Some(ref log_cfg) => match JsonlLogger::new(log_cfg) {
                Ok(l) => Some(l),
                Err(e) => {
                    eprintln!("Log init error: {e}");
                    std::process::exit(1);
                }
            },
            None => None,
        };

        // Probe device type if not configured
        let dev_type = cfg.device.device_type.unwrap_or_else(|| {
            eprintln!("Probing device type...");
            match TuyaDevice::connect(&cfg.device.ip, &cfg.device.id, &cfg.device.local_key, version) {
                Ok(mut d) => match d.query_dps() {
                    Ok(dps) => {
                        let t = detect_device_type(&dps);
                        eprintln!("Detected: {:?}", t);
                        t
                    }
                    Err(_) => DeviceType::At4pw,
                },
                Err(_) => DeviceType::At4pw,
            }
        });

        let mut server = Server {
            dev: cfg.device,
            mqtt: cfg.mqtt,
            logger,
            dev_type,
            poll_secs,
            auto_ip,
            bcast_addr: cfg.bcast_addr,
        };
        server.run();
        return;
    }

    let mut dev = match TuyaDevice::connect(&cfg.device.ip, &cfg.device.id, &cfg.device.local_key, version) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Connect failed: {e}");
            std::process::exit(1);
        }
    };

    match command {
        "status" => match dev.query_dps() {
            Ok(dps) => {
                let dev_type = cfg.device.device_type.unwrap_or_else(|| detect_device_type(&dps));
                print_meter(&dps, dev_type);
            }
            Err(e) => {
                eprintln!("Query failed: {e}");
                std::process::exit(1);
            }
        },
        "json" => match dev.query_dps() {
            Ok(dps) => println!("{}", serde_json::to_string_pretty(&dps).unwrap()),
            Err(e) => {
                eprintln!("Query failed: {e}");
                std::process::exit(1);
            }
        },
        "on" => {
            if let Err(e) = dev.set_dp("1", serde_json::json!(true)) {
                eprintln!("Failed: {e}");
                std::process::exit(1);
            }
            println!("Switch ON");
        }
        "off" => {
            if let Err(e) = dev.set_dp("1", serde_json::json!(false)) {
                eprintln!("Failed: {e}");
                std::process::exit(1);
            }
            println!("Switch OFF");
        }
        c => {
            eprintln!("Unknown command: {c}");
            std::process::exit(1);
        }
    }
}
