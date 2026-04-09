use aes::Aes128;
use aes_gcm::{aead::KeyInit as GcmKeyInit, AeadInPlace, Aes128Gcm, Nonce as GcmNonce};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use crc32fast::Hasher as Crc32Hasher;
use hmac::{Hmac, Mac};
use rumqttc::{Client, MqttOptions, QoS};
use sha2::Sha256;
use std::env;
use std::fs;
use std::io::{Read, Write, BufWriter, BufRead, BufReader};
use std::net::TcpStream;
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

// ── JSONL Logger with rotation ──

struct JsonlLogger {
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

        let path = PathBuf::from(&cfg.file);
        let mut logger = JsonlLogger {
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
        // Check time-based rotation
        if let Some(interval) = self.rotate_interval_secs {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH).unwrap().as_secs();
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

    let cfg = match load_config(config_path) {
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
