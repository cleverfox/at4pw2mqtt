use aes::Aes128;
use aes_gcm::{aead::KeyInit as GcmKeyInit, AeadInPlace, Aes128Gcm, Nonce as GcmNonce};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use crc32fast::Hasher as Crc32Hasher;
use hmac::{Hmac, Mac};
use rumqttc::{Client, MqttOptions, QoS};
use sha2::Sha256;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

// All known DPs for AT4P-W
const ALL_DPS: &[u32] = &[
    1, 9, 17, 18, 19, 20, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
    111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
    126, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
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
}

#[derive(Debug, serde::Deserialize)]
struct DeviceConfig {
    ip: String,
    id: String,
    local_key: String,
    #[serde(default = "default_version")]
    version: String,
}

fn default_version() -> String {
    "3.5".to_string()
}

#[derive(Debug, serde::Deserialize)]
struct MqttConfig {
    host: String,
    #[serde(default = "default_mqtt_port")]
    port: u16,
    #[serde(default = "default_poll_secs")]
    poll_secs: u64,
    #[serde(default = "default_node_id")]
    node_id: String,
}

fn default_mqtt_port() -> u16 {
    1883
}
fn default_poll_secs() -> u64 {
    10
}
fn default_node_id() -> String {
    "at4pw".to_string()
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

        // Strip retcode if present
        let payload = if !buffer.is_empty() && buffer[0] != b'{' && buffer.len() > 4 {
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
        let json_str = String::from_utf8(data.to_vec()).map_err(|e| format!("utf8: {e}"))?;
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

        // Collect responses — device may send multiple STATUS messages
        let mut merged = serde_json::Map::new();

        // Set shorter timeout for collecting burst responses
        self.stream.set_read_timeout(Some(Duration::from_secs(3))).ok();

        // Read all available responses
        loop {
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
        let mut dps = Self::parse_dps_response(&resp)?;

        // Now request ALL DPs via UPDATEDPS and merge
        if let Ok(all) = self.request_all_dps() {
            if let (Some(base), Some(extra)) = (dps.as_object_mut(), all.as_object()) {
                for (k, v) in extra {
                    base.insert(k.clone(), v.clone());
                }
            }
        }

        Ok(dps)
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

fn print_meter(dps: &serde_json::Value) {
    let get = |k: &str| dps.get(k).and_then(|v| v.as_f64());

    println!("=== AT4P-W Power Meter ===");
    if let Some(v) = get("20") {
        println!("  Voltage:        {:.1} V", v / 100.0);
    }
    if let Some(v) = get("18") {
        println!("  Current:        {:.3} A", v / 1000.0);
    }
    if let Some(v) = get("19") {
        println!("  Power:          {:.1} W", v / 10.0);
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
        println!("  Cost:           {:.2}", v as f64 / 100.0);
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

// ── MQTT bridge with Home Assistant discovery ──

struct MqttBridge {
    dev: DeviceConfig,
    mqtt: MqttConfig,
}

impl MqttBridge {
    fn ha_discovery_configs(&self) -> Vec<(String, serde_json::Value)> {
        let node_id = &self.mqtt.node_id;
        let device = serde_json::json!({
            "identifiers": [node_id],
            "name": "AT4P-W Power Meter",
            "model": "AT4P-W",
            "manufacturer": "Tuya"
        });
        let state_topic = format!("home/{}/state", node_id);
        let avail_topic = format!("home/{}/availability", node_id);

        let sensors: Vec<(&str, &str, &str, &str, Option<&str>)> = vec![
            // (object_id, name, device_class, unit, value_template_field)
            ("voltage",        "Voltage",        "voltage",      "V",    Some("voltage")),
            ("current",        "Current",        "current",      "A",    Some("current")),
            ("power",          "Power",          "power",        "W",    Some("power")),
            ("energy",         "Total Energy",   "energy",       "kWh",  Some("energy")),
            ("session_energy", "Session Energy", "energy",       "kWh",  Some("session_energy")),
            ("frequency",      "Frequency",      "frequency",    "Hz",   Some("frequency")),
            ("power_factor",   "Power Factor",   "power_factor", "",     Some("power_factor")),
            ("cost",           "Cost",           "monetary",     "",     Some("cost")),
            ("temperature",    "CPU Temp",       "temperature",  "°C",   Some("temperature")),
            ("leakage",        "Leakage Current","current",      "mA",   Some("leakage_ma")),
        ];

        let mut configs = Vec::new();

        for (obj_id, name, dev_class, unit, field) in &sensors {
            let topic = format!("homeassistant/sensor/{}/{}/config", node_id, obj_id);
            let mut config = serde_json::json!({
                "name": name,
                "device_class": dev_class,
                "state_topic": &state_topic,
                "availability_topic": &avail_topic,
                "unique_id": format!("{}_{}", node_id, obj_id),
                "device": &device,
                "value_template": format!("{{{{ value_json.{} }}}}", field.unwrap()),
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

        // Switch (binary sensor for status display)
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

        configs
    }

    fn dps_to_state(dps: &serde_json::Value) -> serde_json::Value {
        let get = |k: &str| dps.get(k).and_then(|v| v.as_f64());
        let mut state = serde_json::Map::new();

        if let Some(v) = get("20") {
            state.insert("voltage".into(), serde_json::json!(format!("{:.1}", v / 100.0)));
        }
        if let Some(v) = get("18") {
            state.insert("current".into(), serde_json::json!(format!("{:.3}", v / 1000.0)));
        }
        if let Some(v) = get("19") {
            state.insert("power".into(), serde_json::json!(format!("{:.1}", v / 10.0)));
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
            state.insert("cost".into(), serde_json::json!(format!("{:.2}", v as f64 / 100.0)));
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
        serde_json::Value::Object(state)
    }

    fn run(&self) {
        let mqtt_host = self.mqtt.host.trim_start_matches('[').trim_end_matches(']');
        let mut mqttopts = MqttOptions::new(
            format!("at4pw-{}", &self.mqtt.node_id),
            mqtt_host,
            self.mqtt.port,
        );
        mqttopts.set_keep_alive(Duration::from_secs(30));

        let avail_topic = format!("home/{}/availability", self.mqtt.node_id);
        mqttopts.set_last_will(rumqttc::LastWill::new(
            &avail_topic,
            "offline",
            QoS::AtLeastOnce,
            true,
        ));

        let (client, mut connection) = Client::new(mqttopts, 32);
        let cmd_topic = format!("home/{}/switch/set", self.mqtt.node_id);
        let state_topic = format!("home/{}/state", self.mqtt.node_id);

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

        // Subscribe to switch commands
        client.subscribe(&cmd_topic, QoS::AtLeastOnce).ok();

        // Spawn MQTT event loop in background
        let ip = self.dev.ip.clone();
        let dev_id = self.dev.id.clone();
        let local_key = self.dev.local_key.clone();
        let version = parse_version(&self.dev.version);

        let cmd_topic_clone = cmd_topic.clone();
        let client_clone = client.clone();
        std::thread::spawn(move || {
            for notification in connection.iter() {
                if let Ok(rumqttc::Event::Incoming(rumqttc::Packet::Publish(msg))) = notification {
                    if msg.topic == cmd_topic_clone {
                        let payload = String::from_utf8_lossy(&msg.payload);
                        let val = match payload.as_ref() {
                            "ON" => Some(true),
                            "OFF" => Some(false),
                            _ => None,
                        };
                        if let Some(on) = val {
                            eprintln!("MQTT command: switch {}", if on { "ON" } else { "OFF" });
                            match TuyaDevice::connect(&ip, &dev_id, &local_key, version) {
                                Ok(mut dev) => {
                                    if let Err(e) = dev.set_dp("1", serde_json::json!(on)) {
                                        eprintln!("Set switch failed: {e}");
                                    }
                                }
                                Err(e) => eprintln!("Connect for switch: {e}"),
                            }
                        }
                    }
                }
            }
        });

        eprintln!(
            "MQTT bridge started: {}:{} -> poll every {}s",
            self.mqtt.host, self.mqtt.port, self.mqtt.poll_secs
        );

        let poll_version = parse_version(&self.dev.version);
        loop {
            match TuyaDevice::connect(&self.dev.ip, &self.dev.id, &self.dev.local_key, poll_version) {
                Ok(mut dev) => match dev.query_dps() {
                    Ok(dps) => {
                        let state = Self::dps_to_state(&dps);
                        let payload = serde_json::to_string(&state).unwrap();
                        eprintln!("Poll OK: {payload}");
                        client
                            .publish(&state_topic, QoS::AtLeastOnce, false, payload)
                            .ok();
                        client
                            .publish(&avail_topic, QoS::AtLeastOnce, true, "online")
                            .ok();
                    }
                    Err(e) => {
                        eprintln!("Query failed: {e}");
                        client_clone
                            .publish(&avail_topic, QoS::AtLeastOnce, true, "offline")
                            .ok();
                    }
                },
                Err(e) => {
                    eprintln!("Connect failed: {e}");
                    client_clone
                        .publish(&avail_topic, QoS::AtLeastOnce, true, "offline")
                        .ok();
                }
            }

            std::thread::sleep(Duration::from_secs(self.mqtt.poll_secs));
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
            eprintln!("  command: status (default), json, on, off, mqtt");
            std::process::exit(1);
        }
    };

    let version = parse_version(&cfg.device.version);

    if command == "mqtt" {
        let mqtt = cfg.mqtt.unwrap_or_else(|| {
            eprintln!("No 'mqtt' section in config");
            std::process::exit(1);
        });
        let bridge = MqttBridge {
            dev: cfg.device,
            mqtt,
        };
        bridge.run();
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
            Ok(dps) => print_meter(&dps),
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
