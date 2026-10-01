//! RADIUS Change-of-Authorization / Disconnect client (RFC 5176).
//!
//! `radius-rust` provides the dictionary, attribute and packet types. It has no async client and
//! does not compute the RFC 5176 request authenticator, so signing and UDP transport live here.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use radius_rust::{
    protocol::{
        dictionary::{Dictionary, SupportedAttributeTypes},
        radius_packet::{RadiusAttribute, RadiusPacket, TypeCode},
    },
    tools::{integer64_to_bytes, integer_to_bytes, ipv4_string_to_bytes, ipv6_string_to_bytes},
};
use serde::{Deserialize, Serialize};
use tokio::net::{lookup_host, UdpSocket};

use crate::config::RadiusConfig;

pub const EMBEDDED_DICTIONARY: &str = include_str!("../dictionary/dictionary");

const HEADER_LEN: usize = 20;
const MAX_PACKET_LEN: usize = 4096;
const MAX_ATTR_VALUE_LEN: usize = 253;
pub const ATTR_VENDOR_SPECIFIC: u8 = 26;
pub const ATTR_MESSAGE_AUTHENTICATOR: u8 = 80;
pub const ATTR_ERROR_CAUSE: u8 = 101;

type HmacMd5 = Hmac<Md5>;

// ---------------------------------------------------------------------------------------------
// Activity input / output (mirrored in types/radius-coa.d.ts)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoaKind {
    /// CoA-Request (code 43)
    #[default]
    Coa,
    /// Disconnect-Request (code 40)
    Disconnect,
}

/// An attribute value: numbers for integer/enum/time attributes, strings for everything else.
/// Strings for integer attributes may also be a dictionary `VALUE` name (e.g. `"Framed-User"`).
/// Strings prefixed with `0x` are sent as raw octets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    Number(u64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attribute {
    pub name: String,
    pub value: AttributeValue,
}

/// A Vendor-Specific attribute (type 26) in the RFC 2865 recommended format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VendorAttribute {
    pub vendor_id: u32,
    pub vendor_type: u8,
    pub value: AttributeValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoaRequest {
    /// NAS hostname or IP address.
    pub nas_address: String,
    /// Defaults to `RADIUS_COA_PORT` (3799).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nas_port: Option<u16>,
    #[serde(default)]
    pub kind: CoaKind,
    #[serde(default)]
    pub attributes: Vec<Attribute>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vendor_attributes: Vec<VendorAttribute>,
    /// Per-attempt timeout; defaults to `RADIUS_TIMEOUT_MS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Retransmissions after the first attempt; defaults to `RADIUS_RETRIES`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplyCode {
    #[serde(rename = "CoA-ACK")]
    CoaAck,
    #[serde(rename = "CoA-NAK")]
    CoaNak,
    #[serde(rename = "Disconnect-ACK")]
    DisconnectAck,
    #[serde(rename = "Disconnect-NAK")]
    DisconnectNak,
}

impl ReplyCode {
    fn from_u8(code: u8) -> Option<Self> {
        match code {
            41 => Some(Self::DisconnectAck),
            42 => Some(Self::DisconnectNak),
            44 => Some(Self::CoaAck),
            45 => Some(Self::CoaNak),
            _ => None,
        }
    }

    fn is_ack(self) -> bool {
        matches!(self, Self::CoaAck | Self::DisconnectAck)
    }

    fn matches(self, kind: CoaKind) -> bool {
        match kind {
            CoaKind::Coa => matches!(self, Self::CoaAck | Self::CoaNak),
            CoaKind::Disconnect => matches!(self, Self::DisconnectAck | Self::DisconnectNak),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoaResult {
    pub code: ReplyCode,
    pub acked: bool,
    /// Error-Cause (RFC 5176 §3.5), usually present on a NAK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_cause: Option<u32>,
    pub attributes: Vec<Attribute>,
    /// Resolved NAS socket address the request was sent to.
    pub nas: String,
    /// Number of transmissions (1 = answered on the first try).
    pub attempts: u32,
    pub rtt_ms: u64,
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CoaError {
    /// The request can never succeed as given (bad attribute, unresolvable input, ...).
    #[error("invalid CoA request: {0}")]
    Invalid(String),
    /// The NAS answered, but the reply failed authentication — almost always a secret mismatch.
    #[error("reply from {nas} failed verification: {reason}")]
    BadReply { nas: String, reason: String },
    /// No valid reply within timeout × (retries + 1).
    #[error("no reply from {nas} after {attempts} attempt(s)")]
    Timeout { nas: String, attempts: u32 },
    #[error("network error talking to {nas}: {source}")]
    Io {
        nas: String,
        #[source]
        source: std::io::Error,
    },
}

impl CoaError {
    /// Whether Temporal should retry the activity.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Timeout { .. } | Self::Io { .. })
    }
}

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

pub struct CoaClient {
    dict: Arc<Dictionary>,
    cfg: RadiusConfig,
}

impl CoaClient {
    pub fn new(cfg: RadiusConfig) -> anyhow::Result<Self> {
        Ok(Self { dict: Arc::new(load_dictionary(cfg.dictionary_path.as_deref())?), cfg })
    }

    pub async fn send(&self, req: &CoaRequest) -> Result<CoaResult, CoaError> {
        let port = req.nas_port.unwrap_or(self.cfg.default_port);
        let nas = resolve(&req.nas_address, port).await?;
        let nas_str = nas.to_string();

        let mut packet = build_request(&self.dict, req)?;
        let wire = sign_request(&mut packet, &self.cfg.secret);
        let req_auth: [u8; 16] = wire[4..20].try_into().expect("16-byte authenticator");

        let bind: SocketAddr = if nas.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
        let io_err = |source| CoaError::Io { nas: nas_str.clone(), source };
        let socket = UdpSocket::bind(bind).await.map_err(io_err)?;
        socket.connect(nas).await.map_err(io_err)?;

        let timeout = req.timeout_ms.map(Duration::from_millis).unwrap_or(self.cfg.timeout);
        let max_attempts = req.retries.unwrap_or(self.cfg.retries) + 1;
        let started = Instant::now();
        let mut buf = vec![0u8; MAX_PACKET_LEN];

        for attempt in 1..=max_attempts {
            tracing::debug!(nas = %nas_str, id = packet.id(), attempt, "sending {:?} request", req.kind);
            socket.send(&wire).await.map_err(io_err)?;

            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let n = match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                    Err(_) => break, // attempt timed out → retransmit
                    // ICMP port-unreachable surfaces as ConnectionRefused on a connected socket;
                    // treat like a lost packet so retries still apply.
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        tokio::time::sleep_until(deadline).await;
                        break;
                    }
                    Ok(Err(e)) => return Err(io_err(e)),
                    Ok(Ok(n)) => n,
                };
                let reply = &buf[..n];
                if reply.len() < HEADER_LEN || reply[1] != packet.id() {
                    tracing::debug!(nas = %nas_str, len = n, "ignoring stray datagram");
                    continue;
                }
                let bad = |reason: String| CoaError::BadReply { nas: nas_str.clone(), reason };
                verify_response(reply, &req_auth, &self.cfg.secret).map_err(bad)?;
                let code = ReplyCode::from_u8(reply[0])
                    .filter(|c| c.matches(req.kind))
                    .ok_or_else(|| bad(format!("unexpected reply code {}", reply[0])))?;
                let attributes = decode_attributes(&self.dict, reply).map_err(bad)?;
                let error_cause =
                    attributes.iter().find(|a| a.name == "Error-Cause").and_then(|a| match a.value {
                        AttributeValue::Number(n) => u32::try_from(n).ok(),
                        AttributeValue::Text(_) => None,
                    });
                return Ok(CoaResult {
                    code,
                    acked: code.is_ack(),
                    error_cause,
                    attributes,
                    nas: nas_str,
                    attempts: attempt,
                    rtt_ms: started.elapsed().as_millis() as u64,
                });
            }
        }
        Err(CoaError::Timeout { nas: nas_str, attempts: max_attempts })
    }
}

pub fn load_dictionary(path: Option<&str>) -> anyhow::Result<Dictionary> {
    let dict = match path {
        Some(p) => Dictionary::from_file(p),
        None => Dictionary::from_str(EMBEDDED_DICTIONARY),
    };
    dict.map_err(|e| anyhow::anyhow!("failed to load RADIUS dictionary: {e}"))
}

async fn resolve(host: &str, port: u16) -> Result<SocketAddr, CoaError> {
    if host.is_empty() {
        return Err(CoaError::Invalid("nasAddress is empty".into()));
    }
    let target = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => return Ok(SocketAddr::new(ip, port)),
        Err(_) => format!("{host}:{port}"),
    };
    let addrs = lookup_host(&target).await.map_err(|e| CoaError::Io { nas: target.clone(), source: e })?;
    // Prefer IPv4 to match the common NAS deployment; fall back to whatever resolved.
    let addrs: Vec<_> = addrs.collect();
    addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).copied().ok_or_else(|| CoaError::Io {
        nas: target,
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved"),
    })
}

// ---------------------------------------------------------------------------------------------
// Packet building / signing / verification
// ---------------------------------------------------------------------------------------------

pub fn build_request(dict: &Dictionary, req: &CoaRequest) -> Result<RadiusPacket, CoaError> {
    let code = match req.kind {
        CoaKind::Coa => TypeCode::CoARequest,
        CoaKind::Disconnect => TypeCode::DisconnectRequest,
    };
    let mut attrs = Vec::with_capacity(req.attributes.len() + req.vendor_attributes.len() + 1);
    for a in &req.attributes {
        if a.name == "Message-Authenticator" {
            continue; // always generated below
        }
        attrs.push(encode_attribute(dict, a)?);
    }
    for v in &req.vendor_attributes {
        attrs.push(encode_vendor_attribute(dict, v)?);
    }
    if attrs.is_empty() {
        return Err(CoaError::Invalid(
            "at least one session identification attribute is required (RFC 5176 §3)".into(),
        ));
    }
    // RFC 5176 §3.3 permits Message-Authenticator; many NASes now require it.
    attrs.push(
        RadiusAttribute::create_by_id(dict, ATTR_MESSAGE_AUTHENTICATOR, vec![0; 16])
            .ok_or_else(|| CoaError::Invalid("dictionary lacks Message-Authenticator".into()))?,
    );
    let mut packet = RadiusPacket::initialise_packet(code);
    packet.set_attributes(attrs);
    let len = HEADER_LEN + packet.attributes().iter().map(|a| a.value().len() + 2).sum::<usize>();
    if len > MAX_PACKET_LEN {
        return Err(CoaError::Invalid(format!("packet would be {len} bytes (max {MAX_PACKET_LEN})")));
    }
    Ok(packet)
}

/// Fills in Message-Authenticator and the RFC 5176 Request Authenticator, returning wire bytes.
///
/// Both are computed with the authenticator field zeroed:
/// `Request Authenticator = MD5(Code | Id | Length | 16×0 | Attributes | Secret)`.
pub fn sign_request(packet: &mut RadiusPacket, secret: &str) -> Vec<u8> {
    packet.override_authenticator(vec![0; 16]);
    if packet.attribute_by_id(ATTR_MESSAGE_AUTHENTICATOR).is_some() {
        packet.generate_message_authenticator(secret).expect("Message-Authenticator attribute present");
    }
    let mut wire = packet.to_bytes();
    let auth = md5_of(&[&wire, secret.as_bytes()]);
    wire[4..20].copy_from_slice(&auth);
    packet.override_authenticator(auth.to_vec());
    wire
}

/// Verifies an incoming CoA/Disconnect *request* (used by the test responder).
pub fn verify_request(packet: &[u8], secret: &str) -> Result<(), String> {
    check_length(packet)?;
    let mut zeroed = packet.to_vec();
    zeroed[4..20].fill(0);
    if md5_of(&[&zeroed, secret.as_bytes()]) != packet[4..20] {
        return Err("Request Authenticator mismatch".into());
    }
    verify_message_authenticator(&zeroed, secret)
}

/// Verifies a CoA/Disconnect *response* against the request's authenticator.
pub fn verify_response(reply: &[u8], request_auth: &[u8; 16], secret: &str) -> Result<(), String> {
    check_length(reply)?;
    let expected = md5_of(&[&reply[0..4], request_auth, &reply[HEADER_LEN..], secret.as_bytes()]);
    if expected != reply[4..20] {
        return Err("Response Authenticator mismatch (wrong RADIUS secret?)".into());
    }
    let mut with_req_auth = reply.to_vec();
    with_req_auth[4..20].copy_from_slice(request_auth);
    verify_message_authenticator(&with_req_auth, secret)
}

/// Builds and signs a response to `request` (used by the test responder).
pub fn sign_response(code: u8, request: &[u8], attrs: &[(u8, Vec<u8>)], secret: &str) -> Vec<u8> {
    let mut wire = Vec::with_capacity(HEADER_LEN + 32);
    wire.push(code);
    wire.push(request[1]);
    wire.extend_from_slice(&[0, 0]);
    wire.extend_from_slice(&request[4..20]);
    for (id, value) in attrs {
        wire.push(*id);
        wire.push((value.len() + 2) as u8);
        wire.extend_from_slice(value);
    }
    let len = wire.len() as u16;
    wire[2..4].copy_from_slice(&len.to_be_bytes());
    let auth = md5_of(&[&wire, secret.as_bytes()]);
    wire[4..20].copy_from_slice(&auth);
    wire
}

/// If a Message-Authenticator is present, checks HMAC-MD5 over `packet` (authenticator field as
/// the caller prepared it) with the attribute value zeroed.
fn verify_message_authenticator(packet: &[u8], secret: &str) -> Result<(), String> {
    let Some((offset, len)) = find_attribute(packet, ATTR_MESSAGE_AUTHENTICATOR)? else {
        return Ok(());
    };
    if len != 16 {
        return Err("Message-Authenticator has invalid length".into());
    }
    let received = packet[offset..offset + 16].to_vec();
    let mut zeroed = packet.to_vec();
    zeroed[offset..offset + 16].fill(0);
    let mut mac = HmacMd5::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(&zeroed);
    mac.verify_slice(&received).map_err(|_| "Message-Authenticator mismatch".to_string())
}

fn check_length(packet: &[u8]) -> Result<(), String> {
    if packet.len() < HEADER_LEN {
        return Err(format!("packet too short ({} bytes)", packet.len()));
    }
    let declared = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if declared != packet.len() {
        return Err(format!("length field {declared} != datagram size {}", packet.len()));
    }
    Ok(())
}

/// Returns `(value_offset, value_len)` of the first attribute with `id`.
fn find_attribute(packet: &[u8], id: u8) -> Result<Option<(usize, usize)>, String> {
    let mut i = HEADER_LEN;
    while i < packet.len() {
        let (aid, alen) = parse_attr_header(packet, i)?;
        if aid == id {
            return Ok(Some((i + 2, alen - 2)));
        }
        i += alen;
    }
    Ok(None)
}

fn parse_attr_header(packet: &[u8], i: usize) -> Result<(u8, usize), String> {
    if i + 2 > packet.len() {
        return Err("truncated attribute header".into());
    }
    let len = packet[i + 1] as usize;
    if len < 2 || i + len > packet.len() {
        return Err(format!("attribute {} has invalid length {len}", packet[i]));
    }
    Ok((packet[i], len))
}

fn md5_of(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ---------------------------------------------------------------------------------------------
// Attribute encoding / decoding
// ---------------------------------------------------------------------------------------------

fn encode_attribute(dict: &Dictionary, a: &Attribute) -> Result<RadiusAttribute, CoaError> {
    let def = dict
        .attributes()
        .iter()
        .find(|d| d.name() == a.name)
        .ok_or_else(|| CoaError::Invalid(format!("unknown attribute {:?}", a.name)))?;
    let bytes = encode_value(dict, &a.name, def.code_type(), &a.value)
        .map_err(|e| CoaError::Invalid(format!("attribute {:?}: {e}", a.name)))?;
    check_value_len(&a.name, &bytes)?;
    Ok(RadiusAttribute::create_by_id(dict, def.code(), bytes).expect("attribute exists"))
}

fn encode_vendor_attribute(dict: &Dictionary, v: &VendorAttribute) -> Result<RadiusAttribute, CoaError> {
    let label = format!("vendor {} type {}", v.vendor_id, v.vendor_type);
    let data = match &v.value {
        AttributeValue::Number(n) => integer_to_bytes(
            u32::try_from(*n).map_err(|_| CoaError::Invalid(format!("{label}: integer out of range")))?,
        ),
        AttributeValue::Text(s) => text_or_hex(s).map_err(|e| CoaError::Invalid(format!("{label}: {e}")))?,
    };
    // Vendor-Id(4) | Vendor-Type(1) | Vendor-Length(1) | data
    let mut value = Vec::with_capacity(6 + data.len());
    value.extend_from_slice(&v.vendor_id.to_be_bytes());
    value.push(v.vendor_type);
    value.push(
        u8::try_from(data.len() + 2).map_err(|_| CoaError::Invalid(format!("{label}: value too long")))?,
    );
    value.extend_from_slice(&data);
    check_value_len(&label, &value)?;
    RadiusAttribute::create_by_id(dict, ATTR_VENDOR_SPECIFIC, value)
        .ok_or_else(|| CoaError::Invalid("dictionary lacks Vendor-Specific".into()))
}

fn check_value_len(label: &str, bytes: &[u8]) -> Result<(), CoaError> {
    if bytes.len() > MAX_ATTR_VALUE_LEN {
        return Err(CoaError::Invalid(format!(
            "{label}: value is {} bytes (max {MAX_ATTR_VALUE_LEN})",
            bytes.len()
        )));
    }
    Ok(())
}

fn encode_value(
    dict: &Dictionary,
    name: &str,
    ty: &Option<SupportedAttributeTypes>,
    value: &AttributeValue,
) -> Result<Vec<u8>, String> {
    use SupportedAttributeTypes as T;
    match (ty, value) {
        (Some(T::Integer | T::Enum | T::Date), AttributeValue::Number(n)) => {
            Ok(integer_to_bytes(u32::try_from(*n).map_err(|_| "integer out of range")?))
        }
        (Some(T::Integer | T::Enum | T::Date), AttributeValue::Text(s)) => {
            let n = match s.parse::<u32>() {
                Ok(n) => n,
                Err(_) => dict
                    .values()
                    .iter()
                    .find(|v| v.attribute_name() == name && v.name() == s)
                    .and_then(|v| v.value().parse::<u32>().ok())
                    .ok_or_else(|| format!("{s:?} is not a number or known VALUE"))?,
            };
            Ok(integer_to_bytes(n))
        }
        (Some(T::Integer64), AttributeValue::Number(n)) => Ok(integer64_to_bytes(*n)),
        (Some(T::Integer64), AttributeValue::Text(s)) => {
            Ok(integer64_to_bytes(s.parse().map_err(|_| format!("{s:?} is not a number"))?))
        }
        (Some(T::IPv4Addr), AttributeValue::Text(s)) => ipv4_string_to_bytes(s).map_err(|e| e.to_string()),
        (Some(T::IPv6Addr | T::IPv6Prefix), AttributeValue::Text(s)) => {
            ipv6_string_to_bytes(s).map_err(|e| e.to_string())
        }
        (Some(T::InterfaceId), AttributeValue::Text(s)) => {
            radius_rust::tools::interfaceid_string_to_bytes(s).map_err(|e| e.to_string())
        }
        (_, AttributeValue::Text(s)) => text_or_hex(s),
        (_, AttributeValue::Number(_)) => Err("expected a string value".into()),
    }
}

/// `"0x..."` → raw octets, anything else → UTF-8 bytes.
fn text_or_hex(s: &str) -> Result<Vec<u8>, String> {
    match s.strip_prefix("0x") {
        Some(hex) if hex.len() % 2 == 0 => (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| format!("invalid hex {s:?}")))
            .collect(),
        Some(_) => Err(format!("invalid hex {s:?}")),
        None => Ok(s.as_bytes().to_vec()),
    }
}

/// Leniently decodes reply attributes: unknown attributes become `Attr-<id>` with hex values.
pub fn decode_attributes(dict: &Dictionary, packet: &[u8]) -> Result<Vec<Attribute>, String> {
    use SupportedAttributeTypes as T;
    let mut out = Vec::new();
    let mut i = HEADER_LEN;
    while i < packet.len() {
        let (id, len) = parse_attr_header(packet, i)?;
        let raw = &packet[i + 2..i + len];
        i += len;
        if id == ATTR_MESSAGE_AUTHENTICATOR {
            continue;
        }
        let def = dict.attributes().iter().find(|d| d.code() == id);
        let name = def.map_or_else(|| format!("Attr-{id}"), |d| d.name().to_string());
        let value = match def.and_then(|d| d.code_type().as_ref()) {
            Some(T::Integer | T::Enum | T::Date) if raw.len() == 4 => {
                AttributeValue::Number(u32::from_be_bytes(raw.try_into().unwrap()) as u64)
            }
            Some(T::Integer64) if raw.len() == 8 => {
                AttributeValue::Number(u64::from_be_bytes(raw.try_into().unwrap()))
            }
            Some(T::IPv4Addr) if raw.len() == 4 => {
                AttributeValue::Text(std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string())
            }
            Some(T::AsciiString | T::ByteString) if is_printable(raw) => {
                AttributeValue::Text(String::from_utf8_lossy(raw).into_owned())
            }
            _ => AttributeValue::Text(to_hex(raw)),
        };
        out.push(Attribute { name, value });
    }
    Ok(out)
}

fn is_printable(b: &[u8]) -> bool {
    std::str::from_utf8(b).is_ok_and(|s| !s.chars().any(|c| c.is_control()))
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "testing123";

    fn dict() -> Dictionary {
        load_dictionary(None).unwrap()
    }

    fn req(attrs: &[(&str, AttributeValue)]) -> CoaRequest {
        CoaRequest {
            nas_address: "127.0.0.1".into(),
            nas_port: None,
            kind: CoaKind::Coa,
            attributes: attrs
                .iter()
                .map(|(n, v)| Attribute { name: n.to_string(), value: v.clone() })
                .collect(),
            vendor_attributes: vec![],
            timeout_ms: None,
            retries: None,
        }
    }

    fn text(s: &str) -> AttributeValue {
        AttributeValue::Text(s.into())
    }

    #[test]
    fn deserializes_typescript_shaped_input() {
        let r: CoaRequest = serde_json::from_str(
            r#"{"nasAddress":"10.0.0.1","kind":"disconnect","attributes":[
                {"name":"User-Name","value":"alice"},{"name":"Session-Timeout","value":3600}],
                "vendorAttributes":[{"vendorId":9,"vendorType":1,"value":"subscriber:command=reauthenticate"}]}"#,
        )
        .unwrap();
        assert_eq!(r.kind, CoaKind::Disconnect);
        assert_eq!(r.attributes[1].value, AttributeValue::Number(3600));
        assert_eq!(r.vendor_attributes[0].vendor_id, 9);
    }

    #[test]
    fn serializes_result_with_wire_names() {
        let r = CoaResult {
            code: ReplyCode::CoaNak,
            acked: false,
            error_cause: Some(503),
            attributes: vec![],
            nas: "1.2.3.4:3799".into(),
            attempts: 1,
            rtt_ms: 2,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["code"], "CoA-NAK");
        assert_eq!(v["errorCause"], 503);
        assert_eq!(v["rttMs"], 2);
    }

    #[test]
    fn encodes_typed_attributes() {
        let d = dict();
        let p = build_request(
            &d,
            &req(&[
                ("User-Name", text("alice")),
                ("Session-Timeout", AttributeValue::Number(3600)),
                ("Service-Type", text("Framed-User")),
                ("Framed-IP-Address", text("10.1.2.3")),
                ("Class", text("0xdeadbeef")),
            ]),
        )
        .unwrap();
        let get = |n: &str| p.attribute_by_name(n).unwrap().value().to_vec();
        assert_eq!(get("User-Name"), b"alice");
        assert_eq!(get("Session-Timeout"), 3600u32.to_be_bytes());
        assert_eq!(get("Service-Type"), 2u32.to_be_bytes());
        assert_eq!(get("Framed-IP-Address"), [10, 1, 2, 3]);
        assert_eq!(get("Class"), [0xde, 0xad, 0xbe, 0xef]);
        assert!(p.attribute_by_id(ATTR_MESSAGE_AUTHENTICATOR).is_some());
    }

    #[test]
    fn encodes_vendor_specific() {
        let d = dict();
        let mut r = req(&[]);
        r.vendor_attributes.push(VendorAttribute { vendor_id: 9, vendor_type: 1, value: text("a=b") });
        let p = build_request(&d, &r).unwrap();
        let vsa = p.attribute_by_id(ATTR_VENDOR_SPECIFIC).unwrap().value();
        assert_eq!(vsa, [0, 0, 0, 9, 1, 5, b'a', b'=', b'b']);
    }

    #[test]
    fn rejects_bad_input() {
        let d = dict();
        assert!(matches!(build_request(&d, &req(&[])), Err(CoaError::Invalid(_))));
        assert!(matches!(build_request(&d, &req(&[("Nope", text("x"))])), Err(CoaError::Invalid(_))));
        assert!(matches!(
            build_request(&d, &req(&[("Session-Timeout", text("forever"))])),
            Err(CoaError::Invalid(_))
        ));
        assert!(matches!(
            build_request(&d, &req(&[("User-Name", text(&"x".repeat(254)))])),
            Err(CoaError::Invalid(_))
        ));
    }

    #[test]
    fn request_authenticator_follows_rfc5176() {
        let d = dict();
        let mut p = build_request(&d, &req(&[("User-Name", text("alice"))])).unwrap();
        let wire = sign_request(&mut p, SECRET);
        assert_eq!(wire[0], 43);
        let mut zeroed = wire.clone();
        zeroed[4..20].fill(0);
        assert_eq!(md5_of(&[&zeroed, SECRET.as_bytes()]), wire[4..20]);
        verify_request(&wire, SECRET).unwrap();
        assert!(verify_request(&wire, "wrong").is_err());

        let mut tampered = wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_request(&tampered, SECRET).is_err());
    }

    #[test]
    fn response_round_trip() {
        let d = dict();
        let mut p = build_request(&d, &req(&[("User-Name", text("alice"))])).unwrap();
        let wire = sign_request(&mut p, SECRET);
        let auth: [u8; 16] = wire[4..20].try_into().unwrap();
        let reply = sign_response(45, &wire, &[(ATTR_ERROR_CAUSE, 503u32.to_be_bytes().to_vec())], SECRET);
        verify_response(&reply, &auth, SECRET).unwrap();
        assert!(verify_response(&reply, &auth, "wrong").is_err());
        let attrs = decode_attributes(&d, &reply).unwrap();
        assert_eq!(attrs, vec![Attribute { name: "Error-Cause".into(), value: AttributeValue::Number(503) }]);
    }

    #[test]
    fn decodes_unknown_attributes_leniently() {
        let d = dict();
        let mut pkt = vec![44, 1, 0, 0];
        pkt.extend([0; 16]);
        pkt.extend([250, 4, 0xab, 0xcd]);
        let len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&len.to_be_bytes());
        let attrs = decode_attributes(&d, &pkt).unwrap();
        assert_eq!(attrs[0], Attribute { name: "Attr-250".into(), value: text("0xabcd") });
    }
}
