//! Minimal NAS-side CoA/Disconnect responder for testing.
//!
//! Verifies the Request Authenticator and Message-Authenticator with `RADIUS_SECRET`, then
//! replies ACK — or NAK with Error-Cause 503 (Session-Context-Not-Found) when User-Name starts
//! with `nak`. Requests that fail verification are dropped silently, as RFC 5176 §3.4 requires.

use std::sync::Arc;

use radius_rust::{protocol::dictionary::Dictionary, tools::integer_to_bytes};
use tokio::net::UdpSocket;

use crate::{
    coa::{self, AttributeValue, ATTR_ERROR_CAUSE},
    config::ResponderConfig,
};

const ERROR_CAUSE_SESSION_NOT_FOUND: u32 = 503;

pub async fn run(cfg: ResponderConfig) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(cfg.bind).await?;
    tracing::info!(bind = %socket.local_addr()?, "CoA responder listening");
    serve(socket, cfg.radius.secret, cfg.radius.dictionary_path.as_deref()).await
}

pub async fn serve(socket: UdpSocket, secret: String, dictionary_path: Option<&str>) -> anyhow::Result<()> {
    let dict = Arc::new(coa::load_dictionary(dictionary_path)?);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let pkt = &buf[..n];
        match respond(&dict, pkt, &secret) {
            Ok((reply, summary)) => {
                tracing::info!(%peer, id = pkt[1], "{summary}");
                if let Err(e) = socket.send_to(&reply, peer).await {
                    tracing::warn!(%peer, "send failed: {e}");
                }
            }
            Err(reason) => tracing::warn!(%peer, len = n, "dropping request: {reason}"),
        }
    }
}

fn respond(dict: &Dictionary, pkt: &[u8], secret: &str) -> Result<(Vec<u8>, String), String> {
    let (ack, nak, kind) = match pkt.first() {
        Some(43) => (44, 45, "CoA"),
        Some(40) => (41, 42, "Disconnect"),
        Some(c) => return Err(format!("unsupported code {c}")),
        None => return Err("empty datagram".into()),
    };
    coa::verify_request(pkt, secret)?;
    let attrs = coa::decode_attributes(dict, pkt)?;
    let user = attrs.iter().find(|a| a.name == "User-Name").and_then(|a| match &a.value {
        AttributeValue::Text(s) => Some(s.as_str()),
        AttributeValue::Number(_) => None,
    });
    let summary = format!("{kind}-Request attrs={attrs:?}");
    if user.is_some_and(|u| u.starts_with("nak")) {
        let cause = vec![(ATTR_ERROR_CAUSE, integer_to_bytes(ERROR_CAUSE_SESSION_NOT_FOUND))];
        Ok((coa::sign_response(nak, pkt, &cause, secret), format!("{summary} -> {kind}-NAK")))
    } else {
        Ok((coa::sign_response(ack, pkt, &[], secret), format!("{summary} -> {kind}-ACK")))
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use super::*;
    use crate::{
        coa::{Attribute, CoaClient, CoaError, CoaKind, CoaRequest, ReplyCode},
        config::RadiusConfig,
    };

    const SECRET: &str = "testing123";

    async fn spawn_responder(secret: &str) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let secret = secret.to_string();
        tokio::spawn(async move { serve(socket, secret, None).await });
        addr
    }

    fn client(secret: &str) -> CoaClient {
        CoaClient::new(RadiusConfig {
            secret: secret.into(),
            default_port: 3799,
            timeout: Duration::from_millis(200),
            retries: 1,
            dictionary_path: None,
        })
        .unwrap()
    }

    fn request(addr: SocketAddr, kind: CoaKind, user: &str) -> CoaRequest {
        CoaRequest {
            nas_address: addr.ip().to_string(),
            nas_port: Some(addr.port()),
            kind,
            attributes: vec![Attribute {
                name: "User-Name".into(),
                value: AttributeValue::Text(user.into()),
            }],
            vendor_attributes: vec![],
            timeout_ms: None,
            retries: None,
        }
    }

    #[tokio::test]
    async fn coa_ack() {
        let addr = spawn_responder(SECRET).await;
        let res = client(SECRET).send(&request(addr, CoaKind::Coa, "alice")).await.unwrap();
        assert_eq!(res.code, ReplyCode::CoaAck);
        assert!(res.acked);
        assert_eq!(res.attempts, 1);
    }

    #[tokio::test]
    async fn coa_nak_with_error_cause() {
        let addr = spawn_responder(SECRET).await;
        let res = client(SECRET).send(&request(addr, CoaKind::Coa, "nak-bob")).await.unwrap();
        assert_eq!(res.code, ReplyCode::CoaNak);
        assert!(!res.acked);
        assert_eq!(res.error_cause, Some(503));
    }

    #[tokio::test]
    async fn disconnect_ack() {
        let addr = spawn_responder(SECRET).await;
        let res = client(SECRET).send(&request(addr, CoaKind::Disconnect, "alice")).await.unwrap();
        assert_eq!(res.code, ReplyCode::DisconnectAck);
    }

    #[tokio::test]
    async fn wrong_secret_is_dropped_and_times_out() {
        // The responder silently drops unauthenticated requests, so the client retries then times out.
        let addr = spawn_responder("other-secret").await;
        let err = client(SECRET).send(&request(addr, CoaKind::Coa, "alice")).await.unwrap_err();
        assert!(matches!(err, CoaError::Timeout { attempts: 2, .. }), "{err:?}");
        assert!(err.is_retryable());
    }

    #[tokio::test]
    async fn reply_signed_with_wrong_secret_is_rejected() {
        // A fake NAS that answers with a different secret.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let reply = coa::sign_response(44, &buf[..n], &[], "not-the-secret");
            socket.send_to(&reply, peer).await.unwrap();
        });
        let err = client(SECRET).send(&request(addr, CoaKind::Coa, "alice")).await.unwrap_err();
        assert!(matches!(err, CoaError::BadReply { .. }), "{err:?}");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn closed_port_times_out_after_retries() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        let err = client(SECRET).send(&request(addr, CoaKind::Coa, "alice")).await.unwrap_err();
        assert!(matches!(err, CoaError::Timeout { attempts: 2, .. }), "{err:?}");
    }
}
