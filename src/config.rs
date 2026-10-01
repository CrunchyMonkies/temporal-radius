//! Environment-variable configuration.
//!
//! Temporal connection settings (`TEMPORAL_ADDRESS`, `TEMPORAL_NAMESPACE`, `TEMPORAL_API_KEY`,
//! `TEMPORAL_TLS*`, ...) are read by the SDK's `envconfig` loader. Everything specific to this
//! worker is read here.

use std::{env, fmt, net::SocketAddr, time::Duration};

use anyhow::{bail, Context, Result};

pub const DEFAULT_TASK_QUEUE: &str = "radius-coa";
pub const DEFAULT_COA_PORT: u16 = 3799;

/// RADIUS client settings shared by every CoA request the worker sends.
#[derive(Clone)]
pub struct RadiusConfig {
    pub secret: String,
    pub default_port: u16,
    pub timeout: Duration,
    pub retries: u32,
    pub dictionary_path: Option<String>,
}

// Hand-written so the shared secret can never end up in logs.
impl fmt::Debug for RadiusConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RadiusConfig")
            .field("secret", &"<redacted>")
            .field("default_port", &self.default_port)
            .field("timeout", &self.timeout)
            .field("retries", &self.retries)
            .field("dictionary_path", &self.dictionary_path)
            .finish()
    }
}

impl RadiusConfig {
    pub fn from_env() -> Result<Self> {
        let secret = match env::var("RADIUS_SECRET") {
            Ok(s) if !s.is_empty() => s,
            _ => bail!("RADIUS_SECRET is required"),
        };
        Ok(Self {
            secret,
            default_port: parse_or("RADIUS_COA_PORT", DEFAULT_COA_PORT)?,
            timeout: Duration::from_millis(parse_or("RADIUS_TIMEOUT_MS", 3000u64)?),
            retries: parse_or("RADIUS_RETRIES", 2u32)?,
            dictionary_path: non_empty("RADIUS_DICTIONARY"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub task_queue: String,
    pub radius: RadiusConfig,
}

impl WorkerConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            task_queue: non_empty("TEMPORAL_TASK_QUEUE").unwrap_or_else(|| DEFAULT_TASK_QUEUE.to_string()),
            radius: RadiusConfig::from_env()?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResponderConfig {
    pub bind: SocketAddr,
    pub radius: RadiusConfig,
}

impl ResponderConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            bind: parse_or("COA_RESPONDER_BIND", SocketAddr::from(([0, 0, 0, 0], DEFAULT_COA_PORT)))?,
            radius: RadiusConfig::from_env()?,
        })
    }
}

fn non_empty(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

fn parse_or<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match non_empty(key) {
        Some(v) => v.parse().with_context(|| format!("invalid value for {key}: {v:?}")),
        None => Ok(default),
    }
}
