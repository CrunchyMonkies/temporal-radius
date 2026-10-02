mod activities;
mod coa;
mod config;
mod health;
mod responder;
mod workflow;

use anyhow::Context;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use temporalio_client::{
    envconfig::LoadClientConfigProfileOptions, tonic::IntoRequest, Client, ClientOptions, Connection,
};
use temporalio_common::protos::grpc::health::v1::{health_check_response::ServingStatus, HealthCheckRequest};
use temporalio_sdk::{Runtime, Worker, WorkerOptions};
use tracing::Level;
use tracing_subscriber::{filter::Targets, fmt, prelude::*};

use crate::{
    activities::RadiusActivities,
    coa::CoaClient,
    config::{HealthConfig, ResponderConfig, WorkerConfig},
    health::Health,
    workflow::SendCoaWorkflow,
};

const USAGE: &str = "usage: radius-coa-worker [worker|coa-responder|healthcheck [path]]";

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "worker".into());
    // Runs every few seconds under Docker HEALTHCHECK: no runtime, no logging setup.
    if mode == "healthcheck" {
        std::process::exit(healthcheck(args.next().as_deref().unwrap_or("/readyz")));
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run(mode));
}

fn healthcheck(path: &str) -> i32 {
    let bind = match HealthConfig::from_env() {
        Ok(HealthConfig { bind: Some(bind), .. }) => bind,
        Ok(_) => {
            eprintln!("health endpoint disabled (HEALTH_BIND=off)");
            return 1;
        }
        Err(e) => {
            eprintln!("{e:#}");
            return 1;
        }
    };
    // Probe over loopback when bound to the wildcard address.
    let ip = match bind.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    if health::probe(SocketAddr::new(ip, bind.port()), path) {
        0
    } else {
        eprintln!("{path} on port {} is not healthy", bind.port());
        1
    }
}

async fn run(mode: String) {
    // RUST_LOG accepts `level` or `target=level,...` directives (no regex/span filters).
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(Level::INFO));
    tracing_subscriber::registry().with(fmt::layer().with_target(false).with_ansi(false)).with(filter).init();

    let result = match mode.as_str() {
        "worker" => run_worker().await,
        "coa-responder" => run_responder().await,
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            return;
        }
        other => Err(anyhow::anyhow!("unknown mode {other:?}; {USAGE}")),
    };
    if let Err(e) = result {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

async fn run_worker() -> anyhow::Result<()> {
    let cfg = WorkerConfig::from_env()?;
    let coa = CoaClient::new(cfg.radius.clone())?;

    // TEMPORAL_ADDRESS / TEMPORAL_NAMESPACE / TEMPORAL_API_KEY / TEMPORAL_TLS* etc.
    let (mut conn_opts, client_opts) =
        ClientOptions::load_from_config(LoadClientConfigProfileOptions::default())
            .map_err(|e| anyhow::anyhow!("loading Temporal client config from environment: {e}"))?;
    if conn_opts.identity.is_empty() {
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into());
        conn_opts.identity = format!("radius-coa-worker@{host}");
    }
    tracing::info!(
        target_url = %conn_opts.target,
        namespace = %client_opts.namespace,
        task_queue = %cfg.task_queue,
        radius = ?cfg.radius,
        "starting worker"
    );

    // Start the health endpoint first: liveness answers immediately, readiness stays 503 until
    // Temporal health checks succeed.
    let health = Health::new(cfg.health.interval * 3);
    if let Some(bind) = cfg.health.bind {
        let addr = health::spawn(bind, health.clone()).await.context("binding health endpoint")?;
        tracing::info!(%addr, "health endpoint listening");
    }

    let runtime = Runtime::from_current_tokio(Default::default())?;
    let connection = Connection::connect(conn_opts).await.context("connecting to Temporal")?;
    let client = Client::new(connection, client_opts)?;
    tokio::spawn(watch_temporal(client.connection().clone(), health, cfg.health.interval));

    let worker_options = WorkerOptions::new(cfg.task_queue.as_str())
        .register_activities(RadiusActivities::new(coa))
        .register_workflow::<SendCoaWorkflow>()?
        .build();

    let mut worker = Worker::new(&runtime, client, worker_options)?;
    let shutdown = worker.shutdown_handle();
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown signal received, draining worker");
        shutdown();
    });
    worker.run().await?;
    tracing::info!("worker stopped");
    Ok(())
}

/// Periodically calls the Temporal frontend's gRPC health service and records the result.
async fn watch_temporal(connection: Connection, health: Health, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    let mut was_ready = false;
    loop {
        ticker.tick().await;
        let mut svc = connection.health_service();
        let check = svc.check(HealthCheckRequest::default().into_request());
        let ready = match tokio::time::timeout(Duration::from_secs(5), check).await {
            Ok(Ok(resp)) => resp.get_ref().status == ServingStatus::Serving as i32,
            Ok(Err(status)) => {
                tracing::debug!("Temporal health check failed: {status}");
                false
            }
            Err(_) => false,
        };
        health.set_ready(ready);
        if ready != was_ready {
            if ready {
                tracing::info!("Temporal reachable; worker ready");
            } else {
                tracing::warn!("Temporal health check failing; worker not ready");
            }
            was_ready = ready;
        }
    }
}

async fn run_responder() -> anyhow::Result<()> {
    responder::run(ResponderConfig::from_env()?).await
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
