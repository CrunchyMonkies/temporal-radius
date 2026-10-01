mod activities;
mod coa;
mod config;
mod responder;
mod workflow;

use anyhow::Context;
use temporalio_client::{envconfig::LoadClientConfigProfileOptions, Client, ClientOptions, Connection};
use temporalio_sdk::{Runtime, Worker, WorkerOptions};
use tracing_subscriber::EnvFilter;

use crate::{
    activities::RadiusActivities,
    coa::CoaClient,
    config::{ResponderConfig, WorkerConfig},
    workflow::SendCoaWorkflow,
};

const USAGE: &str = "usage: radius-coa-worker [worker|coa-responder]";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let mode = std::env::args().nth(1).unwrap_or_else(|| "worker".into());
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

    let runtime = Runtime::from_current_tokio(Default::default())?;
    let connection = Connection::connect(conn_opts).await.context("connecting to Temporal")?;
    let client = Client::new(connection, client_opts)?;

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
