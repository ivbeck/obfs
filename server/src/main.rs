mod server;
mod tui;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use vpn_obfs_common::observe::{LogRing, PumpStats};
use vpn_obfs_common::privilege::{ensure_elevated_with_relaunch, ElevationOutcome};

use crate::tui::ServerTuiCtx;

#[derive(Parser)]
#[command(name = "vpn-obfs-server", version, about)]
struct Cli {
    /// Address + port to listen on
    #[arg(short, long, default_value = "0.0.0.0:443")]
    listen: String,

    /// Pre-shared key (arbitrary passphrase; longer = better)
    #[arg(short, long, env = "VPN_PSK")]
    psk: String,

    /// VPN subnet in CIDR notation
    #[arg(long, default_value = "10.8.0.0/24")]
    subnet: String,

    /// TLS certificate file (PEM). Omit to auto-generate self-signed.
    #[arg(long)]
    cert: Option<String>,

    /// TLS private key file (PEM). Required when --cert is provided.
    #[arg(long)]
    key: Option<String>,

    /// CN/SAN domain for the auto-generated self-signed certificate.
    /// Pick something that looks like a real CDN hostname.
    #[arg(long, default_value = "cdn.cloudflare.com")]
    domain: String,

    /// Run with a terminal UI instead of streaming logs to stdout.
    #[arg(long, default_value_t = false)]
    tui: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match ensure_elevated_with_relaunch("vpn-obfs-server", !cli.tui)? {
        ElevationOutcome::Continue => {}
        ElevationOutcome::Relaunched => return Ok(()),
    }
    let stats = PumpStats::new();
    let active = Arc::new(AtomicUsize::new(0));

    let env_filter = || {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("vpn_obfs_server=info,warn"))
    };

    let cert_source = match (&cli.cert, &cli.key) {
        (Some(c), Some(_)) => format!("PEM file {c}"),
        _ => format!("self-signed for {}", cli.domain),
    };

    if cli.tui {
        let logs = LogRing::new(500);
        tracing_subscriber::fmt()
            .with_env_filter(env_filter())
            .with_ansi(false)
            .with_writer(logs.writer())
            .init();

        let should_quit = Arc::new(AtomicBool::new(false));

        let stats_run = stats.clone();
        let active_run = active.clone();
        let sq_run = should_quit.clone();
        let listen = cli.listen.clone();
        let psk = cli.psk.clone();
        let subnet = cli.subnet.clone();
        let cert = cli.cert.clone();
        let key = cli.key.clone();
        let domain = cli.domain.clone();
        let mut srv = tokio::spawn(async move {
            let result = server::run(
                listen, psk, subnet, cert, key, domain, stats_run, active_run,
            )
            .await;
            sq_run.store(true, Ordering::Relaxed);
            result
        });

        let tui_ctx = ServerTuiCtx {
            listen: cli.listen,
            domain: cli.domain,
            subnet: cli.subnet,
            cert_source,
            stats: stats.clone(),
            active: active.clone(),
            logs,
            should_quit: should_quit.clone(),
        };
        let mut ui = tokio::task::spawn_blocking(move || tui::run(tui_ctx));

        let mut srv_first = None;
        let mut ui_first = None;
        tokio::select! {
            res = &mut srv => { srv_first = Some(res); }
            res = &mut ui => { ui_first = Some(res); }
        }

        should_quit.store(true, Ordering::Relaxed);
        if let Some(ui_res) = ui_first {
            let ui_outcome: anyhow::Result<()> = match ui_res {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(anyhow::anyhow!("tui error: {e}")),
                Err(e) => Err(anyhow::anyhow!("tui task join failed: {e}")),
            };
            srv.abort();
            let _ = srv.await;
            ui_outcome
        } else {
            let srv_outcome: anyhow::Result<()> =
                match srv_first.expect("server or ui must finish") {
                    Ok(res) => res,
                    Err(e) => Err(anyhow::anyhow!("server task join failed: {e}")),
                };
            let ui_outcome: anyhow::Result<()> = match ui.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(anyhow::anyhow!("tui error: {e}")),
                Err(e) => Err(anyhow::anyhow!("tui task join failed: {e}")),
            };
            srv_outcome.and(ui_outcome)
        }
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter())
            .init();
        server::run(
            cli.listen, cli.psk, cli.subnet, cli.cert, cli.key, cli.domain, stats, active,
        )
        .await
    }
}
