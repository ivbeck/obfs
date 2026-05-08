use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use vpn_obfs_client::tui::{self, ClientTuiCtx};
use vpn_obfs_common::observe::{ConnStatus, LogRing, PumpStats};
use vpn_obfs_common::privilege::{ensure_elevated_with_relaunch, ElevationOutcome};

#[derive(Parser)]
#[command(name = "vpn-obfs-client", version, about)]
struct Cli {
    /// Server address in host:port format
    #[arg(short, long)]
    server: String,

    /// Pre-shared key (must match the server)
    #[arg(short, long, env = "VPN_PSK")]
    psk: String,

    /// IP address to assign to the local TUN interface
    #[arg(long, default_value = "10.8.0.2")]
    ip: String,

    /// Server-side TUN address (used as the VPN gateway)
    #[arg(long, default_value = "10.8.0.1")]
    gateway: String,

    /// SNI hostname sent in the TLS ClientHello.
    /// Should match the server's certificate CN.
    #[arg(long, default_value = "cdn.cloudflare.com")]
    sni: String,

    /// Skip TLS certificate verification (testing only - MITM-vulnerable)
    #[arg(long, default_value_t = false)]
    no_verify: bool,

    /// Run with a terminal UI instead of streaming logs to stdout.
    #[arg(long, default_value_t = false)]
    tui: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match ensure_elevated_with_relaunch("vpn-obfs-client", !cli.tui)? {
        ElevationOutcome::Continue => {}
        ElevationOutcome::Relaunched => return Ok(()),
    }
    let stats = PumpStats::new();
    let status = ConnStatus::new();

    let env_filter = || {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("vpn_obfs_client=info,warn"))
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
        let status_run = status.clone();
        let sq_run = should_quit.clone();
        let server = cli.server.clone();
        let psk = cli.psk.clone();
        let ip = cli.ip.clone();
        let gateway = cli.gateway.clone();
        let sni = cli.sni.clone();
        let no_verify = cli.no_verify;
        let mut vpn = tokio::spawn(async move {
            let result = vpn_obfs_client::client::run(
                server, psk, ip, gateway, sni, no_verify, stats_run, status_run,
            )
            .await;
            sq_run.store(true, Ordering::Relaxed);
            result
        });

        let tui_ctx = ClientTuiCtx {
            server: cli.server,
            sni: cli.sni,
            client_ip: cli.ip,
            gateway: cli.gateway,
            no_verify: cli.no_verify,
            stats: stats.clone(),
            status: status.clone(),
            logs,
            should_quit: should_quit.clone(),
        };
        let mut ui = tokio::task::spawn_blocking(move || tui::run(tui_ctx));

        let mut vpn_first = None;
        let mut ui_first = None;
        tokio::select! {
            res = &mut vpn => { vpn_first = Some(res); }
            res = &mut ui => { ui_first = Some(res); }
        }

        should_quit.store(true, Ordering::Relaxed);
        if let Some(ui_res) = ui_first {
            let ui_outcome: anyhow::Result<()> = match ui_res {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(anyhow::anyhow!("tui error: {e}")),
                Err(e) => Err(anyhow::anyhow!("tui task join failed: {e}")),
            };
            vpn.abort();
            let _ = vpn.await;
            ui_outcome
        } else {
            let vpn_outcome: anyhow::Result<()> = match vpn_first.expect("vpn or ui must finish") {
                Ok(res) => res,
                Err(e) => Err(anyhow::anyhow!("client task join failed: {e}")),
            };
            let ui_outcome: anyhow::Result<()> = match ui.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(anyhow::anyhow!("tui error: {e}")),
                Err(e) => Err(anyhow::anyhow!("tui task join failed: {e}")),
            };
            vpn_outcome.and(ui_outcome)
        }
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter())
            .init();
        vpn_obfs_client::client::run(
            cli.server,
            cli.psk,
            cli.ip,
            cli.gateway,
            cli.sni,
            cli.no_verify,
            stats,
            status,
        )
        .await
    }
}
