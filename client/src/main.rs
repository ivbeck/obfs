use clap::Parser;
use tracing_subscriber::EnvFilter;
use vpn_obfs_common::privilege::{ensure_elevated, ElevationOutcome};

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match ensure_elevated("vpn-obfs-client")? {
        ElevationOutcome::Continue => {}
        ElevationOutcome::Relaunched => return Ok(()),
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("vpn_obfs_client=info,warn")),
        )
        .init();

    let cli = Cli::parse();
    vpn_obfs_client::client::run(
        cli.server,
        cli.psk,
        cli.ip,
        cli.gateway,
        cli.sni,
        cli.no_verify,
    )
    .await
}
