mod server;

use clap::Parser;
use tracing_subscriber::EnvFilter;

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("vpn_obfs_server=info,warn")),
        )
        .init();

    let cli = Cli::parse();
    server::run(cli.listen, cli.psk, cli.subnet, cli.cert, cli.key, cli.domain).await
}
