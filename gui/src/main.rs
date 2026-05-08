use std::sync::mpsc::{channel, Receiver};

use eframe::egui;
use vpn_obfs_common::privilege::{ensure_elevated, ElevationOutcome};

struct App {
    server: String,
    psk: String,
    ip: String,
    gateway: String,
    sni: String,
    no_verify: bool,
    running: bool,
    status: String,
    result_rx: Option<Receiver<String>>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            server: String::new(),
            psk: String::new(),
            ip: "10.8.0.2".to_owned(),
            gateway: "10.8.0.1".to_owned(),
            sni: "cdn.cloudflare.com".to_owned(),
            no_verify: false,
            running: false,
            status: "Idle".to_owned(),
            result_rx: None,
        }
    }
}

impl App {
    fn connect(&mut self) {
        if self.running {
            return;
        }
        if self.server.trim().is_empty() || self.psk.trim().is_empty() {
            self.status = "Server and PSK are required.".to_owned();
            return;
        }

        let server = self.server.clone();
        let psk = self.psk.clone();
        let ip = self.ip.clone();
        let gateway = self.gateway.clone();
        let sni = self.sni.clone();
        let no_verify = self.no_verify;
        let (tx, rx) = channel::<String>();

        self.running = true;
        self.status = "Connecting... (requires elevated privileges)".to_owned();
        self.result_rx = Some(rx);

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(format!("Failed to create runtime: {e}"));
                    return;
                }
            };

            let stats = vpn_obfs_common::observe::PumpStats::new();
            let status = vpn_obfs_common::observe::ConnStatus::new();
            let result = rt.block_on(vpn_obfs_client::client::run(
                server, psk, ip, gateway, sni, no_verify, stats, status,
            ));
            let msg = match result {
                Ok(()) => "Disconnected.".to_owned(),
                Err(e) => format!("Connection ended with error: {e}"),
            };
            let _ = tx.send(msg);
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.result_rx {
            if let Ok(msg) = rx.try_recv() {
                self.status = msg;
                self.running = false;
                self.result_rx = None;
            }
        }

        ui.heading("vpn-obfs client");
        ui.label("Cross-platform GUI wrapper for the VPN client.");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Server");
            ui.text_edit_singleline(&mut self.server);
        });
        ui.horizontal(|ui| {
            ui.label("PSK");
            ui.add(egui::TextEdit::singleline(&mut self.psk).password(true));
        });
        ui.horizontal(|ui| {
            ui.label("Client IP");
            ui.text_edit_singleline(&mut self.ip);
        });
        ui.horizontal(|ui| {
            ui.label("Gateway");
            ui.text_edit_singleline(&mut self.gateway);
        });
        ui.horizontal(|ui| {
            ui.label("SNI");
            ui.text_edit_singleline(&mut self.sni);
        });
        ui.checkbox(&mut self.no_verify, "Skip TLS verification (unsafe)");

        ui.separator();
        if ui
            .add_enabled(!self.running, egui::Button::new("Connect"))
            .clicked()
        {
            self.connect();
        }
        if self.running {
            ui.label("Session running. Close this window to stop.");
        }

        ui.separator();
        ui.label(format!("Status: {}", self.status));
        ui.label("Run this app with administrator/root privileges.");
    }
}

fn main() -> anyhow::Result<()> {
    match ensure_elevated("vpn-obfs-gui")? {
        ElevationOutcome::Continue => {}
        ElevationOutcome::Relaunched => return Ok(()),
    }

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "vpn-obfs GUI",
        options,
        Box::new(|_cc| Ok(Box::<App>::default())),
    )
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("WAYLAND_DISPLAY")
            || msg.contains("DISPLAY")
            || msg.contains("XOpenDisplayFailed")
        {
            anyhow::anyhow!(
                "start GUI app: no desktop display session detected.\n\
                 If elevation was requested, your display environment may have been stripped.\n\
                 Re-run from a desktop terminal or launch manually as root with preserved display env."
            )
        } else {
            anyhow::Error::new(e).context("start GUI app")
        }
    })
}
