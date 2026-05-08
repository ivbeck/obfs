//! Terminal UI for the client.
//!
//! Top pane: connection info + live status. Middle pane: TX/RX counters and
//! per-second throughput. Bottom pane: recent log lines from the in-memory
//! ring populated by the tracing subscriber. Quit with `q` / `Esc` /
//! `Ctrl+C`.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, DisableMouseCapture, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Terminal;
use vpn_obfs_common::observe::{
    fmt_bytes, ConnState, ConnStatus, LogRing, PumpStats, StatsSnapshot,
};

pub struct ClientTuiCtx {
    pub server: String,
    pub sni: String,
    pub client_ip: String,
    pub gateway: String,
    pub no_verify: bool,
    pub stats: Arc<PumpStats>,
    pub status: Arc<ConnStatus>,
    pub logs: LogRing,
    pub should_quit: Arc<AtomicBool>,
}

struct Throughput {
    last_snap: StatsSnapshot,
    last_at: Instant,
    tx_bps: f64,
    rx_bps: f64,
}

impl Throughput {
    fn new(snap: StatsSnapshot) -> Self {
        Self {
            last_snap: snap,
            last_at: Instant::now(),
            tx_bps: 0.0,
            rx_bps: 0.0,
        }
    }

    fn update(&mut self, snap: StatsSnapshot) {
        let dt = self.last_at.elapsed().as_secs_f64();
        if dt < 0.5 {
            return;
        }
        let dtx = snap.tx_bytes.saturating_sub(self.last_snap.tx_bytes) as f64;
        let drx = snap.rx_bytes.saturating_sub(self.last_snap.rx_bytes) as f64;
        self.tx_bps = dtx / dt;
        self.rx_bps = drx / dt;
        self.last_snap = snap;
        self.last_at = Instant::now();
    }
}

pub fn run(ctx: ClientTuiCtx) -> io::Result<()> {
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, &ctx);

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    ctx.should_quit.store(true, Ordering::Relaxed);
    result
}

fn event_loop<B: Backend>(terminal: &mut Terminal<B>, ctx: &ClientTuiCtx) -> io::Result<()> {
    let tick = Duration::from_millis(250);
    let mut throughput = Throughput::new(ctx.stats.snapshot());
    let mut last_tick = Instant::now();

    while !ctx.should_quit.load(Ordering::Relaxed) {
        if last_tick.elapsed() >= Duration::from_millis(900) {
            throughput.update(ctx.stats.snapshot());
            last_tick = Instant::now();
        }

        terminal.draw(|f| render(f, ctx, &throughput))?;

        let remaining = tick
            .checked_sub(last_tick.elapsed().min(tick))
            .unwrap_or(Duration::from_millis(50));
        if event::poll(remaining)? {
            if let Event::Key(key) = event::read()? {
                let ctrl_c = key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL);
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c {
                    ctx.should_quit.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
    Ok(())
}

fn render(f: &mut ratatui::Frame, ctx: &ClientTuiCtx, tput: &Throughput) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

    let state = ctx.status.get();
    let (state_color, state_label) = state_style(state);

    let info_lines = vec![
        Line::from(vec![
            Span::styled("Server : ", Style::default().fg(Color::Gray)),
            Span::raw(&ctx.server),
        ]),
        Line::from(vec![
            Span::styled("SNI    : ", Style::default().fg(Color::Gray)),
            Span::raw(&ctx.sni),
        ]),
        Line::from(vec![
            Span::styled("TUN    : ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{} -> {}", ctx.client_ip, ctx.gateway)),
        ]),
        Line::from(vec![
            Span::styled("TLS    : ", Style::default().fg(Color::Gray)),
            Span::raw(if ctx.no_verify {
                "verification disabled"
            } else {
                "standard verify"
            }),
        ]),
        Line::from(vec![
            Span::styled("Status : ", Style::default().fg(Color::Gray)),
            Span::styled(
                state_label,
                Style::default().fg(state_color).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];
    f.render_widget(
        Paragraph::new(info_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" vpn-obfs client "),
        ),
        chunks[0],
    );

    let snap = ctx.stats.snapshot();
    let stat_lines = vec![
        Line::from(vec![
            Span::styled("TX  ", Style::default().fg(Color::LightGreen)),
            Span::raw(format!(
                "{} ({} packets)  rate {}/s",
                fmt_bytes(snap.tx_bytes),
                snap.tx_packets,
                fmt_bytes(tput.tx_bps as u64),
            )),
        ]),
        Line::from(vec![
            Span::styled("RX  ", Style::default().fg(Color::LightCyan)),
            Span::raw(format!(
                "{} ({} packets)  rate {}/s",
                fmt_bytes(snap.rx_bytes),
                snap.rx_packets,
                fmt_bytes(tput.rx_bps as u64),
            )),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Press q / Esc / Ctrl-C to quit.",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )]),
    ];
    f.render_widget(
        Paragraph::new(stat_lines).block(Block::default().borders(Borders::ALL).title(" Traffic ")),
        chunks[1],
    );

    let log_height = chunks[2].height.saturating_sub(2) as usize;
    let lines = ctx.logs.snapshot(log_height.max(1));
    let log_widget = Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>())
        .block(Block::default().borders(Borders::ALL).title(" Logs "))
        .wrap(Wrap { trim: false });
    f.render_widget(log_widget, chunks[2]);

    let footer = Paragraph::new(Line::from(Span::styled(
        format!(
            "tx pkts: {}  rx pkts: {}  state: {}",
            snap.tx_packets,
            snap.rx_packets,
            state.label()
        ),
        Style::default().fg(Color::DarkGray),
    )))
    .alignment(Alignment::Left);
    f.render_widget(footer, chunks[3]);
}

fn state_style(s: ConnState) -> (Color, &'static str) {
    match s {
        ConnState::Idle => (Color::Gray, "idle"),
        ConnState::Connecting => (Color::Yellow, "connecting"),
        ConnState::Handshaking => (Color::Yellow, "handshaking"),
        ConnState::Connected => (Color::Green, "connected"),
        ConnState::Disconnected => (Color::Red, "disconnected"),
    }
}
