//! Operator TUI dashboard for the Proteus morph factory.
//!
//! Entry point: [`run_tui`]. Renders a four-tab live view of factory
//! state by polling files under `root` every 500ms — no daemon process,
//! no shared memory, no IPC. Files consulted:
//!
//! - `scheduler.toml` — module configs.
//! - `scheduler_state.json` — last cycle per module (optional).
//! - `attest.log.jsonl` — hash-chained attestation log (schema v2+),
//!   parsed tolerantly to survive schema drift.
//! - `perf.jsonl` — per-cycle perf samples.
//! - `factory_keys.toml` — federation keyset (counted only, never used).
//!
//! Tabs:
//!
//! 1. **Overview** — totals, last entry summary, accepted ratio across
//!    the last 50 entries, last 5 entries.
//! 2. **Modules** — table of `scheduler.toml` modules with the same
//!    "due in" formula the scheduler uses: `(now - last) * priority >=
//!    max_age_secs`.
//! 3. **Attestation** — scrollable table of the last 30 entries.
//! 4. **Performance** — line chart of the last 50 samples for the
//!    currently-selected metric. Number keys 1..6 switch metric.
//!
//! ## Headless mode
//!
//! Production use: `morph tui` opens the alternate screen, enters raw
//! mode, and polls real keystrokes. CI use: `morph tui --ticks N` runs
//! N redraw iterations against a [`TestBackend`] and exits 0. This is
//! how the smoke test exercises the redraw path without a real TTY.
//! When `--ticks` is set, we NEVER touch crossterm raw mode or the
//! alternate screen — keeping the test side-effect-free on Windows
//! piped-stdout CI.

use anyhow::{Context, Result};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend, TestBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, GraphType, List, ListItem, Paragraph, Row,
        Table, Tabs, Wrap,
    },
    Frame, Terminal,
};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::scheduler::{load_config, load_state, ModuleConfig, SchedulerConfig, SchedulerState};

/// Polling cadence. Each iteration of the main loop either (a) takes a
/// keystroke if one arrived within this window, or (b) re-reads state
/// and redraws.
const TICK_MS: u64 = 500;

/// Number of attestation entries shown on the Attestation tab.
const ATTEST_WINDOW: usize = 30;

/// Number of perf samples used for the chart + summary stats.
const PERF_WINDOW: usize = 50;

/// Number of recent entries used to compute the Overview accepted ratio.
const OVERVIEW_RATIO_WINDOW: usize = 50;

// ---------------------------------------------------------------------
// Pure data shapes
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct AttestRow {
    cycle: u64,
    ts_unix: u64,
    module: String,
    candidate_sha256: String,
    accepted: bool,
    synthesizer: String,
    has_image: bool,
    cosig_count: usize,
}

#[derive(Debug, Clone, Default)]
struct PerfRow {
    /// Wall-clock of the sample. Carried for future "x-axis is real
    /// time, not sample index" support; currently the chart is indexed
    /// by sample number, so the field is unused at render time.
    #[allow(dead_code)]
    ts_unix: u64,
    fletcher32_ns: f64,
    feistel_mix_ns: f64,
    derive_byte_ns: f64,
    demohash_ns: f64,
    demosyscall_ns: f64,
    demosigverify_ns: f64,
}

/// Six switchable metrics on the Performance tab. Stable enum so 1..6
/// key bindings have one obvious destination each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PerfMetric {
    Fletcher32,
    FeistelMix,
    DeriveByte,
    DemoHash,
    DemoSyscall,
    DemoSigVerify,
}

impl PerfMetric {
    fn from_key(c: char) -> Option<Self> {
        match c {
            '1' => Some(Self::Fletcher32),
            '2' => Some(Self::FeistelMix),
            '3' => Some(Self::DeriveByte),
            '4' => Some(Self::DemoHash),
            '5' => Some(Self::DemoSyscall),
            '6' => Some(Self::DemoSigVerify),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Fletcher32 => "fletcher32_ns",
            Self::FeistelMix => "feistel_mix_ns",
            Self::DeriveByte => "derive_byte_ns",
            Self::DemoHash => "demohash_ns",
            Self::DemoSyscall => "demosyscall_ns",
            Self::DemoSigVerify => "demosigverify_ns",
        }
    }

    fn extract(self, row: &PerfRow) -> f64 {
        match self {
            Self::Fletcher32 => row.fletcher32_ns,
            Self::FeistelMix => row.feistel_mix_ns,
            Self::DeriveByte => row.derive_byte_ns,
            Self::DemoHash => row.demohash_ns,
            Self::DemoSyscall => row.demosyscall_ns,
            Self::DemoSigVerify => row.demosigverify_ns,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Modules,
    Attestation,
    Performance,
}

impl Tab {
    const ALL: [Tab; 4] = [Tab::Overview, Tab::Modules, Tab::Attestation, Tab::Performance];

    fn idx(self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Modules => 1,
            Tab::Attestation => 2,
            Tab::Performance => 3,
        }
    }

    fn from_idx(i: usize) -> Self {
        Self::ALL[i.min(3)]
    }

    fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Modules => "Modules",
            Tab::Attestation => "Attestation",
            Tab::Performance => "Performance",
        }
    }
}

/// Snapshot of disk state loaded on each tick. Errors from individual
/// files are *captured* (not propagated) so the TUI can render a banner
/// rather than blow up the terminal.
#[derive(Debug, Default)]
struct State {
    scheduler_cfg: Option<SchedulerConfig>,
    scheduler_state: SchedulerState,
    entries: Vec<AttestRow>,
    perf: Vec<PerfRow>,
    factory_keys_count: usize,
    /// Human-readable banners — one per file that failed to load.
    banners: Vec<String>,
}

#[derive(Debug)]
struct App {
    root: PathBuf,
    tab: Tab,
    attest_scroll: usize,
    perf_metric: PerfMetric,
    state: State,
    last_refresh: Instant,
    should_quit: bool,
}

impl App {
    fn new(root: PathBuf) -> Self {
        let mut app = App {
            root,
            tab: Tab::Overview,
            attest_scroll: 0,
            perf_metric: PerfMetric::Fletcher32,
            state: State::default(),
            last_refresh: Instant::now(),
            should_quit: false,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.state = load_all(&self.root);
        self.last_refresh = Instant::now();
        // Clamp scroll if entries shrank between refreshes.
        let max_scroll = self.state.entries.len().saturating_sub(1);
        if self.attest_scroll > max_scroll {
            self.attest_scroll = max_scroll;
        }
    }

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                self.should_quit = true;
            }
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            KeyCode::Tab => {
                let next = (self.tab.idx() + 1) % Tab::ALL.len();
                self.tab = Tab::from_idx(next);
            }
            KeyCode::BackTab => {
                let cur = self.tab.idx();
                let next = if cur == 0 { Tab::ALL.len() - 1 } else { cur - 1 };
                self.tab = Tab::from_idx(next);
            }
            KeyCode::Char('h') => {
                let cur = self.tab.idx();
                let next = if cur == 0 { Tab::ALL.len() - 1 } else { cur - 1 };
                self.tab = Tab::from_idx(next);
            }
            KeyCode::Char('l') => {
                let next = (self.tab.idx() + 1) % Tab::ALL.len();
                self.tab = Tab::from_idx(next);
            }
            KeyCode::Char(c @ '1'..='6') => {
                // On the Performance tab, 1..6 selects a perf metric.
                // On every other tab, 1..4 jumps to that tab and 5/6
                // are no-ops.
                if self.tab == Tab::Performance {
                    if let Some(m) = PerfMetric::from_key(c) {
                        self.perf_metric = m;
                    }
                } else if matches!(c, '1'..='4') {
                    let idx = (c as u8 - b'1') as usize;
                    self.tab = Tab::from_idx(idx);
                }
            }
            KeyCode::Down | KeyCode::Char('j') if self.tab == Tab::Attestation => {
                if self.attest_scroll + 1 < self.state.entries.len() {
                    self.attest_scroll += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') if self.tab == Tab::Attestation => {
                self.attest_scroll = self.attest_scroll.saturating_sub(1);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------
// Pure helpers (unit-tested below — no terminal needed)
// ---------------------------------------------------------------------

/// Human-readable seconds-ago. Mirrors the kind of string the operator
/// expects ("12s ago", "3m ago", "2h ago"). Anything past 24h shows
/// days. `0` (or future timestamps) renders as "now".
pub fn humanise_seconds_ago(secs_ago: i64) -> String {
    if secs_ago <= 0 {
        return "now".to_string();
    }
    if secs_ago < 60 {
        return format!("{}s ago", secs_ago);
    }
    if secs_ago < 3600 {
        return format!("{}m ago", secs_ago / 60);
    }
    if secs_ago < 86_400 {
        return format!("{}h ago", secs_ago / 3600);
    }
    format!("{}d ago", secs_ago / 86_400)
}

/// `(now - last) * priority >= max_age_secs` — same formula as
/// [`crate::scheduler::pick_next_at`]. Returns `0` when the module is
/// already due (negative or zero "due in"), else the number of seconds
/// until the inequality flips.
pub fn due_in_seconds(now: u64, last_morph_unix: u64, priority: u64, max_age_secs: u64) -> u64 {
    if priority == 0 {
        // Module is paused — never due.
        return u64::MAX;
    }
    let elapsed = now.saturating_sub(last_morph_unix);
    let weighted = elapsed.saturating_mul(priority);
    if weighted >= max_age_secs {
        return 0;
    }
    let remaining_weighted = max_age_secs - weighted;
    // Ceil divide so "1s away" rounds to 1, not 0.
    (remaining_weighted + priority - 1) / priority
}

/// Truncate a hex SHA-256 to its first `n` characters for display.
/// Returns the input verbatim if shorter than `n`.
fn short_hex(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[..n].to_string()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------
// State loaders — tolerant of missing files + schema drift
// ---------------------------------------------------------------------

fn load_all(root: &Path) -> State {
    let mut state = State::default();

    // Scheduler config.
    let cfg_path = root.join("scheduler.toml");
    match load_config(&cfg_path) {
        Ok(c) => state.scheduler_cfg = Some(c),
        Err(e) => state
            .banners
            .push(format!("scheduler.toml at {}: {:#}", cfg_path.display(), e)),
    }

    // Scheduler state (missing is OK).
    let st_path = root.join("scheduler_state.json");
    match load_state(&st_path) {
        Ok(s) => state.scheduler_state = s,
        Err(e) => state
            .banners
            .push(format!("scheduler_state.json: {:#}", e)),
    }

    // Attestation log — tolerant JSONL parse.
    let attest_path = root.join("attest.log.jsonl");
    match load_attest_rows(&attest_path) {
        Ok(rows) => state.entries = rows,
        Err(e) => state.banners.push(format!("attest.log.jsonl: {:#}", e)),
    }

    // Perf log.
    let perf_path = root.join("perf.jsonl");
    match load_perf_rows(&perf_path) {
        Ok(rows) => state.perf = rows,
        Err(e) => state.banners.push(format!("perf.jsonl: {:#}", e)),
    }

    // Factory keys count.
    state.factory_keys_count = load_factory_keys_count(&root.join("factory_keys.toml"));

    state
}

fn load_attest_rows(path: &Path) -> Result<Vec<AttestRow>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    // Use a Deserializer iterator to tolerate one corrupt line without
    // aborting the whole load. Per-line parse failures are silently
    // dropped — the banner system reports the file-level error if
    // present, but a single garbled line on a 10 000-line log shouldn't
    // blank the dashboard.
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(t) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let cycle = v.get("cycle").and_then(|x| x.as_u64()).unwrap_or(0);
        let ts_unix = v.get("ts_unix").and_then(|x| x.as_u64()).unwrap_or(0);
        let module = v
            .get("module")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let candidate_sha256 = v
            .get("candidate_sha256")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let accepted = v.get("accepted").and_then(|x| x.as_bool()).unwrap_or(false);
        let synthesizer = v
            .get("synthesizer")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let has_image = v
            .get("image_sha256")
            .map(|x| !x.is_null())
            .unwrap_or(false);
        let cosig_count = v
            .get("cosignatures")
            .and_then(|x| x.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        out.push(AttestRow {
            cycle,
            ts_unix,
            module,
            candidate_sha256,
            accepted,
            synthesizer,
            has_image,
            cosig_count,
        });
    }
    Ok(out)
}

fn load_perf_rows(path: &Path) -> Result<Vec<PerfRow>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(t) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let f = |k: &str| -> f64 {
            v.get(k)
                .and_then(|x| x.as_f64().or_else(|| x.as_u64().map(|n| n as f64)))
                .unwrap_or(0.0)
        };
        out.push(PerfRow {
            ts_unix: v.get("ts_unix").and_then(|x| x.as_u64()).unwrap_or(0),
            fletcher32_ns: f("fletcher32_ns"),
            feistel_mix_ns: f("feistel_mix_ns"),
            derive_byte_ns: f("derive_byte_ns"),
            demohash_ns: f("demohash_ns"),
            demosyscall_ns: f("demosyscall_ns"),
            demosigverify_ns: f("demosigverify_ns"),
        });
    }
    Ok(out)
}

fn load_factory_keys_count(path: &Path) -> usize {
    let Ok(text) = fs::read_to_string(path) else {
        return 0;
    };
    let Ok(value) = toml::from_str::<toml::Value>(&text) else {
        return 0;
    };
    value
        .get("signers")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

fn ui(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tabs
            Constraint::Min(0),    // body
            Constraint::Length(1), // status
        ])
        .split(area);

    // Tab bar.
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| Line::from(t.title()))
        .collect();
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("morph tui"))
        .select(app.tab.idx())
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, chunks[0]);

    // Body — banners are rendered above the body within the chunk.
    let body_area = chunks[1];
    let body_area = render_banners(frame, body_area, &app.state.banners);
    match app.tab {
        Tab::Overview => render_overview(frame, body_area, app),
        Tab::Modules => render_modules(frame, body_area, app),
        Tab::Attestation => render_attestation(frame, body_area, app),
        Tab::Performance => render_performance(frame, body_area, app),
    }

    // Status bar.
    let refresh_age = app.last_refresh.elapsed().as_secs();
    let status = format!(
        " tab/shift-tab: switch • 1-4: jump • q: quit • last refresh: {}s ago",
        refresh_age
    );
    let bar = Paragraph::new(status).style(Style::default().fg(Color::Gray).bg(Color::DarkGray));
    frame.render_widget(bar, chunks[2]);
}

fn render_banners(frame: &mut Frame, area: Rect, banners: &[String]) -> Rect {
    if banners.is_empty() {
        return area;
    }
    let h = banners.len().min(3) as u16 + 2;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(h), Constraint::Min(0)])
        .split(area);
    let text: Vec<Line> = banners
        .iter()
        .take(3)
        .map(|b| Line::from(Span::styled(format!("! {}", b), Style::default().fg(Color::Red))))
        .collect();
    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("warnings")
                .style(Style::default().fg(Color::Red)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(p, chunks[0]);
    chunks[1]
}

fn render_overview(frame: &mut Frame, area: Rect, app: &App) {
    let entries = &app.state.entries;
    let total = entries.len();
    let window_start = total.saturating_sub(OVERVIEW_RATIO_WINDOW);
    let window = &entries[window_start..];
    let accepted = window.iter().filter(|e| e.accepted).count();
    let ratio = if window.is_empty() {
        "n/a".to_string()
    } else {
        format!(
            "{}/{} ({:.0}%)",
            accepted,
            window.len(),
            (accepted as f64 / window.len() as f64) * 100.0
        )
    };

    let now = now_unix();
    let last = entries.last();
    let last_summary = if let Some(e) = last {
        format!(
            "cycle {} module={} accepted={} ({})",
            e.cycle,
            e.module,
            if e.accepted { "yes" } else { "no" },
            humanise_seconds_ago(now as i64 - e.ts_unix as i64)
        )
    } else {
        "<no attestation entries yet>".to_string()
    };

    let lines = vec![
        Line::from(format!("factory_keys     : {}", app.state.factory_keys_count)),
        Line::from(format!("attestation total: {}", total)),
        Line::from(format!("last entry       : {}", last_summary)),
        Line::from(format!(
            "accepted (last {}): {}",
            OVERVIEW_RATIO_WINDOW, ratio
        )),
        Line::from(format!("perf samples     : {}", app.state.perf.len())),
        Line::from(format!(
            "modules declared : {}",
            app.state
                .scheduler_cfg
                .as_ref()
                .map(|c| c.modules.len())
                .unwrap_or(0)
        )),
    ];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let summary = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("factory summary"),
    );
    frame.render_widget(summary, chunks[0]);

    let last5: Vec<ListItem> = entries
        .iter()
        .rev()
        .take(5)
        .map(|e| {
            let mark = if e.accepted { "✓" } else { "✗" };
            let style = if e.accepted {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", mark), style),
                Span::raw(format!(
                    "cycle {:>6} {:<12} {} ({})",
                    e.cycle,
                    e.module,
                    short_hex(&e.candidate_sha256, 12),
                    humanise_seconds_ago(now as i64 - e.ts_unix as i64),
                )),
            ]))
        })
        .collect();
    let list =
        List::new(last5).block(Block::default().borders(Borders::ALL).title("last 5 entries"));
    frame.render_widget(list, chunks[1]);
}

fn render_modules(frame: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(vec![
        Cell::from("module"),
        Cell::from("prio"),
        Cell::from("max_age_secs"),
        Cell::from("last_cycle"),
        Cell::from("last_morph"),
        Cell::from("due in"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan));

    let now = now_unix();
    let rows: Vec<Row> = match &app.state.scheduler_cfg {
        Some(cfg) => cfg
            .modules
            .iter()
            .map(|(name, mcfg)| build_module_row(name, mcfg, &app.state.scheduler_state, now))
            .collect(),
        None => Vec::new(),
    };

    let widths = [
        Constraint::Percentage(20),
        Constraint::Percentage(8),
        Constraint::Percentage(15),
        Constraint::Percentage(12),
        Constraint::Percentage(20),
        Constraint::Percentage(25),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("modules"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    frame.render_widget(table, area);
}

fn build_module_row<'a>(
    name: &'a str,
    mcfg: &'a ModuleConfig,
    state: &'a SchedulerState,
    now: u64,
) -> Row<'a> {
    let ms = state.modules.get(name);
    let last_cycle = ms.map(|m| m.last_cycle.to_string()).unwrap_or_default();
    let last_morph_str = match ms {
        Some(m) if m.last_morph_unix > 0 => {
            humanise_seconds_ago(now as i64 - m.last_morph_unix as i64)
        }
        _ => "<never>".to_string(),
    };
    let last_morph_unix = ms.map(|m| m.last_morph_unix).unwrap_or(0);
    let due = due_in_seconds(now, last_morph_unix, mcfg.priority, mcfg.max_age_secs);
    let due_str = if due == 0 {
        "DUE NOW".to_string()
    } else if due == u64::MAX {
        "paused".to_string()
    } else {
        humanise_in_seconds(due)
    };
    let due_style = if due == 0 {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Row::new(vec![
        Cell::from(name.to_string()),
        Cell::from(mcfg.priority.to_string()),
        Cell::from(mcfg.max_age_secs.to_string()),
        Cell::from(last_cycle),
        Cell::from(last_morph_str),
        Cell::from(due_str).style(due_style),
    ])
}

fn humanise_in_seconds(secs: u64) -> String {
    if secs < 60 {
        format!("in {}s", secs)
    } else if secs < 3600 {
        format!("in {}m", secs / 60)
    } else if secs < 86_400 {
        format!("in {}h", secs / 3600)
    } else {
        format!("in {}d", secs / 86_400)
    }
}

fn render_attestation(frame: &mut Frame, area: Rect, app: &App) {
    let entries = &app.state.entries;
    let total = entries.len();
    // Newest at top: slice tail, then reverse for display.
    let start = total.saturating_sub(ATTEST_WINDOW + app.attest_scroll);
    let end = total.saturating_sub(app.attest_scroll);
    let slice = if start < end { &entries[start..end] } else { &[][..] };

    let header = Row::new(vec![
        Cell::from("cycle"),
        Cell::from("module"),
        Cell::from("ok"),
        Cell::from("synth"),
        Cell::from("cand[..8]"),
        Cell::from("img"),
        Cell::from("cosigs"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan));

    let rows: Vec<Row> = slice
        .iter()
        .rev()
        .map(|e| {
            let mark = if e.accepted { "✓" } else { "✗" };
            let style = if e.accepted {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };
            Row::new(vec![
                Cell::from(e.cycle.to_string()),
                Cell::from(e.module.clone()),
                Cell::from(mark).style(style),
                Cell::from(e.synthesizer.clone()),
                Cell::from(short_hex(&e.candidate_sha256, 8)),
                Cell::from(if e.has_image { "✓" } else { "·" }),
                Cell::from(e.cosig_count.to_string()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Length(3),
        Constraint::Length(14),
        Constraint::Length(10),
        Constraint::Length(4),
        Constraint::Length(7),
    ];
    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("attestation (showing {} of {})", slice.len(), total)),
    );
    frame.render_widget(table, area);
}

fn render_performance(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(30)])
        .split(area);

    let perf = &app.state.perf;
    let window_start = perf.len().saturating_sub(PERF_WINDOW);
    let window = &perf[window_start..];

    let data: Vec<(f64, f64)> = window
        .iter()
        .enumerate()
        .map(|(i, r)| (i as f64, app.perf_metric.extract(r)))
        .collect();

    let (y_min, y_max, _median, _p95, latest) = stats(&data);

    let dataset = vec![Dataset::default()
        .name(app.perf_metric.label())
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Cyan))
        .data(&data)];

    let x_max = (data.len().saturating_sub(1)) as f64;
    let chart = Chart::new(dataset)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("perf: {} (last {})", app.perf_metric.label(), data.len())),
        )
        .x_axis(
            Axis::default()
                .title("sample")
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, x_max.max(1.0)]),
        )
        .y_axis(
            Axis::default()
                .title("ns")
                .style(Style::default().fg(Color::DarkGray))
                .labels::<Vec<Span>>(vec![
                    Span::raw(format!("{:.0}", y_min)),
                    Span::raw(format!("{:.0}", y_max)),
                ])
                .bounds([y_min, y_max.max(y_min + 1.0)]),
        );
    frame.render_widget(chart, chunks[0]);

    let (min, max, median, p95, _last) = stats(&data);
    let side = vec![
        Line::from(format!("metric : {}", app.perf_metric.label())),
        Line::from(""),
        Line::from(format!("samples: {}", data.len())),
        Line::from(format!("min    : {:.0} ns", min)),
        Line::from(format!("median : {:.0} ns", median)),
        Line::from(format!("p95    : {:.0} ns", p95)),
        Line::from(format!("max    : {:.0} ns", max)),
        Line::from(format!("latest : {:.0} ns", latest)),
        Line::from(""),
        Line::from("1=fletcher32"),
        Line::from("2=feistel_mix"),
        Line::from("3=derive_byte"),
        Line::from("4=demohash"),
        Line::from("5=demosyscall"),
        Line::from("6=demosigverify"),
    ];
    let p = Paragraph::new(side)
        .block(Block::default().borders(Borders::ALL).title("stats"))
        .wrap(Wrap { trim: false });
    frame.render_widget(p, chunks[1]);
}

/// (min, max, median, p95, latest)
fn stats(data: &[(f64, f64)]) -> (f64, f64, f64, f64, f64) {
    if data.is_empty() {
        return (0.0, 1.0, 0.0, 0.0, 0.0);
    }
    let mut ys: Vec<f64> = data.iter().map(|(_, y)| *y).collect();
    let latest = *ys.last().unwrap();
    ys.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let min = ys[0];
    let max = *ys.last().unwrap();
    let median = ys[ys.len() / 2];
    let p95_idx = ((ys.len() as f64) * 0.95) as usize;
    let p95 = ys[p95_idx.min(ys.len() - 1)];
    (min, max, median, p95, latest)
}

// ---------------------------------------------------------------------
// Entry point + terminal lifecycle
// ---------------------------------------------------------------------

/// RAII guard. `enter()` flips into raw mode + alternate screen;
/// `Drop` always undoes both, even on panic, so the operator's terminal
/// is never left in a wedged state.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enable raw mode")?;
        let mut out = io::stdout();
        execute!(out, EnterAlternateScreen, EnableMouseCapture)
            .context("enter alternate screen")?;
        Ok(TerminalGuard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut out = io::stdout();
        let _ = execute!(out, LeaveAlternateScreen, DisableMouseCapture);
    }
}

/// Run the TUI against `root`. Blocks until the operator quits (`q`,
/// `Q`, `Esc`, or `Ctrl-C`) or — if `ticks` is `Some(n)` — until `n`
/// redraw iterations have happened, in which case we exit cleanly with
/// `Ok(())`.
pub fn run_tui_with_options(root: &Path, ticks: Option<usize>) -> Result<()> {
    if let Some(n) = ticks {
        return run_tui_headless(root, n);
    }
    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend).context("init terminal")?;
    let mut app = App::new(root.to_path_buf());
    run_loop(terminal, &mut app)?;
    Ok(())
}

/// Convenience wrapper used by the CLI when no `--ticks` is provided.
pub fn run_tui(root: &Path) -> Result<()> {
    run_tui_with_options(root, None)
}

fn run_loop<B: Backend>(mut terminal: Terminal<B>, app: &mut App) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|f| ui(f, app))?;
        if event::poll(Duration::from_millis(TICK_MS))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    app.on_key(k.code, k.modifiers);
                }
            }
        } else {
            app.refresh();
        }
    }
    Ok(())
}

/// Headless smoke path: never touches the real terminal, never enters
/// raw mode. Builds a [`TestBackend`] of a reasonable size, runs the UI
/// `ticks` times so all four tabs get exercised (we round-robin the
/// tab and the perf metric), and returns. Used by the smoke test and
/// any future CI gate.
fn run_tui_headless(root: &Path, ticks: usize) -> Result<()> {
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).context("init test backend")?;
    let mut app = App::new(root.to_path_buf());

    // Cycle through every tab + every perf metric so the renderer
    // exercises all four code paths even with --ticks 1 (we draw,
    // rotate, draw, rotate ...).
    for i in 0..ticks.max(1) {
        terminal.draw(|f| ui(f, &app))?;
        app.refresh();
        // Rotate the tab focus so a single-tick run still hits all four
        // body renderers across consecutive draws.
        let next_tab = (app.tab.idx() + 1) % Tab::ALL.len();
        app.tab = Tab::from_idx(next_tab);
        // Rotate the perf metric on the fourth iteration.
        if i % 4 == 3 {
            app.perf_metric = match app.perf_metric {
                PerfMetric::Fletcher32 => PerfMetric::FeistelMix,
                PerfMetric::FeistelMix => PerfMetric::DeriveByte,
                PerfMetric::DeriveByte => PerfMetric::DemoHash,
                PerfMetric::DemoHash => PerfMetric::DemoSyscall,
                PerfMetric::DemoSyscall => PerfMetric::DemoSigVerify,
                PerfMetric::DemoSigVerify => PerfMetric::Fletcher32,
            };
        }
    }
    // Final draw on Overview tab so the operator-visible buffer matches
    // the "initial frame" expectation when --ticks is being used in a
    // demo.
    app.tab = Tab::Overview;
    terminal.draw(|f| ui(f, &app))?;
    Ok(())
}

// ---------------------------------------------------------------------
// Unit tests — pure functions only, no terminal needed.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanise_secs_basic() {
        assert_eq!(humanise_seconds_ago(0), "now");
        assert_eq!(humanise_seconds_ago(-5), "now");
        assert_eq!(humanise_seconds_ago(1), "1s ago");
        assert_eq!(humanise_seconds_ago(59), "59s ago");
        assert_eq!(humanise_seconds_ago(60), "1m ago");
        assert_eq!(humanise_seconds_ago(3599), "59m ago");
        assert_eq!(humanise_seconds_ago(3600), "1h ago");
        assert_eq!(humanise_seconds_ago(86_399), "23h ago");
        assert_eq!(humanise_seconds_ago(86_400), "1d ago");
        assert_eq!(humanise_seconds_ago(172_800), "2d ago");
    }

    #[test]
    fn due_in_zero_when_due_now() {
        // priority 10, max_age 3600, last 1000s ago → 1000*10 = 10_000 > 3600.
        assert_eq!(due_in_seconds(2000, 1000, 10, 3600), 0);
    }

    #[test]
    fn due_in_reflects_priority() {
        // priority 1, max_age 3600, last 600s ago → due in 3000s.
        // Formula: (3600 - 600*1) / 1 = 3000.
        assert_eq!(due_in_seconds(600, 0, 1, 3600), 3000);
        // priority 10, same input → due in 300s. (3600 - 6000 ≤ 0 → due).
        assert_eq!(due_in_seconds(600, 0, 10, 3600), 0);
        // priority 10, max_age 3600, last 60s ago → due in 300s.
        // weighted = 60*10 = 600, remaining = 3000, ceil(3000/10) = 300.
        assert_eq!(due_in_seconds(60, 0, 10, 3600), 300);
    }

    #[test]
    fn due_in_paused_for_zero_priority() {
        assert_eq!(due_in_seconds(100, 0, 0, 3600), u64::MAX);
    }

    #[test]
    fn due_in_ceil_divides() {
        // weighted = 0, remaining = 5, priority = 3 → ceil(5/3) = 2.
        assert_eq!(due_in_seconds(0, 0, 3, 5), 2);
    }

    #[test]
    fn short_hex_truncates_and_passes_through() {
        assert_eq!(short_hex("abcdef0123", 4), "abcd");
        assert_eq!(short_hex("ab", 4), "ab");
        assert_eq!(short_hex("abcd", 4), "abcd");
    }

    #[test]
    fn humanise_in_seconds_basic() {
        assert_eq!(humanise_in_seconds(0), "in 0s");
        assert_eq!(humanise_in_seconds(45), "in 45s");
        assert_eq!(humanise_in_seconds(60), "in 1m");
        assert_eq!(humanise_in_seconds(3600), "in 1h");
        assert_eq!(humanise_in_seconds(86_400), "in 1d");
    }

    #[test]
    fn stats_handles_empty_and_one() {
        let (min, max, med, p95, last) = stats(&[]);
        assert_eq!((min, max, med, p95, last), (0.0, 1.0, 0.0, 0.0, 0.0));
        let (min, max, med, p95, last) = stats(&[(0.0, 42.0)]);
        assert_eq!(min, 42.0);
        assert_eq!(max, 42.0);
        assert_eq!(med, 42.0);
        assert_eq!(p95, 42.0);
        assert_eq!(last, 42.0);
    }

    #[test]
    fn perf_metric_key_round_trip() {
        assert_eq!(PerfMetric::from_key('1'), Some(PerfMetric::Fletcher32));
        assert_eq!(PerfMetric::from_key('6'), Some(PerfMetric::DemoSigVerify));
        assert_eq!(PerfMetric::from_key('7'), None);
    }

    #[test]
    fn load_attest_rows_tolerates_missing_file() {
        let tmp = std::env::temp_dir().join("proteus_tui_test_missing");
        let rows = load_attest_rows(&tmp.join("nope.jsonl")).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn load_perf_rows_skips_garbage_lines() {
        let dir = tempdir_for_test("proteus_tui_perf");
        let p = dir.join("perf.jsonl");
        fs::write(
            &p,
            "{\"ts_unix\":1,\"fletcher32_ns\":10}\n\
             not-json\n\
             {\"ts_unix\":2,\"fletcher32_ns\":20}\n",
        )
        .unwrap();
        let rows = load_perf_rows(&p).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].fletcher32_ns, 10.0);
        assert_eq!(rows[1].fletcher32_ns, 20.0);
    }

    #[test]
    fn load_attest_rows_extracts_cosig_count_and_image_flag() {
        let dir = tempdir_for_test("proteus_tui_attest");
        let p = dir.join("attest.log.jsonl");
        fs::write(
            &p,
            "{\"cycle\":1,\"module\":\"m\",\"accepted\":true,\"synthesizer\":\"passthrough\",\"candidate_sha256\":\"deadbeef\",\"cosignatures\":[{\"signer_id\":\"a\",\"sig_ed25519\":\"00\"},{\"signer_id\":\"b\",\"sig_ed25519\":\"01\"}],\"image_sha256\":\"cafebabe\"}\n\
             {\"cycle\":2,\"module\":\"m\",\"accepted\":false,\"synthesizer\":\"passthrough\",\"candidate_sha256\":\"aaaa\"}\n",
        )
        .unwrap();
        let rows = load_attest_rows(&p).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].cosig_count, 2);
        assert!(rows[0].has_image);
        assert_eq!(rows[1].cosig_count, 0);
        assert!(!rows[1].has_image);
    }

    /// Create a unique temp dir for the calling test. Cleanup is best-
    /// effort via process exit; we don't need a crate dep just for tests.
    fn tempdir_for_test(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("proteus_tui_{}_{}", tag, nonce));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn headless_run_doesnt_crash_with_empty_root() {
        let dir = tempdir_for_test("headless_empty");
        // No files written — exercise the "everything missing" path.
        run_tui_with_options(&dir, Some(2)).unwrap();
    }

    #[test]
    fn headless_run_doesnt_crash_with_fixture_files() {
        let dir = tempdir_for_test("headless_fixture");
        fs::write(
            dir.join("scheduler.toml"),
            "[modules.lib]\npriority = 10\nmax_age_secs = 3600\ntarget_dir = \"x\"\n",
        )
        .unwrap();
        fs::write(
            dir.join("attest.log.jsonl"),
            "{\"cycle\":1,\"module\":\"lib\",\"accepted\":true,\"synthesizer\":\"passthrough\",\"candidate_sha256\":\"deadbeef\",\"ts_unix\":1000}\n",
        )
        .unwrap();
        fs::write(
            dir.join("perf.jsonl"),
            "{\"ts_unix\":1,\"fletcher32_ns\":10,\"feistel_mix_ns\":5,\"derive_byte_ns\":23,\"demohash_ns\":21,\"demosyscall_ns\":8,\"demosigverify_ns\":2000}\n",
        )
        .unwrap();
        run_tui_with_options(&dir, Some(5)).unwrap();
    }
}
