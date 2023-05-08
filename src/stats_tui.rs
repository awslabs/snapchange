//! TUI used for displaying global fuzzing statistics across all cores
#![allow(clippy::format_in_format_args)]

use anyhow::Result;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Span, Spans},
    widgets::{Axis, BarChart, Block, Borders, Chart, Dataset, GraphType, Paragraph, Wrap},
    widgets::{List, ListItem, Tabs},
    Frame, Terminal,
};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use tui_logger::TuiWidgetState;

use std::io::{self, Stdout};
use std::path::PathBuf;

use crate::stats::GlobalStats;
use crate::try_u64;

/// Titles for the various tabs in the TUI
const TAB_TITLES: &[&str] = &["Main", "Crashes", "Coverage", "Log"];

/// The tabs used in the TUI used to translate the `tab_index`
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, TryFromPrimitive, IntoPrimitive)]
#[repr(usize)]
#[allow(clippy::missing_docs_in_private_items)]
enum TuiTab {
    Main,
    Crashes,
    Coverage,
    Log,
}

/// Data used to draw the TUI
pub struct StatsApp<'a> {
    /// Performance stats
    perf_stats: &'a [(&'a str, u64)],

    /// Coverage stats (number of iterations, number of coverage hit)
    cov_stats: &'a [(u64, u64)],

    /// Number of VmExits found by the fuzzers
    vmexits: &'a [(&'static str, u64)],

    /// Table of generic stats from the fuzzers
    general: &'a GlobalStats,

    /// List of symbols roughly in order of when they were seen by the fuzzers
    coverage_timeline: &'a [String],

    /// Crash directory for listing crashes
    crash_dir: &'a PathBuf,

    /// Current tab index
    tab_index: usize,

    /// Locations that, if hit, could uncover the most new coverage
    coverage_blockers: &'a [String],

    /// Current state of the logger to know which types of messages to display
    log_state: &'a mut TuiWidgetState,
}

impl<'a> StatsApp<'a> {
    /// Create a new [`StatsApp`]
    pub fn new(
        perf_stats: &'a [(&'a str, u64)],
        cov_stats: &'a [(u64, u64)],
        vmexits: &'a [(&'static str, u64)],
        general: &'a GlobalStats,
        coverage_timeline: &'a [String],
        crash_dir: &'a PathBuf,
        tab_index: u8,
        coverage_blockers: &'a [String],
        log_state: &'a mut TuiWidgetState,
    ) -> StatsApp<'a> {
        StatsApp {
            perf_stats,
            cov_stats,
            vmexits,
            general,
            coverage_timeline,
            crash_dir,
            coverage_blockers,
            tab_index: usize::from(tab_index) % TAB_TITLES.len(),
            log_state,
        }
    }
}

/// Initialize the terminal for displaying the stats TUI
pub fn init_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    // Setup terminal for displaying stats TUI
    enable_raw_mode()?;

    // Restore the terminal before printing panic messages
    let orig_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        restore_terminal().unwrap();
        orig_panic_hook(panic);
    }));

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

/// Restore the state of the terminal
// pub fn restore_terminal(mut terminal: Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
pub fn restore_terminal() -> Result<()> {
    // restore terminal
    disable_raw_mode()?;

    execute!(
        std::io::stdout(),
        // terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;

    // terminal.show_cursor()?;

    Ok(())
}

/// Draw the `main` tab
fn draw_main<B: Backend>(f: &mut Frame<B>, app: &StatsApp, chunk: Rect) {
    // Super basic testing showed laptop horizontal terminal width is ~3x the height
    let is_horizontal_rect = chunk.width / chunk.height < 3;

    let chunks = if is_horizontal_rect {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(6),
                    Constraint::Percentage(30),
                    Constraint::Percentage(23),
                    Constraint::Percentage(25),
                    Constraint::Percentage(10),
                ]
                .as_ref(),
            )
            .split(chunk)
    } else {
        // For a horizontal terminal, first split the terminal into horizontal chunks and
        // then split the second chunk into two halves
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(6),
                    Constraint::Percentage(35),
                    Constraint::Percentage(30),
                    Constraint::Percentage(20),
                ]
                .as_ref(),
            )
            .split(chunk);

        if let [general_stats_chunk, coverage_chunk, graph_chunk, coverage_timeline_chunk] =
            chunks[..]
        {
            // With these chunks allocated, split the second chunk in two vertically
            let graph_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .margin(0)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(graph_chunk);

            if let [perf_chunk, vmexit_chunk] = graph_chunks[..] {
                vec![
                    general_stats_chunk,
                    coverage_chunk,
                    perf_chunk,
                    vmexit_chunk,
                    coverage_timeline_chunk,
                ]
            } else {
                // Not able to allocate chunks properly. Give a default vec to display a
                // usage message
                Vec::new()
            }
        } else {
            // Not able to allocate chunks properly. Give a default vec to display a
            // usage message
            Vec::new()
        }
    };

    if let [general_stats_chunk, coverage_chunk, perf_chunk, vmexit_chunk, coverage_timeline_chunk] =
        chunks[..]
    {
        let cov_stats = app
            .cov_stats
            .iter()
            .map(|(x, y)| {
                #[allow(clippy::cast_precision_loss)]
                (*x as f64, *y as f64)
            })
            .collect::<Vec<_>>();

        let datasets = vec![Dataset::default()
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::Yellow))
            .graph_type(GraphType::Line)
            .data(&cov_stats)];

        // log::info!("Cov: {cov_stats:#x?}");

        let (num_fuzz_cases, most_cov) = cov_stats.iter().last().unwrap_or(&(0.0, 0.0));

        // most_cov       = (most_cov * 1.05).round();
        // num_fuzz_cases = (num_fuzz_cases * 1.05).round();

        let coverage = Chart::new(datasets)
            .block(
                Block::default()
                    .title(Span::styled(
                        "Coverage",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .x_axis(
                Axis::default()
                    .title("Fuzz cases")
                    .style(Style::default().fg(Color::Gray))
                    .labels(vec![
                        Span::raw("0"),
                        Span::raw(format!("{}", (num_fuzz_cases * 0.25).round())),
                        Span::raw(format!("{}", (num_fuzz_cases * 0.5).round())),
                        Span::raw(format!("{}", (num_fuzz_cases * 0.75).round())),
                        Span::raw(format!("{num_fuzz_cases}")),
                    ])
                    .bounds([0.0, *num_fuzz_cases]),
            )
            .y_axis(
                Axis::default()
                    .title("Blocks")
                    .style(Style::default().fg(Color::Gray))
                    .labels(vec![
                        Span::raw(format!("{}", (most_cov * 0.0).round())),
                        Span::raw(format!("{}", (most_cov * 0.25).round())),
                        Span::raw(format!("{}", (most_cov * 0.5).round())),
                        Span::raw(format!("{}", (most_cov * 0.75).round())),
                        Span::raw(format!("{}", (most_cov * 1.05).round())),
                    ])
                    .bounds([most_cov * 0.0, most_cov * 1.05]),
            );
        f.render_widget(coverage, coverage_chunk);

        // Get the longest name of the stats
        let longest_name = app
            .perf_stats
            .iter()
            .map(|(name, _val)| name.len())
            .max()
            .unwrap_or(0);

        // Auto set the bar width to try and fit all bars on screen if possible
        #[allow(clippy::cast_possible_truncation)]
        let bar_width = std::cmp::min(
            longest_name as u16,
            perf_chunk
                .width
                .checked_div(app.perf_stats.len() as u16)
                .unwrap_or(1),
        );

        // Draw the bar chart
        let perf_stats = BarChart::default()
            .block(
                Block::default()
                    .title(Span::styled(
                        "Performance Stats (%)",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .data(app.perf_stats)
            .bar_width(bar_width)
            .bar_style(Style::default().fg(Color::Yellow))
            .value_style(Style::default().fg(Color::Black).bg(Color::Yellow));
        f.render_widget(perf_stats, perf_chunk);

        // Get the longest name of the stats
        let longest_name = app
            .vmexits
            .iter()
            .map(|(name, _val)| name.len())
            .max()
            .unwrap_or(3);

        // Auto set the bar width to try and fit all bars on screen if possible
        #[allow(clippy::cast_possible_truncation)]
        let bar_width = std::cmp::min(
            longest_name as u16,
            vmexit_chunk.width / (app.vmexits.len() + 1) as u16,
        );

        // Draw the bar chart
        let vmexits = BarChart::default()
            .block(
                Block::default()
                    .title(Span::styled(
                        "VmExits (%)",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL),
            )
            .data(app.vmexits)
            .bar_width(bar_width)
            .bar_style(Style::default().fg(Color::Yellow))
            .value_style(Style::default().fg(Color::Black).bg(Color::Yellow));
        f.render_widget(vmexits, vmexit_chunk);

        let general = app.general;
        let mut stats = String::new();

        let last_cov_elapsed = general.last_coverage;
        let last_cov_seconds = last_cov_elapsed % 60;
        let last_cov_minutes = (last_cov_elapsed / 60) % 60;
        let last_cov_hours = last_cov_elapsed / (60 * 60);

        let line = format!(
            "{} | {} | {}",
            format!("{:>10}: {:>10}", "Time", general.time),
            format!(
                "{:>10}: {:22} ({:8.2} per/core)",
                "Exec/sec",
                general.exec_per_sec,
                general.exec_per_sec / std::cmp::max(1, try_u64!(general.alive)),
            ),
            format!(
                "{:>10}: {:10} (last seen {last_cov_hours:02}:{last_cov_minutes:02}:{last_cov_seconds:02})",
                "Coverage", general.coverage, 
            )
        );
        stats.push_str(&line);
        stats.push('\n');

        let line = format!(
            "{} | {} | {}",
            format!("{:>10}: {:10}", "Iters", general.iterations),
            format!("{:>10}: {:42}", "Corpus", general.corpus),
            format!("{:>10}: {:10}", "Crashes", general.crashes),
        );
        stats.push_str(&line);
        stats.push('\n');

        let line = format!(
            "{} | {} | {} | {}",
            format!("{:>10}: {:10}", "Timeouts", general.timeouts),
            format!("{:>10}: {:11}", "Cov. Left", general.coverage_left),
            format!("{:>17}: {:8}", "Dirty Pages / Iter", general.dirty_pages),
            if cfg!(feature = "redqueen") {
                format!(
                    "{:>10}: {} | Dead {} | Redqueen {}",
                    "Alive",
                    general.alive,
                    general.dead.len(),
                    general.in_redqueen.len()
                )
            } else {
                format!(
                    "{:>10}: {} | Dead {}",
                    "Alive",
                    general.alive,
                    general.dead.len(),
                )
            }
        );

        stats.push_str(&line);
        stats.push('\n');

        let paragraph = Paragraph::new(stats).alignment(Alignment::Left).block(
            Block::default()
                .title(Span::styled(
                    "General Stats",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        );
        f.render_widget(paragraph, general_stats_chunk);

        let list_items: Vec<_> = app
            .coverage_timeline
            .iter()
            .rev()
            .take(coverage_timeline_chunk.height as usize)
            .map(|x| ListItem::new(Span::raw(x)))
            .collect();

        let list = List::new(list_items).block(
            Block::default()
                .title(Span::styled(
                    "Recently seen coverage",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL),
        );

        f.render_widget(list, coverage_timeline_chunk);
    } else {
        let text = "ERROR: Invalid number of chunks found";

        let paragraph = Paragraph::new(Span::styled(
            text,
            Style::default().add_modifier(Modifier::SLOW_BLINK),
        ))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
        f.render_widget(paragraph, chunks[0]);
    }
}

/// Draw the `log` tab
fn draw_log<B: Backend>(f: &mut Frame<B>, app: &StatsApp, chunk: Rect) {
    let tui_smart_widget = tui_logger::TuiLoggerSmartWidget::default()
        .style_error(Style::default().fg(Color::Red))
        .style_debug(Style::default().fg(Color::Green))
        .style_warn(Style::default().fg(Color::Yellow))
        .style_trace(Style::default().fg(Color::Magenta))
        .style_info(Style::default().fg(Color::Cyan))
        .output_separator(':')
        .output_timestamp(Some("%H:%M:%S".to_string()))
        .output_level(Some(tui_logger::TuiLoggerLevelOutput::Abbreviated))
        .output_target(true)
        .output_file(true)
        .output_line(true)
        .state(app.log_state);

    f.render_widget(tui_smart_widget, chunk);
}

/// Draw the `coverage` tab
fn draw_coverage<B: Backend>(f: &mut Frame<B>, app: &StatsApp, chunk: Rect) {
    let blockers: Vec<_> = app
        .coverage_blockers
        .iter()
        .map(|x| ListItem::new(Span::raw(x)))
        .collect();

    let blockers = List::new(blockers).block(
        Block::default()
            .title(Span::styled(
                "Coverage blockers",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL),
    );

    f.render_widget(blockers, chunk);
}

/// Recursively search the given path for other directories. Returns `true` if the directory
/// has file children and `false` if it only has other directories.
fn get_subdirs(path: &PathBuf, crashes: &mut Vec<String>) -> bool {
    let mut has_file_children = false;

    if let Ok(crash_entries) = std::fs::read_dir(path) {
        for file in crash_entries {
            if let Ok(file) = file {
                if !file.path().is_dir() {
                    has_file_children = true;
                    continue;
                }

                let has_files = get_subdirs(&file.path(), crashes);
                if has_files {
                    crashes.push(file.path().to_str().unwrap().to_string());
                }
            }
        }
    }

    has_file_children
}

/// Draw the `crashes` tab
fn draw_crashes<B: Backend>(f: &mut Frame<B>, app: &StatsApp, chunk: Rect) {
    let mut crashes = Vec::new();
    get_subdirs(app.crash_dir, &mut crashes);
    crashes.sort();

    // Remove the crash_dir prefix from the found crash dirs
    let crash_dir_str = format!("{}/", app.crash_dir.to_str().unwrap());
    crashes
        .iter_mut()
        .for_each(|path| *path = path.replace(&crash_dir_str, ""));

    // Create a ListItem for each crash dir
    let crashes: Vec<_> = crashes
        .iter()
        .map(|x| ListItem::new(Span::raw(x)))
        .collect();

    let found_crashes = List::new(crashes).block(
        Block::default()
            .title(Span::styled(
                "Found crashes",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL),
    );

    f.render_widget(found_crashes, chunk);
}

/// Draw the usage of the TUI into the given [`Rect`]
fn draw_usage<B: Backend>(f: &mut Frame<B>, app: &StatsApp, chunk: Rect) {
    // Draw the usage chunk
    let mut text = vec![
        Spans::from("Usage:"),
        Spans::from("[q] quit | [Left/Right][h/l] Switch tabs"),
    ];

    if matches!(TuiTab::try_from(app.tab_index).unwrap(), TuiTab::Log) {
        text.push(Spans::from("[H/L] Increase/Decrease highlighted log level"));
        text.push(Spans::from("[J/K] Switch log level up/down"));
    }

    let paragraph = Paragraph::new(text).alignment(Alignment::Center);

    f.render_widget(paragraph, chunk);
}

/// Draw the tabs into the given [`Rect`]
fn draw_tabs<B: Backend>(f: &mut Frame<B>, app: &StatsApp, chunk: Rect) {
    let spans: Vec<_> = TAB_TITLES
        .iter()
        .map(|x| Spans::from(Span::from(*x)))
        .collect();

    let tabs = Tabs::new(spans)
        .block(Block::default().borders(Borders::ALL).title("Tabs"))
        .select(app.tab_index)
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::Black),
        );
    f.render_widget(tabs, chunk);
}

/// Draw the given [`StatsApp`] into the provided [`Frame`]
pub fn ui<B: Backend>(f: &mut Frame<B>, app: &StatsApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(0)
        .constraints([Constraint::Length(4), Constraint::Percentage(100)].as_ref())
        .split(f.size());

    if let [header_chunk, main_chunk] = chunks[..] {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .margin(0)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(header_chunk);

        if let [usage_chunk, tab_chunk] = chunks[..] {
            draw_usage(f, app, usage_chunk);
            draw_tabs(f, app, tab_chunk);
        }

        match TuiTab::try_from(app.tab_index).unwrap() {
            TuiTab::Log => draw_log(f, app, main_chunk),
            TuiTab::Coverage => draw_coverage(f, app, main_chunk),
            TuiTab::Crashes => draw_crashes(f, app, main_chunk),
            TuiTab::Main => draw_main(f, app, main_chunk),
        }
    } else {
        let text = "ERROR: Invalid number of chunks found";

        let paragraph = Paragraph::new(Span::styled(
            text,
            Style::default().add_modifier(Modifier::SLOW_BLINK),
        ))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
        f.render_widget(paragraph, chunks[0]);
    }
}
