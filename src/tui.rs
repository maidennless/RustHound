//! Interactive terminal UI built with `ratatui` + `crossterm`.
//!
//! Layout:
//! ┌─ Node List ─────┬─ Outgoing Edges ──────────────────────┐
//! │  [search]       │  MEMBEROF ──► DOMAIN USERS@...         │
//! │  > ALFRED@...   │  WRITESPN ──► HENRY@...                │
//! │    HENRY@...    ├─ Incoming Edges ──────────────────────  │
//! │    DC01@...     │  Owns ◄── DOMAIN USERS@...             │
//! └─────────────────┴───────────────────────────────────────┘
//! ─ [/] Search  [↑↓] Navigate  [Tab] Switch panel  [Enter] Inspect  [q] Quit ─

use std::io;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};

use crate::edges::EdgeKind;
use crate::graph_builder::{GNode, Graph, NodeKind};

// State

#[derive(PartialEq)]
enum Panel { NodeList, OutEdges, InEdges }

struct App<'g> {
    graph:          &'g Graph,
    all_node_ids:   Vec<String>,     // sorted list of all node ids
    filtered_ids:   Vec<String>,     // after search filter
    list_state:     ListState,
    out_state:      ListState,
    in_state:       ListState,
    search:         String,
    search_mode:    bool,
    active_panel:   Panel,
    // history for "go back" (press Backspace / Left)
    history:        Vec<String>,
}

impl<'g> App<'g> {
    fn new(graph: &'g Graph) -> Self {
        // Sort: high-value first, then by kind, then alphabetically
        let mut ids: Vec<String> = graph.all_nodes().map(|n| n.id.clone()).collect();
        ids.sort_by(|a, b| {
            let na = graph.node(a).unwrap();
            let nb = graph.node(b).unwrap();
            nb.high_value.cmp(&na.high_value)
                .then(na.kind.to_string().cmp(&nb.kind.to_string()))
                .then(na.name.cmp(&nb.name))
        });

        let mut s = App {
            graph,
            all_node_ids: ids.clone(),
            filtered_ids: ids,
            list_state:   ListState::default(),
            out_state:    ListState::default(),
            in_state:     ListState::default(),
            search:       String::new(),
            search_mode:  false,
            active_panel: Panel::NodeList,
            history:      Vec::new(),
        };
        if !s.filtered_ids.is_empty() {
            s.list_state.select(Some(0));
        }
        s
    }

    fn selected_node(&self) -> Option<&GNode> {
        let i = self.list_state.selected()?;
        let id = self.filtered_ids.get(i)?;
        self.graph.node(id)
    }

    fn apply_search(&mut self) {
        let q = self.search.to_uppercase();
        self.filtered_ids = self.all_node_ids
            .iter()
            .filter(|id| {
                if q.is_empty() { return true; }
                self.graph.node(id)
                    .map(|n| n.name.to_uppercase().contains(&q)
                          || n.kind.to_string().to_uppercase().contains(&q))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        self.list_state.select(if self.filtered_ids.is_empty() { None } else { Some(0) });
        self.out_state.select(Some(0));
        self.in_state.select(Some(0));
    }

    fn navigate_to(&mut self, id: &str) {
        if let Some(pos) = self.filtered_ids.iter().position(|x| x == id) {
            if let Some(cur) = self.list_state.selected() {
                if let Some(cur_id) = self.filtered_ids.get(cur) {
                    self.history.push(cur_id.clone());
                }
            }
            self.list_state.select(Some(pos));
            self.out_state.select(Some(0));
            self.in_state.select(Some(0));
            self.active_panel = Panel::NodeList;
        }
    }

    fn go_back(&mut self) {
        if let Some(prev) = self.history.pop() {
            if let Some(pos) = self.filtered_ids.iter().position(|x| *x == prev) {
                self.list_state.select(Some(pos));
                self.out_state.select(Some(0));
                self.in_state.select(Some(0));
            }
        }
    }

    fn scroll_up(&mut self) {
        match self.active_panel {
            Panel::NodeList => {
                let i = self.list_state.selected().unwrap_or(0);
                self.list_state.select(Some(i.saturating_sub(1)));
                self.out_state.select(Some(0));
                self.in_state.select(Some(0));
            }
            Panel::OutEdges => {
                let i = self.out_state.selected().unwrap_or(0);
                self.out_state.select(Some(i.saturating_sub(1)));
            }
            Panel::InEdges => {
                let i = self.in_state.selected().unwrap_or(0);
                self.in_state.select(Some(i.saturating_sub(1)));
            }
        }
    }

    fn scroll_down(&mut self) {
        match self.active_panel {
            Panel::NodeList => {
                let i = self.list_state.selected().unwrap_or(0);
                let max = self.filtered_ids.len().saturating_sub(1);
                self.list_state.select(Some((i + 1).min(max)));
                self.out_state.select(Some(0));
                self.in_state.select(Some(0));
            }
            Panel::OutEdges => {
                if let Some(node) = self.selected_node() {
                    let edges = self.graph.outgoing(&node.id);
                    let i = self.out_state.selected().unwrap_or(0);
                    self.out_state.select(Some((i + 1).min(edges.len().saturating_sub(1))));
                }
            }
            Panel::InEdges => {
                if let Some(node) = self.selected_node() {
                    let edges = self.graph.incoming(&node.id);
                    let i = self.in_state.selected().unwrap_or(0);
                    self.in_state.select(Some((i + 1).min(edges.len().saturating_sub(1))));
                }
            }
        }
    }

    fn enter_selected(&mut self) {
        match self.active_panel {
            Panel::NodeList => {
                self.active_panel = Panel::OutEdges;
            }
            Panel::OutEdges => {
                if let Some(node) = self.selected_node() {
                    let edges: Vec<_> = self.graph.outgoing(&node.id).to_vec();
                    if let Some(i) = self.out_state.selected() {
                        if let Some(e) = edges.get(i) {
                            let target = e.target.clone();
                            self.search.clear();
                            self.apply_search();
                            self.navigate_to(&target);
                        }
                    }
                }
            }
            Panel::InEdges => {
                if let Some(node) = self.selected_node() {
                    let edges: Vec<_> = self.graph.incoming(&node.id).to_vec();
                    if let Some(i) = self.in_state.selected() {
                        if let Some(e) = edges.get(i) {
                            let source = e.source.clone();
                            self.search.clear();
                            self.apply_search();
                            self.navigate_to(&source);
                        }
                    }
                }
            }
        }
    }
}

// Entry point

pub fn run_tui(graph: &Graph) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut app = App::new(graph);
    let result = run_loop(&mut term, &mut app);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    term.show_cursor()?;
    result
}

fn run_loop<B: ratatui::backend::Backend>(
    term: &mut Terminal<B>,
    app:  &mut App,
) -> io::Result<()> {
    loop {
        term.draw(|f| ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            // Global shortcuts
            match (key.modifiers, key.code) {
                (KeyModifiers::CONTROL, KeyCode::Char('c')) => return Ok(()),
                (_, KeyCode::Char('q')) if !app.search_mode => return Ok(()),
                _ => {}
            }

            if app.search_mode {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => {
                        app.search_mode = false;
                    }
                    KeyCode::Backspace => {
                        app.search.pop();
                        app.apply_search();
                    }
                    KeyCode::Char(c) => {
                        app.search.push(c);
                        app.apply_search();
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('/') => {
                        app.search_mode = true;
                    }
                    KeyCode::Esc => {
                        app.search.clear();
                        app.apply_search();
                        app.active_panel = Panel::NodeList;
                    }
                    KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                    KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
                    KeyCode::Tab => {
                        app.active_panel = match app.active_panel {
                            Panel::NodeList => Panel::OutEdges,
                            Panel::OutEdges => Panel::InEdges,
                            Panel::InEdges  => Panel::NodeList,
                        };
                    }
                    KeyCode::BackTab => {
                        app.active_panel = match app.active_panel {
                            Panel::NodeList => Panel::InEdges,
                            Panel::OutEdges => Panel::NodeList,
                            Panel::InEdges  => Panel::OutEdges,
                        };
                    }
                    KeyCode::Enter => app.enter_selected(),
                    KeyCode::Left | KeyCode::Backspace => {
                        if app.active_panel != Panel::NodeList {
                            app.active_panel = Panel::NodeList;
                        } else {
                            app.go_back();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

// UI rendering

fn ui(f: &mut Frame, app: &mut App) {
    let area = f.area();

    // Outer layout: main area + bottom status bar
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let main_area   = outer[0];
    let status_area = outer[1];

    // Main layout: left node list (30%) + right edge panels (70%)
    let main_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_area);

    let left_area  = main_cols[0];
    let right_area = main_cols[1];

    // Right split: outgoing (top 55%) + incoming (bottom 45%)
    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(right_area);

    let out_area = right_rows[0];
    let in_area  = right_rows[1];

    render_node_list(f, app, left_area);
    render_edge_list(f, app, out_area, true);
    render_edge_list(f, app, in_area,  false);
    render_status(f, app, status_area);
}

fn render_node_list(f: &mut Frame, app: &mut App, area: Rect) {
    let is_active = app.active_panel == Panel::NodeList;
    let border_style = if is_active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let search_line = if app.search_mode {
        format!("🔍 {}█", app.search)
    } else if !app.search.is_empty() {
        format!("🔍 {} ({} results)", app.search, app.filtered_ids.len())
    } else {
        format!("/ to search  ({} nodes)", app.filtered_ids.len())
    };

    let title = format!(" Nodes  {}", search_line);

    let items: Vec<ListItem> = app.filtered_ids.iter().map(|id| {
        let node = app.graph.node(id);
        let name  = node.map(|n| n.name.as_str()).unwrap_or(id);
        let kind  = node.map(|n| n.kind).unwrap_or(NodeKind::User);
        let hv    = node.map(|n| n.high_value).unwrap_or(false);
        let adm   = node.map(|n| n.admin_count).unwrap_or(false);

        let (icon, fg) = kind_style(kind, hv);

        let mut spans = vec![
            Span::styled(format!("{icon} "), Style::default().fg(fg)),
            Span::styled(name.to_string(), Style::default().fg(fg).add_modifier(Modifier::BOLD)),
        ];
        if adm {
            spans.push(Span::styled(" [adm]", Style::default().fg(Color::Magenta)));
        }
        if hv {
            spans.push(Span::styled(" *", Style::default().fg(Color::Yellow)));
        }
        ListItem::new(Line::from(spans))
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style))
        .highlight_style(Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn render_edge_list(f: &mut Frame, app: &mut App, area: Rect, outgoing: bool) {
    let is_active = app.active_panel == if outgoing { Panel::OutEdges } else { Panel::InEdges };
    let border_style = if is_active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let node = app.selected_node();
    let (node_name, edges) = match node {
        None => ("(none)".to_string(), vec![]),
        Some(n) => {
            let e = if outgoing {
                app.graph.outgoing(&n.id).to_vec()
            } else {
                app.graph.incoming(&n.id).to_vec()
            };
            (n.name.clone(), e)
        }
    };

    let title = if outgoing {
        format!(" Outgoing from {}  ({} edges) ", node_name, edges.len())
    } else {
        format!(" Incoming to {}  ({} edges) ", node_name, edges.len())
    };

    // Sort: attack edges first
    let mut sorted = edges.clone();
    sorted.sort_by_key(|e| if e.is_attack_edge() { 0u8 } else { 1u8 });

    let items: Vec<ListItem> = sorted.iter().map(|edge| {
        let other_id   = if outgoing { &edge.target } else { &edge.source };
        let other_node = app.graph.node(other_id);
        let other_name = other_node.map(|n| n.name.as_str()).unwrap_or(other_id.as_str());
        let other_hv   = other_node.map(|n| n.high_value).unwrap_or(false);
        let other_kind = other_node.map(|n| n.kind).unwrap_or(NodeKind::User);

        let (edge_col, edge_label) = edge_style(&edge.kind);
        let (icon, node_col) = kind_style(other_kind, other_hv);

        let arrow = if outgoing { "──►" } else { "◄──" };

        let mut spans = vec![
            Span::styled(
                format!("{edge_label} {arrow} "),
                Style::default().fg(edge_col).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{icon} {other_name}"),
                Style::default().fg(node_col),
            ),
        ];
        if other_hv {
            spans.push(Span::styled(" *", Style::default().fg(Color::Yellow)));
        }

        ListItem::new(Line::from(spans))
    }).collect();

    let state_ref = if outgoing { &mut app.out_state } else { &mut app.in_state };

    let list = List::new(items)
        .block(Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style))
        .highlight_style(Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, state_ref);
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let mode = if app.search_mode { "SEARCH" } else { "NORMAL" };
    let help = match app.active_panel {
        Panel::NodeList => "[/] Search  [↑↓/jk] Navigate  [Tab] Edges  [Enter] Select  [q] Quit",
        Panel::OutEdges => "[↑↓/jk] Scroll  [Enter] Go to target  [Tab] Incoming  [←/BS] Back",
        Panel::InEdges  => "[↑↓/jk] Scroll  [Enter] Go to source  [Tab] Node list  [←/BS] Back",
    };

    let graph_info = format!(
        "{} nodes  {} edges",
        app.graph.node_count(),
        app.graph.edge_count()
    );

    let line = Line::from(vec![
        Span::styled(format!(" {mode} "), Style::default()
            .bg(if app.search_mode { Color::Yellow } else { Color::Blue })
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(help, Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled(graph_info, Style::default().fg(Color::DarkGray)),
    ]);

    f.render_widget(Paragraph::new(line), area);
}

// Style helpers

fn kind_style(kind: NodeKind, high_value: bool) -> (&'static str, Color) {
    if high_value {
        return ("", Color::Yellow);
    }
    match kind {
        NodeKind::User      => ("", Color::Cyan),
        NodeKind::Group     => ("", Color::LightYellow),
        NodeKind::Computer  => ("", Color::Green),
        NodeKind::Domain    => ("", Color::Magenta),
        NodeKind::Gpo       => ("", Color::LightBlue),
        NodeKind::Ou        => ("", Color::Blue),
        NodeKind::Container => ("", Color::DarkGray),
        NodeKind::Adcs      => ("CRT", Color::Magenta),
    }
}

fn edge_style(kind: &EdgeKind) -> (Color, String) {
    let color = match kind {
        EdgeKind::MemberOf             => Color::Blue,
        EdgeKind::AdminTo              => Color::Yellow,
        EdgeKind::HasSession           => Color::Yellow,
        EdgeKind::GenericAll           => Color::Red,
        EdgeKind::Owns                 => Color::Red,
        EdgeKind::WriteDacl            => Color::LightRed,
        EdgeKind::WriteOwner           => Color::LightRed,
        EdgeKind::GenericWrite         => Color::LightRed,
        EdgeKind::ForceChangePassword  => Color::Red,
        EdgeKind::DCSync               => Color::Red,
        EdgeKind::AllExtendedRights    => Color::LightRed,
        EdgeKind::AddMember            => Color::Magenta,
        EdgeKind::AddSelf              => Color::Magenta,
        EdgeKind::WriteSPN             => Color::LightMagenta,
        EdgeKind::AddKeyCredentialLink => Color::LightMagenta,
        EdgeKind::ReadLAPSPassword     => Color::LightYellow,
        EdgeKind::ReadGMSAPassword     => Color::LightYellow,
        EdgeKind::CanRDP               => Color::Cyan,
        EdgeKind::CanPSRemote          => Color::Cyan,
        EdgeKind::ExecuteDCOM          => Color::Cyan,
        EdgeKind::AllowedToDelegate    => Color::LightYellow,
        EdgeKind::AllowedToAct         => Color::LightYellow,
        _                              => Color::White,
    };
    (color, kind.to_string())
}