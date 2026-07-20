//! Prints an attack-path tree rooted at a node, like:
//!
//! ```text
//! ALFRED@TOMBWATCHER.HTB [User]
//! ├── MemberOf ──► DOMAIN USERS@TOMBWATCHER.HTB [Group ★]
//! │   ├── Owns ──► DOMAIN ADMINS@TOMBWATCHER.HTB [Group ★]
//! │   └── GenericAll ──► ACCOUNT OPERATORS@TOMBWATCHER.HTB [Group ★]
//! └── WriteSPN ──► HENRY@TOMBWATCHER.HTB [User]
//!     └── HasSession ──► DC01.TOMBWATCHER.HTB [Computer]
//! ```

use std::collections::HashSet;
use std::collections::VecDeque;
use std::str::FromStr;

use crate::edges::EdgeKind;
use crate::graph_builder::{GEdge, GNode, Graph, NodeKind};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31;1m";
const YELLOW: &str = "\x1b[33;1m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const PURPLE: &str = "\x1b[35;1m";

pub struct TreeConfig {
    pub max_depth: usize,
    pub attack_only: bool,   // only show attack edges (hide MemberOf/Contains)
    pub max_children: usize, // truncate after this many children per node
    pub show_disabled: bool,
}

impl Default for TreeConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            attack_only: false,
            max_children: 20,
            show_disabled: true,
        }
    }
}

pub fn print_tree(graph: &Graph, root_id: &str, cfg: &TreeConfig) {
    let Some(root) = graph.node(root_id) else {
        eprintln!("{RED}Node not found: {root_id}{RESET}");
        return;
    };

    // Print root
    println!("{BOLD}{}{RESET} {}", root.name, kind_tag(root));
    if root.high_value {
        println!("  {YELLOW}! HIGH VALUE / TIER ZERO{RESET}");
    }

    let mut visited = HashSet::new();
    visited.insert(root_id.to_string());

    let edges = sorted_edges(graph.outgoing(root_id), cfg);
    let n = edges.len();
    for (i, edge) in edges.iter().enumerate() {
        let is_last = i + 1 == n;
        print_edge(graph, edge, is_last, "", 1, cfg, &mut visited);
    }
}

fn print_edge(
    graph: &Graph,
    edge: &GEdge,
    is_last: bool,
    prefix: &str,
    depth: usize,
    cfg: &TreeConfig,
    visited: &mut HashSet<String>,
) {
    let branch = if is_last { "└── " } else { "├── " };
    let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });

    let target_name = graph
        .node(&edge.target)
        .map(|n| n.name.as_str())
        .unwrap_or(&edge.target);

    let target_node = graph.node(&edge.target);
    let tag = target_node.map(kind_tag).unwrap_or_default();

    let edge_col = edge.color_code();
    let target_col = target_node.map(node_color).unwrap_or(RESET);
    let hv_marker = target_node
        .map(|n| {
            if n.high_value {
                format!(" {YELLOW}*{RESET}")
            } else {
                String::new()
            }
        })
        .unwrap_or_default();
    let cycle = if visited.contains(&edge.target) {
        format!(" {DIM}(↩ already shown){RESET}")
    } else {
        String::new()
    };

    println!(
        "{prefix}{branch}{edge_col}{edge_name}{RESET} ──► {target_col}{BOLD}{target_name}{RESET}{tag}{hv_marker}{cycle}",
        edge_name = edge.kind,
    );

    // Don't recurse into already-visited or if at max depth
    if depth >= cfg.max_depth || visited.contains(&edge.target) {
        return;
    }

    visited.insert(edge.target.clone());

    let children = sorted_edges(graph.outgoing(&edge.target), cfg);
    let truncated = children.len() > cfg.max_children;
    let show_n = children.len().min(cfg.max_children);

    for (i, child_edge) in children.iter().take(show_n).enumerate() {
        let last = i + 1 == show_n && !truncated;
        print_edge(
            graph,
            child_edge,
            last,
            &child_prefix,
            depth + 1,
            cfg,
            visited,
        );
    }

    if truncated {
        println!(
            "{child_prefix}└── {DIM}… and {} more edges{RESET}",
            children.len() - cfg.max_children
        );
    }
}

fn sorted_edges<'a>(edges: &'a [GEdge], cfg: &TreeConfig) -> Vec<&'a GEdge> {
    let mut v: Vec<&GEdge> = edges
        .iter()
        .filter(|e| !cfg.attack_only || e.is_attack_edge())
        .collect();

    // Attack edges first, then structural (MemberOf), then others
    v.sort_by_key(|e| {
        if e.is_attack_edge() {
            0u8
        } else if e.kind == EdgeKind::MemberOf {
            1u8
        } else {
            2u8
        }
    });
    v
}

// Paths to high-value targets

/// Print all shortest paths from `start_id` to any high-value node.
/// Uses BFS so paths are always shortest first.
pub fn print_attack_paths(graph: &Graph, start_id: &str, max_paths: usize) {
    let Some(start) = graph.node(start_id) else {
        eprintln!("{RED}Node not found: {start_id}{RESET}");
        return;
    };

    println!(
        "{BOLD}Attack paths from: {}{RESET} {}\n",
        start.name,
        kind_tag(start)
    );

    // BFS: find paths to high-value nodes
    let mut paths: Vec<Vec<(String, String)>> = Vec::new(); // Vec<(node_id, edge_kind)>
    let mut queue: VecDeque<Vec<(String, String)>> =
        VecDeque::from([vec![(start_id.to_string(), String::new())]]);
    let mut found_targets: HashSet<String> = HashSet::new();
    let mut visited_global: HashSet<String> = HashSet::new();
    visited_global.insert(start_id.to_string());

    while !queue.is_empty() && paths.len() < max_paths {
        let path = queue.pop_front().unwrap();
        let current_id = &path.last().unwrap().0;

        for edge in graph.outgoing(current_id) {
            if visited_global.contains(&edge.target) {
                continue;
            }

            let mut new_path = path.clone();
            new_path.push((edge.target.clone(), edge.kind.to_string()));

            if let Some(tgt) = graph.node(&edge.target) {
                if tgt.high_value && !found_targets.contains(&edge.target) {
                    found_targets.insert(edge.target.clone());
                    paths.push(new_path.clone());
                    if paths.len() >= max_paths {
                        break;
                    }
                }
            }

            if new_path.len() < 8 {
                // max path length
                visited_global.insert(edge.target.clone());
                queue.push_back(new_path);
            }
        }
    }

    if paths.is_empty() {
        println!("{DIM}No direct attack paths to high-value targets found within 7 hops.{RESET}");
        println!("{DIM}Try `tree` to explore all edges.{RESET}");
        return;
    }

    println!("{GREEN}Found {} attack path(s):{RESET}\n", paths.len());

    for (pi, path) in paths.iter().enumerate() {
        println!("{BOLD}Path {}:{RESET}", pi + 1);
        for (i, (node_id, edge_kind)) in path.iter().enumerate() {
            let node = graph.node(node_id);
            let name = node.map(|n| n.name.as_str()).unwrap_or(node_id);
            let tag = node.map(kind_tag).unwrap_or_default();
            let col = node.map(node_color).unwrap_or(RESET);
            let hv = node.map(|n| n.high_value).unwrap_or(false);

            if i == 0 {
                println!("  {col}{BOLD}{name}{RESET}{tag}");
            } else {
                // Find the edge between previous and this node
                let parsed_kind = EdgeKind::from_str(edge_kind).unwrap_or(EdgeKind::Unknown);
                let dummy = GEdge {
                    source: String::new(),
                    target: String::new(),
                    kind: parsed_kind,
                };
                let ecol = dummy.color_code();
                let hv_m = if hv {
                    format!(" {YELLOW}* HIGH VALUE{RESET}")
                } else {
                    String::new()
                };
                println!("  {DIM}│{RESET}");
                println!("  {ecol}{edge_kind}{RESET}");
                println!("  {col}{BOLD}{name}{RESET}{tag}{hv_m}");
            }
        }
        println!();
    }
}

/// Print all high-value (Tier Zero) nodes in the dataset.
pub fn print_tier_zero(graph: &Graph) {
    let mut tier_zero: Vec<&GNode> = graph.all_nodes().filter(|n| n.high_value).collect();
    tier_zero.sort_by(|a, b| {
        a.kind
            .to_string()
            .cmp(&b.kind.to_string())
            .then(a.name.cmp(&b.name))
    });

    println!(
        "{BOLD}{YELLOW}!  Tier Zero / High-Value Objects  ({} found){RESET}\n",
        tier_zero.len()
    );
    for n in tier_zero {
        let col = node_color(n);
        println!(
            "  {col}-{RESET} {BOLD}{}{RESET} {}  {DIM}[{}]{RESET}",
            n.name,
            kind_tag(n),
            n.domain_sid.as_deref().unwrap_or("")
        );
    }
}

// Helpers

fn kind_tag(n: &GNode) -> String {
    let ac = if n.admin_count {
        format!(" {PURPLE}[admincount]{RESET}")
    } else {
        String::new()
    };
    format!(" {DIM}[{}]{RESET}{ac}", n.kind)
}

fn node_color(n: &GNode) -> &'static str {
    if n.high_value {
        YELLOW
    } else {
        match n.kind {
            NodeKind::User => CYAN,
            NodeKind::Group => "\x1b[33m",
            NodeKind::Computer => "\x1b[32m",
            NodeKind::Domain => PURPLE,
            NodeKind::Adcs => "\x1b[35m",
            _ => RESET,
        }
    }
}
