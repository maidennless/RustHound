//! # rusthound-tui
//!
//! ```text
//! rusthound-tui ingest   <zip>                  – parse + summarise
//! rusthound-tui analyze  <zip>                  – deep attack analysis
//! rusthound-tui tree     <zip> [--from NAME]    – attack-path tree
//! rusthound-tui paths    <zip> [--from NAME]    – BFS paths to Tier Zero
//! rusthound-tui tui      <zip>                  – interactive terminal UI
//! ```

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use rusthound_tui::{
    analysis,
    graph_builder,
    parse_path,
    summarize,
    tree_view::{self, TreeConfig},
    tui,
};

// CLI definition

#[derive(Parser)]
#[command(
    name    = "rusthound-tui",
    about   = "RustHound TUI — SharpHound collection ingester and explorer",
    version = env!("CARGO_PKG_VERSION"),
    after_help = "\
EXAMPLES:
  # Quick summary
  rusthound-tui ingest collection.zip

  # Deep attack-path analysis
  rusthound-tui analyze collection.zip

  # Attack-path tree from a specific user (depth 4, attack edges only)
  rusthound-tui tree collection.zip --from \"ALFRED@TOMBWATCHER.HTB\" --depth 4 --attack

  # All BFS paths to Tier Zero from a node
  rusthound-tui paths collection.zip --from \"ALFRED@TOMBWATCHER.HTB\"

  # Show all Tier Zero objects
  rusthound-tui tree collection.zip --tier-zero

  # Full interactive TUI
  rusthound-tui tui collection.zip
"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse a SharpHound-CE ZIP and print object counts.
    Ingest {
        /// ZIP archive, JSON file, or directory of SharpHound JSON files.
        path: PathBuf,
    },

    /// Deep in-memory attack-path analysis.
    Analyze {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },

    /// Print an attack-path tree rooted at a node.
    Tree {
        path: PathBuf,
        /// Starting node — name or object ID (case-insensitive).
        #[arg(long, short)]
        from: Option<String>,
        /// Tree depth (default 3).
        #[arg(long, short, default_value_t = 3)]
        depth: usize,
        /// Only show attack edges (hide MemberOf/Contains).
        #[arg(long, short)]
        attack: bool,
        /// Max children to show per node before truncating.
        #[arg(long, default_value_t = 25)]
        max_children: usize,
        /// List all Tier Zero / high-value objects instead of a tree.
        #[arg(long)]
        tier_zero: bool,
    },

    /// Find shortest BFS attack paths from a node to Tier Zero targets.
    Paths {
        path: PathBuf,
        #[arg(long, short)]
        from: String,
        /// Maximum number of paths to show (default 20).
        #[arg(long, default_value_t = 20)]
        max: usize,
    },

    /// Launch the interactive terminal UI (ratatui TUI).
    Tui {
        path: PathBuf,
    },
}

// Entry point

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {

// ingest
        Commands::Ingest { path } => {
            let dataset = parse_path(&path)?;
            let summary = summarize(&dataset);

            println!("Files: {}", dataset.files_seen.join(", "));
            println!();
            println!("╔══════════════════════════════════════╗");
            println!("║   BloodHound CE Ingest Summary       ║");
            println!("╚══════════════════════════════════════╝");
            println!("  Domains:    {:>4}  {:?}", summary.domains, summary.domain_names);
            println!("  Users:      {:>4}", summary.users);
            println!("  Groups:     {:>4}", summary.groups);
            println!("  Computers:  {:>4}", summary.computers);
            println!("  GPOs:       {:>4}", summary.gpos);
            println!("  OUs:        {:>4}", summary.ous);
            println!("  Containers: {:>4}", summary.containers);
            println!("  ─────────────────────────────────────");
            println!("  Total:      {:>4}", dataset.total_objects());
            println!("  Total ACEs: {:>4}", summary.total_aces);
            println!();
            println!("  Kerberoastable users:             {:>3}", summary.kerberoastable_users);
            println!("  AS-REP roastable users:           {:>3}", summary.asrep_roastable_users);
            println!("  Unconstrained delegation systems: {:>3}", summary.unconstrained_delegation_computers);
            println!("  High-value / Tier-Zero groups:    {:>3}", summary.high_value_groups);
            println!("\n  (run `analyze` or `tui` for detailed attack paths)");
        }

// analyze
        Commands::Analyze { path, json } => {
            let dataset = parse_path(&path)?;
            let graph   = graph_builder::build(&dataset);
            let reports = analysis::analyze(&dataset, &graph);

            if json {
                let output = serde_json::to_string_pretty(&reports)?;
                println!("{output}");
                return Ok(());
            }

            for r in &reports {
                println!("\n╔══════════════════════════════════════════════════════╗");
                println!("║  Domain: {:<42} ║", r.domain_name);
                println!("╚══════════════════════════════════════════════════════╝");

                println!("\n  [Tier Zero / High-Value Groups]  ({} found)", r.tier_zero_groups.len());
                for g in &r.tier_zero_groups {
                    println!("    • {}  ({} members)", g.name, g.members);
                }

                println!("\n  [Kerberoastable Users]  ({} found)", r.kerberoastable.len());
                if r.kerberoastable.is_empty() { println!("    None"); }
                for u in &r.kerberoastable {
                    let adm = if u.admin_count { " [ADMINCOUNT]" } else { "" };
                    println!("    • {}{}", u.name, adm);
                    for s in &u.spns { println!("        spn: {s}"); }
                }

                println!("\n  [AS-REP Roastable]  ({} found)", r.asrep_roastable.len());
                if r.asrep_roastable.is_empty() { println!("    None"); }
                for u in &r.asrep_roastable {
                    println!("    • {}  [{}]", u.name, if u.enabled { "enabled" } else { "disabled" });
                }

                println!("\n  [Unconstrained Delegation]  ({} found)", r.unconstrained_computers.len());
                for c in &r.unconstrained_computers {
                    println!("    !  {}  ({})", c.name, c.os.as_deref().unwrap_or("unknown OS"));
                }

                println!("\n  [ACE Breakdown]  (total: {})", r.ace_summary.total);
                println!("    GenericAll:          {:>4}", r.ace_summary.generic_all);
                println!("    WriteDacl:           {:>4}", r.ace_summary.write_dacl);
                println!("    WriteOwner:          {:>4}", r.ace_summary.write_owner);
                println!("    Owns:                {:>4}", r.ace_summary.owns);
                println!("    GenericWrite:        {:>4}", r.ace_summary.generic_write);
                println!("    ForceChangePassword: {:>4}", r.ace_summary.force_change_pass);
                println!("    AddMember:           {:>4}", r.ace_summary.add_member);
                println!("    DCSync:              {:>4}", r.ace_summary.dcsync);

                println!("\n  [Graph Edges]");
                println!("    MemberOf:   {:>4}", r.member_edges.len());
                println!("    HasSession: {:>4}", r.session_edges.len());
                println!("    AdminTo:    {:>4}", r.admin_edges.len());
            }
        }

// tree
        Commands::Tree { path, from, depth, attack, max_children, tier_zero } => {
            let dataset = parse_path(&path)?;
            let graph   = graph_builder::build(&dataset);

            if tier_zero {
                tree_view::print_tier_zero(&graph);
                return Ok(());
            }

            let start_id = match from {
                Some(name) => {
                    let matches = graph.find_all(&name);
                    if matches.len() > 1 {
                        eprintln!("Multiple nodes matched '{name}':");
                        for n in matches {
                            eprintln!("  - {} [{}]", n.name, n.id);
                        }
                        anyhow::bail!("Please choose a more specific name or use the object ID.");
                    }

                    matches.first()
                        .map(|n| n.id.clone())
                        .ok_or_else(|| anyhow::anyhow!(
                            "Node '{}' not found.\nTry: rusthound-tui tree {} --tier-zero to list all nodes",
                            name, path.display()
                        ))?
                }
                None => {
                    // Default: find the first non-synthetic user that isn't NT AUTHORITY/…
                    graph.all_nodes()
                        .filter(|n| matches!(n.kind, graph_builder::NodeKind::User)
                            && !n.name.starts_with("NT AUTHORITY")
                            && !n.name.contains("S-1-5"))
                        .min_by_key(|n| n.name.clone())
                        .map(|n| n.id.clone())
                        .ok_or_else(|| anyhow::anyhow!("No users found in dataset"))?
                }
            };

            let cfg = TreeConfig {
                max_depth:    depth,
                attack_only:  attack,
                max_children,
                show_disabled: true,
            };

            println!();
            tree_view::print_tree(&graph, &start_id, &cfg);
            println!();
            println!("\x1b[2mGraph: {} nodes  {} edges — use --depth N for deeper traversal\x1b[0m",
                graph.node_count(), graph.edge_count());
        }

// paths
        Commands::Paths { path, from, max } => {
            let dataset = parse_path(&path)?;
            let graph   = graph_builder::build(&dataset);

            let matches = graph.find_all(&from);
            if matches.len() > 1 {
                eprintln!("Multiple nodes matched '{from}':");
                for n in matches {
                    eprintln!("  - {} [{}]", n.name, n.id);
                }
                anyhow::bail!("Please choose a more specific name or use the object ID.");
            }

            let start_id = matches.first()
                .map(|n| n.id.clone())
                .ok_or_else(|| anyhow::anyhow!("Node '{}' not found", from))?;

            println!();
            tree_view::print_attack_paths(&graph, &start_id, max);
        }

// tui
        Commands::Tui { path } => {
            let dataset = parse_path(&path)?;
            let graph   = graph_builder::build(&dataset);

            eprintln!("Building graph: {} nodes, {} edges",
                graph.node_count(), graph.edge_count());

            tui::run_tui(&graph)?;
        }
    }

    Ok(())
}
