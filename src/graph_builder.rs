//! Builds a fully resolved in-memory graph from a [`ParsedDataset`].
//!
//! Every node (User/Group/Computer/Domain/GPO/OU) becomes a [`GNode`].
//! Every relationship (MemberOf, ACE rights, AdminTo, HasSession, etc.)
//! becomes a directed [`GEdge`].  All lookups are O(1) via HashMaps.

use std::collections::HashMap;

use crate::ad::PropertyAccess;

use crate::ParsedDataset;

// Node

#[derive(Debug, Clone)]
pub struct GNode {
    pub id:           String,
    pub name:         String,
    pub kind:         NodeKind,
    pub enabled:      bool,
    pub high_value:   bool,
    pub admin_count:  bool,
    pub domain_sid:   Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    User, Group, Computer, Domain, Gpo, Ou, Container, Adcs,
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            NodeKind::User      => "User",
            NodeKind::Group     => "Group",
            NodeKind::Computer  => "Computer",
            NodeKind::Domain    => "Domain",
            NodeKind::Gpo       => "GPO",
            NodeKind::Ou        => "OU",
            NodeKind::Container => "Container",
            NodeKind::Adcs      => "ADCS",
        })
    }
}

// Edge

#[derive(Debug, Clone)]
pub struct GEdge {
    pub source: String,
    pub target: String,
    pub kind:   String,
}

impl GEdge {
    /// True for edges that represent privilege escalation paths.
    pub fn is_attack_edge(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "GenericAll" | "GenericWrite" | "WriteDacl" | "WriteOwner" | "Owns"
            | "AllExtendedRights" | "ForceChangePassword" | "AddMember"
            | "AddSelf" | "WriteSPN" | "AddKeyCredentialLink"
            | "ReadLAPSPassword" | "ReadGMSAPassword"
            | "DCSync" | "GetChanges" | "GetChangesAll"
            | "AdminTo" | "HasSession"
            | "CanRDP" | "CanPSRemote" | "ExecuteDCOM"
            | "AllowedToDelegate" | "AllowedToAct"
        )
    }

    /// ANSI colour for this edge kind.
    pub fn color_code(&self) -> &'static str {
        match self.kind.as_str() {
            "MemberOf" | "Contains" => "\x1b[34m",      // blue
            "AdminTo" | "HasSession" => "\x1b[33m",     // yellow
            "GenericAll" | "Owns"    => "\x1b[31m",     // red
            "WriteDacl" | "WriteOwner" | "GenericWrite" => "\x1b[91m", // bright red
            "ForceChangePassword" | "DCSync" => "\x1b[31;1m",         // bold red
            "AddMember" | "AddSelf"  => "\x1b[35m",    // magenta
            "AllExtendedRights"      => "\x1b[91m",    // bright red
            "ReadLAPSPassword" | "ReadGMSAPassword" => "\x1b[33;1m",  // bright yellow
            "WriteSPN" | "AddKeyCredentialLink"     => "\x1b[95m",    // bright magenta
            "CanRDP" | "CanPSRemote" | "ExecuteDCOM" => "\x1b[36m",  // cyan
            "AllowedToDelegate" | "AllowedToAct"    => "\x1b[93m",   // bright yellow
            _                        => "\x1b[37m",    // white
        }
    }
}

// Graph

pub struct Graph {
    pub nodes:       HashMap<String, GNode>,         // id → node
    pub edges_from:  HashMap<String, Vec<GEdge>>,    // source id → outgoing edges
    pub edges_to:    HashMap<String, Vec<GEdge>>,    // target id → incoming edges
    /// name (uppercase) → matching node ids, for case-insensitive name lookup
    name_index:     HashMap<String, Vec<String>>,
}

impl Graph {
    /// Find a node by exact object-id or by name (case-insensitive).
    pub fn find(&self, query: &str) -> Option<&GNode> {
        self.find_all(query).into_iter().next()
    }

    /// Find all nodes matching an exact object-id or a case-insensitive name.
    pub fn find_all(&self, query: &str) -> Vec<&GNode> {
        if let Some(n) = self.nodes.get(query) {
            return vec![n];
        }

        let mut matches = Vec::new();
        let key = query.to_uppercase();

        if let Some(ids) = self.name_index.get(&key) {
            matches.extend(ids.iter().filter_map(|id| self.nodes.get(id)));
        }

        let short_key = query.split('@').next().unwrap_or(query).to_uppercase();
        if short_key != key {
            if let Some(ids) = self.name_index.get(&short_key) {
                for id in ids {
                    if let Some(node) = self.nodes.get(id) {
                        if !matches.iter().any(|existing| existing.id == node.id) {
                            matches.push(node);
                        }
                    }
                }
            }
        }

        matches
    }

    pub fn outgoing(&self, id: &str) -> &[GEdge] {
        self.edges_from.get(id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn incoming(&self, id: &str) -> &[GEdge] {
        self.edges_to.get(id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn node(&self, id: &str) -> Option<&GNode> {
        self.nodes.get(id)
    }

    pub fn all_nodes(&self) -> impl Iterator<Item = &GNode> {
        self.nodes.values()
    }

    pub fn node_count(&self) -> usize { self.nodes.len() }
    pub fn edge_count(&self) -> usize {
        self.edges_from.values().map(|v| v.len()).sum()
    }
}

// Builder

pub fn build(dataset: &ParsedDataset) -> Graph {
    let mut nodes:      HashMap<String, GNode>      = HashMap::new();
    let mut edges_from: HashMap<String, Vec<GEdge>> = HashMap::new();
    let mut edges_to:   HashMap<String, Vec<GEdge>> = HashMap::new();

    macro_rules! add_edge {
        ($src:expr, $tgt:expr, $kind:expr) => {{
            let e = GEdge {
                source: $src.to_string(),
                target: $tgt.to_string(),
                kind:   $kind.to_string(),
            };
            edges_from.entry($src.to_string()).or_default().push(e.clone());
            edges_to.entry($tgt.to_string()).or_default().push(e);
        }};
    }

// Users
    for u in &dataset.users {
        let name = u.name().to_string();
        nodes.insert(u.object_identifier.clone(), GNode {
            id:          u.object_identifier.clone(),
            name:        name.clone(),
            kind:        NodeKind::User,
            enabled:     u.enabled(),
            high_value:  u.properties.prop_bool("highvalue").unwrap_or(false),
            admin_count: u.admin_count(),
            domain_sid:  u.domain_sid().map(str::to_string),
        });
        for ace in &u.aces {
            add_edge!(ace.principal_sid, u.object_identifier, ace.right_name);
        }
        for d in &u.allowed_to_delegate {
            add_edge!(u.object_identifier, d, "AllowedToDelegate");
        }
    }

// Groups
    for g in &dataset.groups {
        let name = g.name().to_string();
        let hv = g.is_high_value_name()
            || g.admin_count()
            || g.properties.prop_bool("highvalue").unwrap_or(false);
        nodes.insert(g.object_identifier.clone(), GNode {
            id:          g.object_identifier.clone(),
            name:        name.clone(),
            kind:        NodeKind::Group,
            enabled:     true,
            high_value:  hv,
            admin_count: g.admin_count(),
            domain_sid:  g.domain_sid().map(str::to_string),
        });
        // MemberOf edges: member → MemberOf → group
        for m in &g.members {
            add_edge!(m.object_identifier, g.object_identifier, "MemberOf");
        }
        for ace in &g.aces {
            add_edge!(ace.principal_sid, g.object_identifier, ace.right_name);
        }
    }

// Computers
    for c in &dataset.computers {
        let name = c.name().to_string();
        nodes.insert(c.object_identifier.clone(), GNode {
            id:          c.object_identifier.clone(),
            name:        name.clone(),
            kind:        NodeKind::Computer,
            enabled:     c.enabled(),
            high_value:  c.properties.prop_bool("highvalue").unwrap_or(false),
            admin_count: false,
            domain_sid:  c.domain_sid().map(str::to_string),
        });
        for ace in &c.aces {
            add_edge!(ace.principal_sid, c.object_identifier, ace.right_name);
        }
        for p in &c.local_admins.results {
            add_edge!(p.object_identifier, c.object_identifier, "AdminTo");
        }
        for s in &c.sessions.results {
            add_edge!(c.object_identifier, s.user_sid, "HasSession");
        }
        for p in &c.remote_desktop_users.results {
            add_edge!(p.object_identifier, c.object_identifier, "CanRDP");
        }
        for p in &c.ps_remote_users.results {
            add_edge!(p.object_identifier, c.object_identifier, "CanPSRemote");
        }
        for p in &c.dcom_users.results {
            add_edge!(p.object_identifier, c.object_identifier, "ExecuteDCOM");
        }
        for p in &c.allowed_to_act {
            add_edge!(p.object_identifier, c.object_identifier, "AllowedToAct");
        }
    }

// Domains
    for d in &dataset.domains {
        nodes.insert(d.object_identifier.clone(), GNode {
            id:          d.object_identifier.clone(),
            name:        d.name().to_string(),
            kind:        NodeKind::Domain,
            enabled:     true,
            high_value:  true,
            admin_count: false,
            domain_sid:  Some(d.object_identifier.clone()),
        });
        for ace in &d.aces {
            add_edge!(ace.principal_sid, d.object_identifier, ace.right_name);
        }
    }

// GPOs
    for g in &dataset.gpos {
        nodes.insert(g.object_identifier.clone(), GNode {
            id: g.object_identifier.clone(), name: g.name().to_string(),
            kind: NodeKind::Gpo, enabled: true, high_value: false,
            admin_count: false, domain_sid: None,
        });
        for ace in &g.aces {
            add_edge!(ace.principal_sid, g.object_identifier, ace.right_name);
        }
    }

// OUs
    for o in &dataset.ous {
        nodes.insert(o.object_identifier.clone(), GNode {
            id: o.object_identifier.clone(), name: o.name().to_string(),
            kind: NodeKind::Ou, enabled: true, high_value: false,
            admin_count: false, domain_sid: None,
        });
        for ace in &o.aces {
            add_edge!(ace.principal_sid, o.object_identifier, ace.right_name);
        }
    }

// Containers
    for c in &dataset.containers {
        nodes.insert(c.object_identifier.clone(), GNode {
            id: c.object_identifier.clone(), name: c.name().to_string(),
            kind: NodeKind::Container, enabled: true, high_value: false,
            admin_count: false, domain_sid: None,
        });
    }

// ADCS objects (cert templates, CAs, etc.)
    for a in &dataset.adcs {
        let name = a.name().to_string();
        nodes.insert(a.object_identifier.clone(), GNode {
            id: a.object_identifier.clone(),
            name: name.clone(),
            kind: NodeKind::Adcs,
            enabled: true,
            high_value: a.properties.prop_bool("highvalue").unwrap_or(false),
            admin_count: false,
            domain_sid: a.properties.prop_str("domainsid").map(str::to_string),
        });
        for ace in &a.aces {
            add_edge!(ace.principal_sid, a.object_identifier, ace.right_name);
        }
    }

// Name index
    let mut name_index: HashMap<String, Vec<String>> = HashMap::new();
    for (id, n) in &nodes {
        let full_key = n.name.to_uppercase();
        name_index.entry(full_key.clone()).or_default().push(id.clone());

        if let Some(short_name) = n.name.split('@').next() {
            let short_key = short_name.to_uppercase();
            if short_key != full_key {
                name_index.entry(short_key).or_default().push(id.clone());
            }
        }
    }

    Graph { nodes, edges_from, edges_to, name_index }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_all_returns_every_name_match() {
        let mut nodes = HashMap::new();
        nodes.insert("id-1".to_string(), GNode {
            id: "id-1".to_string(),
            name: "john".to_string(),
            kind: NodeKind::User,
            enabled: true,
            high_value: false,
            admin_count: false,
            domain_sid: None,
        });
        nodes.insert("id-2".to_string(), GNode {
            id: "id-2".to_string(),
            name: "JOHN".to_string(),
            kind: NodeKind::User,
            enabled: true,
            high_value: false,
            admin_count: false,
            domain_sid: None,
        });

        let mut name_index: HashMap<String, Vec<String>> = HashMap::new();
        name_index.entry("JOHN".to_uppercase()).or_default().push("id-1".to_string());
        name_index.entry("JOHN".to_uppercase()).or_default().push("id-2".to_string());

        let graph = Graph {
            nodes,
            edges_from: HashMap::new(),
            edges_to: HashMap::new(),
            name_index,
        };

        let matches = graph.find_all("john");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|n| n.id == "id-1"));
        assert!(matches.iter().any(|n| n.id == "id-2"));
    }

    #[test]
    fn find_all_matches_short_name_without_domain() {
        let mut nodes = HashMap::new();
        nodes.insert("id-1".to_string(), GNode {
            id: "id-1".to_string(),
            name: "john@domain1".to_string(),
            kind: NodeKind::User,
            enabled: true,
            high_value: false,
            admin_count: false,
            domain_sid: None,
        });
        nodes.insert("id-2".to_string(), GNode {
            id: "id-2".to_string(),
            name: "john@domain2".to_string(),
            kind: NodeKind::User,
            enabled: true,
            high_value: false,
            admin_count: false,
            domain_sid: None,
        });

        let mut name_index: HashMap<String, Vec<String>> = HashMap::new();
        for (id, node) in &nodes {
            let full_key = node.name.to_uppercase();
            name_index.entry(full_key.clone()).or_default().push(id.clone());
            if let Some(short_name) = node.name.split('@').next() {
                let short_key = short_name.to_uppercase();
                if short_key != full_key {
                    name_index.entry(short_key).or_default().push(id.clone());
                }
            }
        }

        let graph = Graph {
            nodes,
            edges_from: HashMap::new(),
            edges_to: HashMap::new(),
            name_index,
        };

        let matches = graph.find_all("john");
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|n| n.id == "id-1"));
        assert!(matches.iter().any(|n| n.id == "id-2"));
    }
}
