//! In-memory analysis engine: answers common BloodHound attack-path
//! questions directly from a [`ParsedDataset`] without needing Neo4j.
//!
//! This is used in two places:
//! 1. The CLI's `analyze` subcommand (offline, fast, works anywhere)
//! 2. The API server when Neo4j hasn't been connected yet (graceful fallback)

use crate::ad::{AdcsKind, PropertyAccess};
use crate::edges::EdgeKind;
use crate::graph_builder::Graph;
use crate::ParsedDataset;

#[derive(Debug, serde::Serialize)]
pub struct AnalysisReport {
    pub domain_name: String,
    pub domain_sid: String,
    pub tier_zero_groups: Vec<TierZeroGroup>,
    pub kerberoastable: Vec<KerberoastableUser>,
    pub asrep_roastable: Vec<AsrepUser>,
    pub unconstrained_computers: Vec<UnconstrainedComputer>,
    pub ace_summary: AceSummary,
    pub member_edges: Vec<MemberEdge>,
    pub session_edges: Vec<SessionEdge>,
    pub admin_edges: Vec<AdminEdge>,
    pub esc1_findings: Vec<Esc1Finding>,
    pub esc4_findings: Vec<Esc4Finding>,
}

#[derive(Debug, serde::Serialize)]
pub struct TierZeroGroup {
    pub object_id: String,
    pub name: String,
    pub members: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct KerberoastableUser {
    pub object_id: String,
    pub name: String,
    pub admin_count: bool,
    pub pwd_last_set: Option<i64>,
    pub spns: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct AsrepUser {
    pub object_id: String,
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct UnconstrainedComputer {
    pub object_id: String,
    pub name: String,
    pub os: Option<String>,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct AceSummary {
    pub total: usize,
    pub generic_all: usize,
    pub write_dacl: usize,
    pub write_owner: usize,
    pub owns: usize,
    pub generic_write: usize,
    pub force_change_pass: usize,
    pub add_member: usize,
    pub dcsync: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct MemberEdge {
    pub member_id: String,
    pub member_type: String,
    pub group_id: String,
}

#[derive(Debug, serde::Serialize)]
pub struct SessionEdge {
    pub computer_id: String,
    pub user_sid: String,
}

#[derive(Debug, serde::Serialize)]
pub struct AdminEdge {
    pub principal_id: String,
    pub principal_type: String,
    pub computer_id: String,
}

/// A CertTemplate vulnerable to ESC1 (client-auth cert forgery), reachable
/// by a specific principal via a specific enrollment-granting right, and
/// published to a specific EnterpriseCA.
#[derive(Debug, serde::Serialize)]
pub struct Esc1Finding {
    pub template_object_id: String,
    pub template_name: String,
    pub ca_object_id: String,
    pub ca_name: String,
    pub principal_id: String,
    pub principal_right: String,
}

#[derive(Debug, serde::Serialize)]
pub struct Esc4Finding {
    pub template_object_id: String,
    pub template_name: String,
    pub ca_object_id: String,
    pub ca_name: String,
    pub principal_id: String,
    pub principal_right: String,
}

/// The single, authoritative ESC1 vulnerability condition for a CertTemplate.
/// Used both by per-domain reporting (`analyze`) and whole-graph marking
/// (`mark_adcs_vulnerabilities`), so the two views can never drift apart.
fn is_esc1_vulnerable_template(tpl: &crate::ad::AdcsObject) -> bool {
    tpl.enrollee_supplies_subject()
        && tpl.authentication_enabled()
        && !tpl.requires_manager_approval()
        && tpl.authorized_signatures_required().unwrap_or(0) == 0
}

/// Finds all ESC4 findings: a principal holds WriteDacl, WriteOwner,
/// GenericWrite, or GenericAll directly on a CertTemplate object, letting
/// them reconfigure it into an ESC1-exploitable state and enroll.
fn find_esc4_findings(
    d: &ParsedDataset,
    graph: &Graph,
    domain_sid: Option<&str>,
) -> Vec<Esc4Finding> {
    let mut findings = Vec::new();

    for tpl in d.adcs.iter().filter(|a| a.kind == AdcsKind::CertTemplate) {
        if let Some(sid) = domain_sid {
            let in_domain = tpl.domain_sid().map(|s| s == sid).unwrap_or(true);
            if !in_domain {
                continue;
            }
        }

        for pub_edge in graph.outgoing(&tpl.object_identifier) {
            if pub_edge.kind != EdgeKind::PublishedTo {
                continue;
            }
            let ca_id = &pub_edge.target;
            let ca_name = graph
                .node(ca_id)
                .map(|n| n.name.clone())
                .unwrap_or_else(|| ca_id.clone());

            for ace_edge in graph.incoming(&tpl.object_identifier) {
                if matches!(
                    ace_edge.kind,
                    EdgeKind::WriteDacl
                        | EdgeKind::WriteOwner
                        | EdgeKind::GenericWrite
                        | EdgeKind::GenericAll
                ) {
                    findings.push(Esc4Finding {
                        template_object_id: tpl.object_identifier.clone(),
                        template_name: tpl.name().to_string(),
                        ca_object_id: ca_id.clone(),
                        ca_name: ca_name.clone(),
                        principal_id: ace_edge.source.clone(),
                        principal_right: ace_edge.kind.to_string(),
                    });
                }
            }
        }
    }

    findings
}

/// Finds all ESC1 findings across `dataset`. If `domain_sid` is `Some`,
/// results are restricted to that domain (used by per-domain reporting).
/// If `None`, every domain's templates are considered (used for
/// whole-graph vulnerability marking).
fn find_esc1_findings(
    d: &ParsedDataset,
    graph: &Graph,
    domain_sid: Option<&str>,
) -> Vec<Esc1Finding> {
    let mut findings = Vec::new();

    for tpl in d.adcs.iter().filter(|a| a.kind == AdcsKind::CertTemplate) {
        if let Some(sid) = domain_sid {
            let in_domain = tpl.domain_sid().map(|s| s == sid).unwrap_or(true);
            if !in_domain {
                continue;
            }
        }

        if !is_esc1_vulnerable_template(tpl) {
            continue;
        }

        for pub_edge in graph.outgoing(&tpl.object_identifier) {
            if pub_edge.kind != EdgeKind::PublishedTo {
                continue;
            }
            let ca_id = &pub_edge.target;
            let ca_name = graph
                .node(ca_id)
                .map(|n| n.name.clone())
                .unwrap_or_else(|| ca_id.clone());

            for enroll_edge in graph.incoming(&tpl.object_identifier) {
                if matches!(
                    enroll_edge.kind,
                    EdgeKind::Enroll | EdgeKind::GenericAll | EdgeKind::AllExtendedRights
                ) {
                    findings.push(Esc1Finding {
                        template_object_id: tpl.object_identifier.clone(),
                        template_name: tpl.name().to_string(),
                        ca_object_id: ca_id.clone(),
                        ca_name: ca_name.clone(),
                        principal_id: enroll_edge.source.clone(),
                        principal_right: enroll_edge.kind.to_string(),
                    });
                }
            }
        }
    }

    findings
}

/// Marks confirmed ADCS vulnerabilities (currently: ESC1) directly on the
/// graph, so interactive views (tree/paths/tui) surface them automatically:
/// vulnerable CertTemplate nodes become `high_value`, which makes them
/// appear in Tier Zero listings and as BFS attack-path targets, with a
/// human-readable `vulnerability_note` explaining why.
///
/// Call this after `graph_builder::build()` and before handing the graph
/// to `tree_view` or `tui`.
pub fn mark_adcs_vulnerabilities(graph: &mut Graph, dataset: &ParsedDataset) {
    let esc1_findings = find_esc1_findings(dataset, graph, None);
    let esc4_findings = find_esc4_findings(dataset, graph, None);

    let mut notes: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for f in &esc1_findings {
        notes
            .entry(f.template_object_id.clone())
            .or_default()
            .push(format!(
                "ESC1: {} can enroll via {} (published to {})",
                f.principal_id, f.principal_right, f.ca_name
            ));
    }
    for f in &esc4_findings {
        notes
            .entry(f.template_object_id.clone())
            .or_default()
            .push(format!(
                "ESC4: {} can reconfigure template via {} (published to {})",
                f.principal_id, f.principal_right, f.ca_name
            ));
    }

    for (template_id, template_notes) in notes {
        if let Some(node) = graph.nodes.get_mut(&template_id) {
            node.high_value = true;
            node.vulnerability_note = Some(template_notes.join("; "));
        }
    }
}

pub fn analyze(d: &ParsedDataset, graph: &Graph) -> Vec<AnalysisReport> {
    d.domains
        .iter()
        .map(|dom| analyze_domain(d, graph, &dom.object_identifier, dom.name()))
        .collect()
}

fn analyze_domain(
    d: &ParsedDataset,
    graph: &Graph,
    domain_sid: &str,
    domain_name: &str,
) -> AnalysisReport {
    // Tier Zero groups
    let tier_zero_groups: Vec<TierZeroGroup> = d
        .groups
        .iter()
        .filter(|g| {
            g.domain_sid().map(|s| s == domain_sid).unwrap_or(true)
                && (g.is_high_value_name()
                    || g.admin_count()
                    || g.properties.prop_bool("highvalue").unwrap_or(false))
        })
        .map(|g| TierZeroGroup {
            object_id: g.object_identifier.clone(),
            name: g.name().to_string(),
            members: g.members.len(),
        })
        .collect();

    // Kerberoastable users
    let kerberoastable: Vec<KerberoastableUser> = d
        .users
        .iter()
        .filter(|u| {
            u.has_spn() && u.enabled() && u.domain_sid().map(|s| s == domain_sid).unwrap_or(true)
        })
        .map(|u| KerberoastableUser {
            object_id: u.object_identifier.clone(),
            name: u.name().to_string(),
            admin_count: u.admin_count(),
            pwd_last_set: u.pwd_last_set(),
            spns: u.properties.prop_str_vec("serviceprincipalnames"),
        })
        .collect();

    // AS-REP roastable users
    let asrep_roastable: Vec<AsrepUser> = d
        .users
        .iter()
        .filter(|u| u.dont_req_preauth() && u.domain_sid().map(|s| s == domain_sid).unwrap_or(true))
        .map(|u| AsrepUser {
            object_id: u.object_identifier.clone(),
            name: u.name().to_string(),
            enabled: u.enabled(),
        })
        .collect();

    // Unconstrained delegation computers
    let unconstrained_computers: Vec<UnconstrainedComputer> = d
        .computers
        .iter()
        .filter(|c| c.unconstrained_delegation() && c.enabled())
        .map(|c| UnconstrainedComputer {
            object_id: c.object_identifier.clone(),
            name: c.name().to_string(),
            os: c.operating_system().map(String::from),
        })
        .collect();

    // ACE summary — sourced from Graph edges, not re-scanned from ParsedDataset
    let mut ace_summary = AceSummary::default();
    for edges in graph.edges_from.values() {
        for e in edges {
            match e.kind {
                EdgeKind::GenericAll => {
                    ace_summary.total += 1;
                    ace_summary.generic_all += 1;
                }
                EdgeKind::WriteDacl => {
                    ace_summary.total += 1;
                    ace_summary.write_dacl += 1;
                }
                EdgeKind::WriteOwner => {
                    ace_summary.total += 1;
                    ace_summary.write_owner += 1;
                }
                EdgeKind::Owns => {
                    ace_summary.total += 1;
                    ace_summary.owns += 1;
                }
                EdgeKind::GenericWrite => {
                    ace_summary.total += 1;
                    ace_summary.generic_write += 1;
                }
                EdgeKind::ForceChangePassword => {
                    ace_summary.total += 1;
                    ace_summary.force_change_pass += 1;
                }
                EdgeKind::AddMember => {
                    ace_summary.total += 1;
                    ace_summary.add_member += 1;
                }
                EdgeKind::DCSync => {
                    ace_summary.total += 1;
                    ace_summary.dcsync += 1;
                }
                _ => {}
            }
        }
    }

    // Graph edges — sourced from Graph edges, not re-scanned from ParsedDataset
    let member_edges: Vec<MemberEdge> = graph
        .edges_from
        .values()
        .flat_map(|edges| edges.iter())
        .filter(|e| e.kind == EdgeKind::MemberOf)
        .map(|e| MemberEdge {
            member_id: e.source.clone(),
            member_type: graph
                .node(&e.source)
                .map(|n| n.kind.to_string())
                .unwrap_or_default(),
            group_id: e.target.clone(),
        })
        .collect();

    let session_edges: Vec<SessionEdge> = graph
        .edges_from
        .values()
        .flat_map(|edges| edges.iter())
        .filter(|e| e.kind == EdgeKind::HasSession)
        .map(|e| SessionEdge {
            computer_id: e.source.clone(),
            user_sid: e.target.clone(),
        })
        .collect();

    let admin_edges: Vec<AdminEdge> = graph
        .edges_from
        .values()
        .flat_map(|edges| edges.iter())
        .filter(|e| e.kind == EdgeKind::AdminTo)
        .map(|e| AdminEdge {
            principal_id: e.source.clone(),
            principal_type: graph
                .node(&e.source)
                .map(|n| n.kind.to_string())
                .unwrap_or_default(),
            computer_id: e.target.clone(),
        })
        .collect();

    let esc1_findings = find_esc1_findings(d, graph, Some(domain_sid));
    let esc4_findings = find_esc4_findings(d, graph, Some(domain_sid));

    AnalysisReport {
        domain_name: domain_name.to_string(),
        domain_sid: domain_sid.to_string(),
        tier_zero_groups,
        kerberoastable,
        asrep_roastable,
        unconstrained_computers,
        ace_summary,
        member_edges,
        session_edges,
        admin_edges,
        esc1_findings,
        esc4_findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ad::{Ace, AdDomain, AdcsObject, TypedPrincipal};
    use crate::graph_builder;

    fn vulnerable_template_dataset() -> ParsedDataset {
        let mut tpl_props = crate::ad::Properties::new();
        tpl_props.insert("name".to_string(), serde_json::json!("VulnTemplate"));
        tpl_props.insert(
            "enrolleesuppliessubject".to_string(),
            serde_json::json!(true),
        );
        tpl_props.insert("authenticationenabled".to_string(), serde_json::json!(true));
        tpl_props.insert(
            "requiresmanagerapproval".to_string(),
            serde_json::json!(false),
        );
        tpl_props.insert("authorizedsignatures".to_string(), serde_json::json!(0));

        let template = AdcsObject {
            object_identifier: "TEMPLATE-SID".to_string(),
            properties: tpl_props,
            aces: vec![Ace {
                right_name: "Enroll".to_string(),
                is_inherited: false,
                principal_sid: "ATTACKER-SID".to_string(),
                principal_type: "User".to_string(),
            }],
            enabled_cert_templates: vec![],
            is_deleted: false,
            is_acl_protected: false,
            kind: AdcsKind::CertTemplate,
        };

        let mut ca_props = crate::ad::Properties::new();
        ca_props.insert("name".to_string(), serde_json::json!("CORP-CA"));

        let ca = AdcsObject {
            object_identifier: "CA-SID".to_string(),
            properties: ca_props,
            aces: vec![],
            enabled_cert_templates: vec![TypedPrincipal {
                object_identifier: "TEMPLATE-SID".to_string(),
                object_type: "CertTemplate".to_string(),
            }],
            is_deleted: false,
            is_acl_protected: false,
            kind: AdcsKind::EnterpriseCa,
        };

        let domain = AdDomain {
            object_identifier: "DOMAIN-SID".to_string(),
            properties: {
                let mut p = crate::ad::Properties::new();
                p.insert("name".to_string(), serde_json::json!("TEST.LOCAL"));
                p
            },
            trusts: vec![],
            aces: vec![],
            links: vec![],
            child_objects: vec![],
            is_deleted: false,
            is_acl_protected: false,
        };

        let mut dataset = ParsedDataset::default();
        dataset.adcs.push(template);
        dataset.adcs.push(ca);
        dataset.domains.push(domain);
        dataset
    }

    #[test]
    fn detects_esc1_vulnerable_template() {
        let dataset = vulnerable_template_dataset();
        let graph = graph_builder::build(&dataset);
        let reports = analyze(&dataset, &graph);

        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert_eq!(report.esc1_findings.len(), 1);

        let finding = &report.esc1_findings[0];
        assert_eq!(finding.template_object_id, "TEMPLATE-SID");
        assert_eq!(finding.ca_object_id, "CA-SID");
        assert_eq!(finding.principal_id, "ATTACKER-SID");
        assert_eq!(finding.principal_right, "Enroll");
    }

    #[test]
    fn does_not_flag_template_missing_enrollee_supplies_subject() {
        let mut tpl_props = crate::ad::Properties::new();
        tpl_props.insert("name".to_string(), serde_json::json!("SafeTemplate"));
        tpl_props.insert(
            "enrolleesuppliessubject".to_string(),
            serde_json::json!(false),
        );
        tpl_props.insert("authenticationenabled".to_string(), serde_json::json!(true));
        tpl_props.insert(
            "requiresmanagerapproval".to_string(),
            serde_json::json!(false),
        );
        tpl_props.insert("authorizedsignatures".to_string(), serde_json::json!(0));

        let template = AdcsObject {
            object_identifier: "SAFE-TEMPLATE-SID".to_string(),
            properties: tpl_props,
            aces: vec![Ace {
                right_name: "Enroll".to_string(),
                is_inherited: false,
                principal_sid: "SOMEUSER-SID".to_string(),
                principal_type: "User".to_string(),
            }],
            enabled_cert_templates: vec![],
            is_deleted: false,
            is_acl_protected: false,
            kind: AdcsKind::CertTemplate,
        };

        let ca = AdcsObject {
            object_identifier: "CA-SID".to_string(),
            properties: crate::ad::Properties::new(),
            aces: vec![],
            enabled_cert_templates: vec![TypedPrincipal {
                object_identifier: "SAFE-TEMPLATE-SID".to_string(),
                object_type: "CertTemplate".to_string(),
            }],
            is_deleted: false,
            is_acl_protected: false,
            kind: AdcsKind::EnterpriseCa,
        };

        let domain = AdDomain {
            object_identifier: "DOMAIN-SID".to_string(),
            properties: {
                let mut p = crate::ad::Properties::new();
                p.insert("name".to_string(), serde_json::json!("TEST.LOCAL"));
                p
            },
            trusts: vec![],
            aces: vec![],
            links: vec![],
            child_objects: vec![],
            is_deleted: false,
            is_acl_protected: false,
        };

        let mut dataset = ParsedDataset::default();
        dataset.adcs.push(template);
        dataset.adcs.push(ca);
        dataset.domains.push(domain);

        let graph = graph_builder::build(&dataset);
        let reports = analyze(&dataset, &graph);

        assert_eq!(reports[0].esc1_findings.len(), 0);
    }

    #[test]
    fn mark_adcs_vulnerabilities_flags_template_as_high_value_with_note() {
        let dataset = vulnerable_template_dataset();
        let mut graph = graph_builder::build(&dataset);

        // Before marking: template is not high_value, has no note.
        let before = graph.node("TEMPLATE-SID").unwrap();
        assert!(!before.high_value);
        assert!(before.vulnerability_note.is_none());

        mark_adcs_vulnerabilities(&mut graph, &dataset);

        let after = graph.node("TEMPLATE-SID").unwrap();
        assert!(
            after.high_value,
            "vulnerable template should become high_value"
        );
        let note = after
            .vulnerability_note
            .as_ref()
            .expect("expected a vulnerability note");
        assert!(note.contains("ESC1"));
        assert!(note.contains("ATTACKER-SID"));

        // The CA itself must NOT be marked — only the template is the vulnerability.
        let ca = graph.node("CA-SID").unwrap();
        assert!(!ca.high_value);
        assert!(ca.vulnerability_note.is_none());
    }

    #[test]
    fn mark_adcs_vulnerabilities_leaves_safe_templates_untouched() {
        let mut tpl_props = crate::ad::Properties::new();
        tpl_props.insert("name".to_string(), serde_json::json!("SafeTemplate"));
        tpl_props.insert(
            "enrolleesuppliessubject".to_string(),
            serde_json::json!(false),
        );

        let template = AdcsObject {
            object_identifier: "SAFE-TEMPLATE-SID".to_string(),
            properties: tpl_props,
            aces: vec![],
            enabled_cert_templates: vec![],
            is_deleted: false,
            is_acl_protected: false,
            kind: AdcsKind::CertTemplate,
        };

        let mut dataset = ParsedDataset::default();
        dataset.adcs.push(template);

        let mut graph = graph_builder::build(&dataset);
        mark_adcs_vulnerabilities(&mut graph, &dataset);

        let node = graph.node("SAFE-TEMPLATE-SID").unwrap();
        assert!(!node.high_value);
        assert!(node.vulnerability_note.is_none());
    }

    #[test]
    fn detects_esc4_template_acl_abuse() {
        let template = AdcsObject {
            object_identifier: "TEMPLATE-SID".to_string(),
            properties: {
                let mut p = crate::ad::Properties::new();
                p.insert("name".to_string(), serde_json::json!("NormalTemplate"));
                p
            },
            aces: vec![Ace {
                right_name: "WriteDacl".to_string(),
                is_inherited: false,
                principal_sid: "ATTACKER-SID".to_string(),
                principal_type: "User".to_string(),
            }],
            enabled_cert_templates: vec![],
            is_deleted: false,
            is_acl_protected: false,
            kind: AdcsKind::CertTemplate,
        };

        let ca = AdcsObject {
            object_identifier: "CA-SID".to_string(),
            properties: {
                let mut p = crate::ad::Properties::new();
                p.insert("name".to_string(), serde_json::json!("CORP-CA"));
                p
            },
            aces: vec![],
            enabled_cert_templates: vec![TypedPrincipal {
                object_identifier: "TEMPLATE-SID".to_string(),
                object_type: "CertTemplate".to_string(),
            }],
            is_deleted: false,
            is_acl_protected: false,
            kind: AdcsKind::EnterpriseCa,
        };

        let domain = AdDomain {
            object_identifier: "DOMAIN-SID".to_string(),
            properties: {
                let mut p = crate::ad::Properties::new();
                p.insert("name".to_string(), serde_json::json!("TEST.LOCAL"));
                p
            },
            trusts: vec![],
            aces: vec![],
            links: vec![],
            child_objects: vec![],
            is_deleted: false,
            is_acl_protected: false,
        };

        let mut dataset = ParsedDataset::default();
        dataset.adcs.push(template);
        dataset.adcs.push(ca);
        dataset.domains.push(domain);

        let graph = graph_builder::build(&dataset);
        let reports = analyze(&dataset, &graph);

        assert_eq!(reports[0].esc4_findings.len(), 1);
        let finding = &reports[0].esc4_findings[0];
        assert_eq!(finding.principal_id, "ATTACKER-SID");
        assert_eq!(finding.principal_right, "WriteDacl");
        assert_eq!(finding.ca_object_id, "CA-SID");
    }

    #[test]
    fn does_not_flag_esc4_without_acl_rights() {
        let template = AdcsObject {
            object_identifier: "TEMPLATE-SID".to_string(),
            properties: crate::ad::Properties::new(),
            aces: vec![Ace {
                right_name: "Enroll".to_string(),
                is_inherited: false,
                principal_sid: "SOMEUSER-SID".to_string(),
                principal_type: "User".to_string(),
            }],
            enabled_cert_templates: vec![],
            is_deleted: false,
            is_acl_protected: false,
            kind: AdcsKind::CertTemplate,
        };

        let ca = AdcsObject {
            object_identifier: "CA-SID".to_string(),
            properties: crate::ad::Properties::new(),
            aces: vec![],
            enabled_cert_templates: vec![TypedPrincipal {
                object_identifier: "TEMPLATE-SID".to_string(),
                object_type: "CertTemplate".to_string(),
            }],
            is_deleted: false,
            is_acl_protected: false,
            kind: AdcsKind::EnterpriseCa,
        };

        let mut dataset = ParsedDataset::default();
        dataset.adcs.push(template);
        dataset.adcs.push(ca);

        let graph = graph_builder::build(&dataset);
        let findings = find_esc4_findings(&dataset, &graph, None);
        assert_eq!(findings.len(), 0, "Enroll alone should not trigger ESC4");
    }
}
