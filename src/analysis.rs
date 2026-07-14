//! In-memory analysis engine: answers common BloodHound attack-path
//! questions directly from a [`ParsedDataset`] without needing Neo4j.
//!
//! This is used in two places:
//! 1. The CLI's `analyze` subcommand (offline, fast, works anywhere)
//! 2. The API server when Neo4j hasn't been connected yet (graceful fallback)

use crate::ad::PropertyAccess;

use crate::ParsedDataset;

#[derive(Debug)]
pub struct AnalysisReport {
    pub domain_name:              String,
    pub domain_sid:               String,
    pub tier_zero_groups:         Vec<TierZeroGroup>,
    pub kerberoastable:           Vec<KerberoastableUser>,
    pub asrep_roastable:          Vec<AsrepUser>,
    pub unconstrained_computers:  Vec<UnconstrainedComputer>,
    pub ace_summary:              AceSummary,
    pub member_edges:             Vec<MemberEdge>,
    pub session_edges:            Vec<SessionEdge>,
    pub admin_edges:              Vec<AdminEdge>,
}

#[derive(Debug)]
pub struct TierZeroGroup {
    pub object_id: String,
    pub name:      String,
    pub members:   usize,
}

#[derive(Debug)]
pub struct KerberoastableUser {
    pub object_id:  String,
    pub name:       String,
    pub admin_count: bool,
    pub pwd_last_set: Option<i64>,
    pub spns:       Vec<String>,
}

#[derive(Debug)]
pub struct AsrepUser {
    pub object_id: String,
    pub name:      String,
    pub enabled:   bool,
}

#[derive(Debug)]
pub struct UnconstrainedComputer {
    pub object_id: String,
    pub name:      String,
    pub os:        Option<String>,
}

#[derive(Debug, Default)]
pub struct AceSummary {
    pub total:             usize,
    pub generic_all:       usize,
    pub write_dacl:        usize,
    pub write_owner:       usize,
    pub owns:              usize,
    pub generic_write:     usize,
    pub force_change_pass: usize,
    pub add_member:        usize,
    pub dcsync:            usize,
}

#[derive(Debug)]
pub struct MemberEdge {
    pub member_id:   String,
    pub member_type: String,
    pub group_id:    String,
}

#[derive(Debug)]
pub struct SessionEdge {
    pub computer_id: String,
    pub user_sid:    String,
}

#[derive(Debug)]
pub struct AdminEdge {
    pub principal_id:   String,
    pub principal_type: String,
    pub computer_id:    String,
}

pub fn analyze(d: &ParsedDataset) -> Vec<AnalysisReport> {
    d.domains.iter().map(|dom| analyze_domain(d, &dom.object_identifier, dom.name())).collect()
}

fn analyze_domain(d: &ParsedDataset, domain_sid: &str, domain_name: &str) -> AnalysisReport {
    // ── Tier Zero groups ─────────────────────────────────────────────────────
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
            name:      g.name().to_string(),
            members:   g.members.len(),
        })
        .collect();

    // ── Kerberoastable users ──────────────────────────────────────────────────
    let kerberoastable: Vec<KerberoastableUser> = d
        .users
        .iter()
        .filter(|u| {
            u.has_spn()
                && u.enabled()
                && u.domain_sid().map(|s| s == domain_sid).unwrap_or(true)
        })
        .map(|u| KerberoastableUser {
            object_id:   u.object_identifier.clone(),
            name:        u.name().to_string(),
            admin_count: u.admin_count(),
            pwd_last_set: u.pwd_last_set(),
            spns:        u.properties.prop_str_vec("serviceprincipalnames"),
        })
        .collect();

    // ── AS-REP Roastable ─────────────────────────────────────────────────────
    let asrep_roastable: Vec<AsrepUser> = d
        .users
        .iter()
        .filter(|u| {
            u.dont_req_preauth()
                && u.domain_sid().map(|s| s == domain_sid).unwrap_or(true)
        })
        .map(|u| AsrepUser {
            object_id: u.object_identifier.clone(),
            name:      u.name().to_string(),
            enabled:   u.enabled(),
        })
        .collect();

    // ── Unconstrained delegation computers ───────────────────────────────────
    let unconstrained_computers: Vec<UnconstrainedComputer> = d
        .computers
        .iter()
        .filter(|c| c.unconstrained_delegation() && c.enabled())
        .map(|c| UnconstrainedComputer {
            object_id: c.object_identifier.clone(),
            name:      c.name().to_string(),
            os:        c.operating_system().map(String::from),
        })
        .collect();

    // ── ACE summary ──────────────────────────────────────────────────────────
    let mut ace_summary = AceSummary::default();
    let all_aces = d.users.iter().flat_map(|u| u.aces.iter())
        .chain(d.groups.iter().flat_map(|g| g.aces.iter()))
        .chain(d.computers.iter().flat_map(|c| c.aces.iter()))
        .chain(d.domains.iter().flat_map(|x| x.aces.iter()))
        .chain(d.gpos.iter().flat_map(|x| x.aces.iter()))
        .chain(d.ous.iter().flat_map(|x| x.aces.iter()));

    for ace in all_aces {
        ace_summary.total += 1;
        match ace.right_name.as_str() {
            "GenericAll"          => ace_summary.generic_all += 1,
            "WriteDacl"           => ace_summary.write_dacl += 1,
            "WriteOwner"          => ace_summary.write_owner += 1,
            "Owns"                => ace_summary.owns += 1,
            "GenericWrite"        => ace_summary.generic_write += 1,
            "ForceChangePassword" => ace_summary.force_change_pass += 1,
            "AddMember"           => ace_summary.add_member += 1,
            "DCSync"              => ace_summary.dcsync += 1,
            _ => {}
        }
    }

    // ── Graph edges ───────────────────────────────────────────────────────────
    let member_edges: Vec<MemberEdge> = d
        .groups
        .iter()
        .flat_map(|g| {
            let gid = g.object_identifier.clone();
            g.members.iter().map(move |m| MemberEdge {
                member_id:   m.object_identifier.clone(),
                member_type: m.object_type.clone(),
                group_id:    gid.clone(),
            })
        })
        .collect();

    let session_edges: Vec<SessionEdge> = d
        .computers
        .iter()
        .flat_map(|c| {
            let cid = c.object_identifier.clone();
            c.sessions.results.iter().map(move |s| SessionEdge {
                computer_id: cid.clone(),
                user_sid:    s.user_sid.clone(),
            })
        })
        .collect();

    let admin_edges: Vec<AdminEdge> = d
        .computers
        .iter()
        .flat_map(|c| {
            let cid = c.object_identifier.clone();
            c.local_admins.results.iter().map(move |p| AdminEdge {
                principal_id:   p.object_identifier.clone(),
                principal_type: p.object_type.clone(),
                computer_id:    cid.clone(),
            })
        })
        .collect();

    AnalysisReport {
        domain_name:             domain_name.to_string(),
        domain_sid:              domain_sid.to_string(),
        tier_zero_groups,
        kerberoastable,
        asrep_roastable,
        unconstrained_computers,
        ace_summary,
        member_edges,
        session_edges,
        admin_edges,
    }
}
