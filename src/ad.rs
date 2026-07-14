//! Active Directory object models matching the **real** SharpHound-CE
//! collector JSON schema (verified against live `meta.version = 5` output).
//!
//! Unlike a hand-guessed schema, `Properties` is intentionally a loose
//! `HashMap<String, serde_json::Value>` — SharpHound's property set varies
//! across collector versions/methods, and BloodHound's own ingest pipeline
//! treats it the same way (a dynamic property bag merged onto the graph
//! node). Strongly-typed accessor methods are provided for the fields
//! actually used by attack-path logic.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type Properties = HashMap<String, serde_json::Value>;

/// Helper trait for pulling typed values out of a SharpHound `Properties` bag.
pub trait PropertyAccess {
    fn prop_str(&self, key: &str) -> Option<&str>;
    fn prop_bool(&self, key: &str) -> Option<bool>;
    fn prop_i64(&self, key: &str) -> Option<i64>;
    fn prop_str_vec(&self, key: &str) -> Vec<String>;
}

impl PropertyAccess for Properties {
    fn prop_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }
    fn prop_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }
    fn prop_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_i64())
    }
    fn prop_str_vec(&self, key: &str) -> Vec<String> {
        self.get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct TypedPrincipal {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "ObjectType")]
    pub object_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ace {
    #[serde(rename = "RightName")]
    pub right_name: String,
    #[serde(rename = "IsInherited")]
    pub is_inherited: bool,
    #[serde(rename = "PrincipalSID")]
    pub principal_sid: String,
    #[serde(rename = "PrincipalType")]
    pub principal_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpnTarget {
    #[serde(rename = "ComputerSID")]
    pub computer_sid: String,
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(rename = "Service")]
    pub service: String,
}

/// `{ Collected, FailureReason, Results }` wrapper used by Sessions,
/// LocalAdmins, PSRemoteUsers, RemoteDesktopUsers, DcomUsers, etc.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectedResults<T> {
    #[serde(rename = "Collected")]
    pub collected: bool,
    #[serde(rename = "FailureReason")]
    pub failure_reason: Option<String>,
    #[serde(rename = "Results")]
    pub results: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionEntry {
    #[serde(rename = "UserSID")]
    pub user_sid: String,
    #[serde(rename = "ComputerSID")]
    pub computer_sid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpLink {
    #[serde(rename = "GUID")]
    pub guid: String,
    #[serde(rename = "IsEnforced")]
    pub is_enforced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTrust {
    #[serde(rename = "TargetDomainSid")]
    pub target_domain_sid: String,
    #[serde(rename = "TargetDomainName")]
    pub target_domain_name: String,
    #[serde(rename = "IsTransitive")]
    pub is_transitive: bool,
    #[serde(rename = "SidFilteringEnabled")]
    pub sid_filtering_enabled: bool,
    #[serde(rename = "TrustDirection")]
    pub trust_direction: i32,
    #[serde(rename = "TrustType")]
    pub trust_type: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityStatus {
    #[serde(rename = "Connectable")]
    pub connectable: bool,
    #[serde(rename = "Error")]
    pub error: Option<String>,
}

// User

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUser {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "Properties", default)]
    pub properties: Properties,
    #[serde(rename = "PrimaryGroupSID")]
    pub primary_group_sid: Option<String>,
    #[serde(rename = "AllowedToDelegate", default)]
    pub allowed_to_delegate: Vec<String>,
    #[serde(rename = "Aces", default)]
    pub aces: Vec<Ace>,
    #[serde(rename = "SPNTargets", default)]
    pub spn_targets: Vec<SpnTarget>,
    #[serde(rename = "HasSIDHistory", default)]
    pub has_sid_history: Vec<TypedPrincipal>,
    #[serde(rename = "IsDeleted")]
    pub is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    pub is_acl_protected: bool,
}

impl AdUser {
    pub fn name(&self) -> &str {
        self.properties.prop_str("name").unwrap_or(&self.object_identifier)
    }
    pub fn enabled(&self) -> bool {
        self.properties.prop_bool("enabled").unwrap_or(true)
    }
    pub fn has_spn(&self) -> bool {
        self.properties.prop_bool("hasspn").unwrap_or(false)
    }
    pub fn dont_req_preauth(&self) -> bool {
        self.properties.prop_bool("dontreqpreauth").unwrap_or(false)
    }
    pub fn admin_count(&self) -> bool {
        self.properties.prop_bool("admincount").unwrap_or(false)
    }
    pub fn domain_sid(&self) -> Option<&str> {
        self.properties.prop_str("domainsid")
    }
    pub fn pwd_last_set(&self) -> Option<i64> {
        self.properties.prop_i64("pwdlastset")
    }
    pub fn last_logon_timestamp(&self) -> Option<i64> {
        self.properties.prop_i64("lastlogontimestamp")
    }
}

// Computer

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdComputer {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "Properties", default)]
    pub properties: Properties,
    #[serde(rename = "PrimaryGroupSID")]
    pub primary_group_sid: Option<String>,
    #[serde(rename = "AllowedToAct", default)]
    pub allowed_to_act: Vec<TypedPrincipal>,
    #[serde(rename = "AllowedToDelegate", default)]
    pub allowed_to_delegate: Vec<String>,
    #[serde(rename = "LocalAdmins", default)]
    pub local_admins: CollectedResults<TypedPrincipal>,
    #[serde(rename = "PSRemoteUsers", default)]
    pub ps_remote_users: CollectedResults<TypedPrincipal>,
    #[serde(rename = "RemoteDesktopUsers", default)]
    pub remote_desktop_users: CollectedResults<TypedPrincipal>,
    #[serde(rename = "DcomUsers", default)]
    pub dcom_users: CollectedResults<TypedPrincipal>,
    #[serde(rename = "Sessions", default)]
    pub sessions: CollectedResults<SessionEntry>,
    #[serde(rename = "PrivilegedSessions", default)]
    pub privileged_sessions: CollectedResults<SessionEntry>,
    #[serde(rename = "RegistrySessions", default)]
    pub registry_sessions: CollectedResults<SessionEntry>,
    #[serde(rename = "Aces", default)]
    pub aces: Vec<Ace>,
    #[serde(rename = "HasSIDHistory", default)]
    pub has_sid_history: Vec<TypedPrincipal>,
    #[serde(rename = "Status")]
    pub status: Option<ConnectivityStatus>,
    #[serde(rename = "IsDeleted")]
    pub is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    pub is_acl_protected: bool,
}

impl AdComputer {
    pub fn name(&self) -> &str {
        self.properties.prop_str("name").unwrap_or(&self.object_identifier)
    }
    pub fn enabled(&self) -> bool {
        self.properties.prop_bool("enabled").unwrap_or(true)
    }
    pub fn unconstrained_delegation(&self) -> bool {
        self.properties.prop_bool("unconstraineddelegation").unwrap_or(false)
    }
    pub fn operating_system(&self) -> Option<&str> {
        self.properties.prop_str("operatingsystem")
    }
    pub fn domain_sid(&self) -> Option<&str> {
        self.properties.prop_str("domainsid")
    }
}

// Group

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroup {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "Properties", default)]
    pub properties: Properties,
    #[serde(rename = "Members", default)]
    pub members: Vec<TypedPrincipal>,
    #[serde(rename = "Aces", default)]
    pub aces: Vec<Ace>,
    #[serde(rename = "IsDeleted")]
    pub is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    pub is_acl_protected: bool,
}

impl AdGroup {
    pub fn name(&self) -> &str {
        self.properties.prop_str("name").unwrap_or(&self.object_identifier)
    }
    pub fn admin_count(&self) -> bool {
        self.properties.prop_bool("admincount").unwrap_or(false)
    }
    pub fn domain_sid(&self) -> Option<&str> {
        self.properties.prop_str("domainsid")
    }
    /// True for well-known high-value groups (Domain Admins, Enterprise
    /// Admins, etc.) by name pattern — used to auto-tag Tier Zero when no
    /// explicit `system_tags` is present yet.
    pub fn is_high_value_name(&self) -> bool {
        let n = self.name().to_uppercase();
        n.contains("DOMAIN ADMINS")
            || n.contains("ENTERPRISE ADMINS")
            || n.contains("SCHEMA ADMINS")
            || n.contains("ADMINISTRATORS")
            || n.contains("BACKUP OPERATORS")
            || n.contains("ACCOUNT OPERATORS")
            || n.contains("KEY ADMINS")
    }
}

// Domain

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdDomain {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "Properties", default)]
    pub properties: Properties,
    #[serde(rename = "Trusts", default)]
    pub trusts: Vec<DomainTrust>,
    #[serde(rename = "Aces", default)]
    pub aces: Vec<Ace>,
    #[serde(rename = "Links", default)]
    pub links: Vec<GpLink>,
    #[serde(rename = "ChildObjects", default)]
    pub child_objects: Vec<TypedPrincipal>,
    #[serde(rename = "IsDeleted")]
    pub is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    pub is_acl_protected: bool,
}

impl AdDomain {
    pub fn name(&self) -> &str {
        self.properties.prop_str("name").unwrap_or(&self.object_identifier)
    }
}

// GPO

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGpo {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "Properties", default)]
    pub properties: Properties,
    #[serde(rename = "Aces", default)]
    pub aces: Vec<Ace>,
    #[serde(rename = "IsDeleted")]
    pub is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    pub is_acl_protected: bool,
}

impl AdGpo {
    pub fn name(&self) -> &str {
        self.properties.prop_str("name").unwrap_or(&self.object_identifier)
    }
}

// OU

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdOu {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "Properties", default)]
    pub properties: Properties,
    #[serde(rename = "Aces", default)]
    pub aces: Vec<Ace>,
    #[serde(rename = "Links", default)]
    pub links: Vec<GpLink>,
    #[serde(rename = "ChildObjects", default)]
    pub child_objects: Vec<TypedPrincipal>,
    #[serde(rename = "IsDeleted")]
    pub is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    pub is_acl_protected: bool,
}

impl AdOu {
    pub fn name(&self) -> &str {
        self.properties.prop_str("name").unwrap_or(&self.object_identifier)
    }
}

// Container

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdContainer {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "Properties", default)]
    pub properties: Properties,
    #[serde(rename = "Aces", default)]
    pub aces: Vec<Ace>,
    #[serde(rename = "ChildObjects", default)]
    pub child_objects: Vec<TypedPrincipal>,
    #[serde(rename = "IsDeleted")]
    pub is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    pub is_acl_protected: bool,
}

impl AdContainer {
    pub fn name(&self) -> &str {
        self.properties.prop_str("name").unwrap_or(&self.object_identifier)
    }
}

// ADCS objects (cert templates, CAs, NTAuthStores, etc.)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcsObject {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "Properties", default)]
    pub properties: Properties,
    #[serde(rename = "Aces", default)]
    pub aces: Vec<Ace>,
    #[serde(rename = "IsDeleted")]
    pub is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    pub is_acl_protected: bool,
}

impl AdcsObject {
    pub fn name(&self) -> &str {
        self.properties.prop_str("name").unwrap_or(&self.object_identifier)
    }
}

/// All possible AD/Azure object types, for graph node tagging.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, strum::Display, strum::EnumString)]
pub enum ObjectType {
    User,
    Group,
    Computer,
    GPO,
    OU,
    Domain,
    Container,
    AZUser,
    AZGroup,
    AZDevice,
    AZApp,
    AZServicePrincipal,
    AZTenant,
    AZSubscription,
    AZResourceGroup,
    AZKeyVault,
    AZVM,
    AZManagedIdentity,
    #[serde(other)]
    Unknown,
}
