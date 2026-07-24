//! Models for the SharpHound-CE JSON ingestion format, verified against
//! real collector output (`meta.version = 5`).
//!
//! Each collection file has the shape:
//! ```json
//! { "data": [ ... ], "meta": { "methods": 0, "type": "users", "count": N, "version": 5 } }
//! ```

use serde::{Deserialize, Serialize};

use crate::ad::{AdComputer, AdContainer, AdDomain, AdGpo, AdGroup, AdOu, AdUser, AdcsObject};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionMeta {
    #[serde(default)]
    pub methods: i64,
    #[serde(rename = "type")]
    pub kind: CollectionKind,
    pub count: usize,
    pub version: i32,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, strum::Display, strum::EnumString,
)]
#[serde(rename_all = "lowercase")]
pub enum CollectionKind {
    Users,
    Groups,
    Computers,
    Domains,
    Gpos,
    Ous,
    Containers,
    RootCas,
    AiaCas,
    EnterpriseCas,
    NtAuthStores,
    CertTemplates,
    IssuancePolicies,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserFile {
    pub data: Vec<AdUser>,
    pub meta: CollectionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupFile {
    pub data: Vec<AdGroup>,
    pub meta: CollectionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputerFile {
    pub data: Vec<AdComputer>,
    pub meta: CollectionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFile {
    pub data: Vec<AdDomain>,
    pub meta: CollectionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoFile {
    pub data: Vec<AdGpo>,
    pub meta: CollectionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuFile {
    pub data: Vec<AdOu>,
    pub meta: CollectionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerFile {
    pub data: Vec<AdContainer>,
    pub meta: CollectionMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcsFile {
    pub data: Vec<AdcsObject>,
    pub meta: CollectionMeta,
}

/// Discriminated union over all file kinds present in an upload archive,
/// determined by peeking `meta.type` before fully deserializing `data`.
#[derive(Debug, Clone)]
pub enum IngestFile {
    Users(UserFile),
    Groups(GroupFile),
    Computers(ComputerFile),
    Domains(DomainFile),
    Gpos(GpoFile),
    Ous(OuFile),
    Containers(ContainerFile),
    Adcs(AdcsFile),
    Other,
}

impl IngestFile {
    /// Parses a raw JSON byte slice by first peeking `meta.type`, then
    /// deserializing into the matching strongly-typed file struct.
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        #[derive(Deserialize)]
        struct Peek {
            meta: CollectionMeta,
        }
        let peek: Peek = serde_json::from_slice(bytes)?;
        Ok(match peek.meta.kind {
            CollectionKind::Users => IngestFile::Users(serde_json::from_slice(bytes)?),
            CollectionKind::Groups => IngestFile::Groups(serde_json::from_slice(bytes)?),
            CollectionKind::Computers => IngestFile::Computers(serde_json::from_slice(bytes)?),
            CollectionKind::Domains => IngestFile::Domains(serde_json::from_slice(bytes)?),
            CollectionKind::Gpos => IngestFile::Gpos(serde_json::from_slice(bytes)?),
            CollectionKind::Ous => IngestFile::Ous(serde_json::from_slice(bytes)?),
            CollectionKind::Containers => IngestFile::Containers(serde_json::from_slice(bytes)?),
            CollectionKind::RootCas
            | CollectionKind::AiaCas
            | CollectionKind::EnterpriseCas
            | CollectionKind::NtAuthStores
            | CollectionKind::CertTemplates
            | CollectionKind::IssuancePolicies => {
                let kind = match peek.meta.kind {
                    CollectionKind::RootCas => crate::ad::AdcsKind::RootCa,
                    CollectionKind::AiaCas => crate::ad::AdcsKind::AiaCa,
                    CollectionKind::EnterpriseCas => crate::ad::AdcsKind::EnterpriseCa,
                    CollectionKind::NtAuthStores => crate::ad::AdcsKind::NtAuthStore,
                    CollectionKind::CertTemplates => crate::ad::AdcsKind::CertTemplate,
                    CollectionKind::IssuancePolicies => crate::ad::AdcsKind::IssuancePolicy,
                    _ => unreachable!(),
                };
                let mut file: AdcsFile = serde_json::from_slice(bytes)?;
                for obj in &mut file.data {
                    obj.kind = kind;
                }
                IngestFile::Adcs(file)
            }
            CollectionKind::Other => IngestFile::Other,
        })
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            IngestFile::Users(_) => "users",
            IngestFile::Groups(_) => "groups",
            IngestFile::Computers(_) => "computers",
            IngestFile::Domains(_) => "domains",
            IngestFile::Gpos(_) => "gpos",
            IngestFile::Ous(_) => "ous",
            IngestFile::Containers(_) => "containers",
            IngestFile::Adcs(_) => "adcs",
            IngestFile::Other => "other",
        }
    }

    pub fn len(&self) -> usize {
        match self {
            IngestFile::Users(f) => f.data.len(),
            IngestFile::Groups(f) => f.data.len(),
            IngestFile::Computers(f) => f.data.len(),
            IngestFile::Domains(f) => f.data.len(),
            IngestFile::Gpos(f) => f.data.len(),
            IngestFile::Ous(f) => f.data.len(),
            IngestFile::Containers(f) => f.data.len(),
            IngestFile::Adcs(f) => f.data.len(),
            IngestFile::Other => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
