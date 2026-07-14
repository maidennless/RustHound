//! # rusthound-tui
//!
//! Reads SharpHound-CE collection ZIPs (or loose JSON files) and parses
//! them into typed AD structures, the same way upstream BloodHound's Go
//! ingestion service does.

use std::{fs::File, io::Read, path::{Path, PathBuf}};
use thiserror::Error;

use crate::ad::{AdComputer, AdContainer, AdDomain, AdGpo, AdGroup, AdOu, AdUser, AdcsObject};
use crate::ingest::IngestFile;

pub mod ad;
pub mod analysis;
pub mod edges;
pub mod graph_builder;
pub mod ingest;
pub mod tree_view;
pub mod tui;

pub use edges::EdgeKind;

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json parse error in {file}: {source}")]
    Json {
        file: String,
        #[source]
        source: serde_json::Error,
    },
}

pub type Result<T> = std::result::Result<T, IngestError>;

/// Aggregated, fully-parsed contents of an ingestion archive — every AD
/// object collected, bucketed by type.
#[derive(Debug, Default)]
pub struct ParsedDataset {
    pub users:      Vec<AdUser>,
    pub groups:     Vec<AdGroup>,
    pub computers:  Vec<AdComputer>,
    pub domains:    Vec<AdDomain>,
    pub gpos:       Vec<AdGpo>,
    pub ous:        Vec<AdOu>,
    pub containers: Vec<AdContainer>,
    pub adcs: Vec<AdcsObject>,
    pub files_seen: Vec<String>,
}

impl ParsedDataset {
    pub fn total_objects(&self) -> usize {
        self.users.len()
            + self.groups.len()
            + self.computers.len()
            + self.domains.len()
            + self.gpos.len()
            + self.ous.len()
            + self.containers.len()
            + self.adcs.len()
    }

    fn absorb(&mut self, file: IngestFile, name: &str) {
        self.files_seen.push(name.to_string());
        match file {
            IngestFile::Users(f) => self.users.extend(f.data),
            IngestFile::Groups(f) => self.groups.extend(f.data),
            IngestFile::Computers(f) => self.computers.extend(f.data),
            IngestFile::Domains(f) => self.domains.extend(f.data),
            IngestFile::Gpos(f) => self.gpos.extend(f.data),
            IngestFile::Ous(f) => self.ous.extend(f.data),
            IngestFile::Containers(f) => self.containers.extend(f.data),
            IngestFile::Adcs(f) => self.adcs.extend(f.data),
            IngestFile::Other => {}
        }
    }
}

/// Parses every `.json` member of a SharpHound-CE ZIP archive into a
/// [`ParsedDataset`]. Non-JSON members are skipped.
pub fn parse_zip<R: Read + std::io::Seek>(reader: R) -> Result<ParsedDataset> {
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut dataset = ParsedDataset::default();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.is_dir() || !entry.name().ends_with(".json") {
            continue;
        }
        let name = entry.name().to_string();
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;

        let file = IngestFile::parse(&buf).map_err(|source| IngestError::Json {
            file: name.clone(),
            source,
        })?;
        dataset.absorb(file, &name);
    }

    Ok(dataset)
}

/// Parses a single loose JSON file's bytes.
pub fn parse_json_bytes(name: &str, bytes: &[u8]) -> Result<IngestFile> {
    IngestFile::parse(bytes).map_err(|source| IngestError::Json {
        file: name.to_string(),
        source,
    })
}

/// Parses either a SharpHound ZIP archive, a single JSON file, or a directory
/// containing SharpHound JSON files.
pub fn parse_path(path: &Path) -> Result<ParsedDataset> {
    if path.is_dir() {
        return parse_directory(path);
    }

    if path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("zip")) {
        let file = File::open(path)?;
        return parse_zip(file);
    }

    if path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("json")) {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "input.json".to_string());
        let bytes = std::fs::read(path)?;
        let file = parse_json_bytes(&name, &bytes)?;
        let mut dataset = ParsedDataset::default();
        dataset.absorb(file, &name);
        return Ok(dataset);
    }

    Err(IngestError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("unsupported input path: {}", path.display()),
    )))
}

fn parse_directory(dir: &Path) -> Result<ParsedDataset> {
    let mut files = Vec::new();
    collect_json_files(dir, &mut files)?;
    files.sort();

    let mut dataset = ParsedDataset::default();
    for path in files {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "input.json".to_string());
        let bytes = std::fs::read(&path)?;
        let file = parse_json_bytes(&name, &bytes)?;
        dataset.absorb(file, &name);
    }

    Ok(dataset)
}

fn collect_json_files(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_json_files(&path, files)?;
        } else if path.is_file()
            && path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            files.push(path);
        }
    }
    Ok(())
}

/// Human-readable summary of a parsed dataset, used both by the CLI's
/// ingest output and as the basis for the API's post-ingest response.
pub struct DatasetSummary {
    pub users: usize,
    pub groups: usize,
    pub computers: usize,
    pub gpos: usize,
    pub ous: usize,
    pub containers: usize,
    pub domains: usize,
    pub total_aces: usize,
    pub kerberoastable_users: usize,
    pub asrep_roastable_users: usize,
    pub unconstrained_delegation_computers: usize,
    pub high_value_groups: usize,
    pub domain_names: Vec<String>,
}

pub fn summarize(d: &ParsedDataset) -> DatasetSummary {
    let total_aces = d.users.iter().map(|u| u.aces.len()).sum::<usize>()
        + d.groups.iter().map(|g| g.aces.len()).sum::<usize>()
        + d.computers.iter().map(|c| c.aces.len()).sum::<usize>()
        + d.domains.iter().map(|x| x.aces.len()).sum::<usize>()
        + d.gpos.iter().map(|x| x.aces.len()).sum::<usize>()
        + d.ous.iter().map(|x| x.aces.len()).sum::<usize>();

    DatasetSummary {
        users: d.users.len(),
        groups: d.groups.len(),
        computers: d.computers.len(),
        gpos: d.gpos.len(),
        ous: d.ous.len(),
        containers: d.containers.len(),
        domains: d.domains.len(),
        total_aces,
        kerberoastable_users: d.users.iter().filter(|u| u.has_spn() && u.enabled()).count(),
        asrep_roastable_users: d.users.iter().filter(|u| u.dont_req_preauth() && u.enabled()).count(),
        unconstrained_delegation_computers: d
            .computers
            .iter()
            .filter(|c| c.unconstrained_delegation())
            .count(),
        high_value_groups: d.groups.iter().filter(|g| g.is_high_value_name() || g.admin_count()).count(),
        domain_names: d.domains.iter().map(|dm| dm.name().to_string()).collect(),
    }
}
