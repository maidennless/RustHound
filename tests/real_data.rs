//! Integration test that parses **real** SharpHound-CE collector output
//! (a HackTheBox "TombWatcher" domain dump) to validate our schema against
//! ground truth rather than guessed/synthetic data.

use rusthound_tui::ad::PropertyAccess;
use rusthound_tui::ingest::IngestFile;

fn fixture(name: &str) -> &'static [u8] {
    match name {
        "users" => include_bytes!("fixtures/20250610214705_users.json"),
        "groups" => include_bytes!("fixtures/20250610214705_groups.json"),
        "computers" => include_bytes!("fixtures/20250610214705_computers.json"),
        "domains" => include_bytes!("fixtures/20250610214705_domains.json"),
        "gpos" => include_bytes!("fixtures/20250610214705_gpos.json"),
        "ous" => include_bytes!("fixtures/20250610214705_ous.json"),
        "containers" => include_bytes!("fixtures/20250610214705_containers.json"),
        _ => panic!("unknown fixture {name}"),
    }
}

#[test]
fn parses_users_file() {
    let f = IngestFile::parse(fixture("users")).expect("users.json should parse");
    assert_eq!(f.kind_name(), "users");
    assert_eq!(f.len(), 9);

    if let IngestFile::Users(uf) = f {
        // First entry is a well-known NT AUTHORITY synthetic principal.
        assert_eq!(uf.data[0].object_identifier, "TOMBWATCHER.HTB-S-1-5-20");

        // Second entry: ansible_dev$ gMSA — exercise typed accessors.
        let ansible = &uf.data[1];
        assert_eq!(ansible.properties.prop_str("samaccountname"), Some("ansible_dev$"));
        assert!(ansible.enabled());
        assert!(!ansible.has_spn());
        assert!(!ansible.aces.is_empty(), "ansible_dev$ should have ACEs");

        // Verify at least one Owns ACE was parsed correctly.
        let has_owns = ansible.aces.iter().any(|a| a.right_name == "Owns");
        assert!(has_owns, "expected an Owns ACE on ansible_dev$");
    } else {
        panic!("expected Users variant");
    }
}

#[test]
fn parses_groups_file_and_high_value_tagging() {
    let f = IngestFile::parse(fixture("groups")).expect("groups.json should parse");
    assert_eq!(f.kind_name(), "groups");
    assert_eq!(f.len(), 53);

    if let IngestFile::Groups(gf) = f {
        // Enterprise Key Admins group, admincount=true per fixture.
        let eka = gf
            .data
            .iter()
            .find(|g| g.name().to_uppercase().contains("ENTERPRISE KEY ADMINS"))
            .expect("Enterprise Key Admins group should be present");
        assert!(eka.admin_count());
        assert!(eka.is_high_value_name());

        // `highvalue` property should be readable via the generic accessor.
        let raw_highvalue = eka.properties.prop_bool("highvalue");
        assert_eq!(raw_highvalue, Some(false));
    } else {
        panic!("expected Groups variant");
    }
}

#[test]
fn parses_computers_file_with_nested_collections() {
    let f = IngestFile::parse(fixture("computers")).expect("computers.json should parse");
    assert_eq!(f.len(), 1);

    if let IngestFile::Computers(cf) = f {
        let dc = &cf.data[0];
        assert_eq!(dc.name(), "DC01.TOMBWATCHER.HTB");
        assert!(dc.unconstrained_delegation(), "DC01 has unconstrained delegation in fixture");
        assert_eq!(dc.operating_system(), Some("Windows Server 2019 Standard"));
        assert!(dc.local_admins.collected);
        assert_eq!(dc.local_admins.results.len(), 3);
        assert!(!dc.aces.is_empty());
    } else {
        panic!("expected Computers variant");
    }
}

#[test]
fn parses_domains_file() {
    let f = IngestFile::parse(fixture("domains")).expect("domains.json should parse");
    assert_eq!(f.len(), 1);
    if let IngestFile::Domains(df) = f {
        assert_eq!(df.data[0].name().to_uppercase(), "TOMBWATCHER.HTB");
    } else {
        panic!("expected Domains variant");
    }
}

#[test]
fn parses_gpos_ous_containers() {
    let gpos = IngestFile::parse(fixture("gpos")).unwrap();
    assert_eq!(gpos.len(), 2);

    let ous = IngestFile::parse(fixture("ous")).unwrap();
    assert_eq!(ous.len(), 2);

    let containers = IngestFile::parse(fixture("containers")).unwrap();
    assert_eq!(containers.len(), 19);
}

#[test]
fn full_dataset_round_trip_counts() {
    let total: usize = ["users", "groups", "computers", "domains", "gpos", "ous", "containers"]
        .iter()
        .map(|name| IngestFile::parse(fixture(name)).unwrap().len())
        .sum();
    // 9 + 53 + 1 + 1 + 2 + 2 + 19 = 87
    assert_eq!(total, 87);
}
