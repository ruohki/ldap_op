use std::collections::HashSet;
use std::fs;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Ldap, Scope, SearchEntry};
use crate::args;
use crate::args::{ExportArgs};
use crate::structs::toml::{ExportToml, LdapObject};
use crate::prelude::*;

pub async fn export_objects(ldap: &mut Ldap, args: &ExportArgs) -> Result<()> {
    let scope = match &args.search_scope {
        args::Scope::Base => Scope::Base,
        args::Scope::OneLevel => Scope::OneLevel,
        args::Scope::SubTree => Scope::Subtree
    };

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(500)),
    ];

    let base_properties: Vec<&str> = vec!("objectClass", "cn");
    let set: HashSet<_> = base_properties.into_iter().map(|e| e.to_string()).chain(args.ldap_properties.clone().into_iter()).collect();
    let joined_properties: Vec<_> = set.into_iter().collect();

    let mut search = ldap.streaming_search_with(
        adapters,
        &args.search_base.as_str(),
        scope,
        &args.ldap_filter.as_str(),
        &joined_properties
    ).await?;

    let mut entries: Vec<LdapObject> = vec![];
    while let Some(entry) = search.next().await? {
        let entry = SearchEntry::construct(entry);
        let mut entry = LdapObject::try_from(entry).unwrap();
        if let Some(password) = &args.user_password {
            if entry.classes.contains(&"user".to_string()) {
                entry.password = Some(password.clone());
            }
        }

        entries.push(entry);
    }

    // find domain part
    let count = entries.len();
    match count {
        0 => {},
        _ => {
            let substring = ",DC=";
            let entry_zero = entries[0].clone();
            let domain = match &entry_zero.dn.find(substring)
            {
                Some(index) => &entry_zero.dn[(index + 0)..],
                None => ""
            };

            let mut toml = toml::to_string(&ExportToml::from(entries)).unwrap();

            if let Some(new_domain) = &args.target_domain {
                toml = toml.replace(domain, f!(",{new_domain}").as_str());
            }

            fs::write(&args.target_file, toml).expect("TODO: panic message");
        }
    }

    println!("Exported {count} elements.");
    Ok(())
}