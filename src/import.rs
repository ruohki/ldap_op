use std::{fs};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;
use ldap3::{Ldap, LdapResult, Mod};
use ldap3::controls::{MakeCritical, RelaxRules};

use crate::args::ImportArgs;
use crate::prelude::*;
use crate::structs::toml::ExportToml;

pub async fn import_objects(ldap: &mut Ldap, args: &ImportArgs) -> Result<()> {
    // Read file and load objects from toml
    let source_file_path = Path::new(&args.source_file);
    let source_file_content = fs::read_to_string(source_file_path)?;
    let import: ExportToml = toml::from_str(source_file_content.as_str())?;

    // Build remap hashmap
    let remap_map = match &args.remap_properties {
        Some(raw) => raw.clone().into_iter().collect::<HashMap<String, String>>(),
        None => HashMap::new()
    };

    println!("{remap_map:?}");

    let mut counter = 0;
    let count = import.objects.len();
    for element in import.objects {
        counter += 1;

        let mut attrs = match element.attrs {
            Some(attrs) => attrs,
            None =>  Vec::new(),
        };

        // Filter out ignored props
        if let Some(props) = &args.ignore_properties {
            if props.len() > 0 {
                attrs.retain(|(k , _) | !props.contains(k))
            }
        }

        // Remap properties
        let mut attrs: Vec<(String, Vec<String>)> = attrs.into_iter().map(|(k, val)| match remap_map.contains_key(k.as_str()) {
            true => (remap_map.get(k.as_str()).unwrap().clone(), val),
            false => (k.clone(), val)
        }).collect();

        let mut initial_attributes: Vec<(String, HashSet<String>)> = Vec::new();
        initial_attributes.push(("objectClass".to_string(), element.classes.into_iter().collect()));

        let _ = match ldap.add(element.dn.as_str(), initial_attributes).await? {
            LdapResult { rc, .. } => {
                if rc == 0 {
                    println!("[Add][{counter}/{count}][{rc}] {}", element.dn.as_str());
                }
            }
        };

        // Update password
        if let Some(password) = element.password {
            let password = f!("\"{password}\"");
            let mut attributes: Vec<Mod<_>> = Vec::new();
            let data = password.encode_utf16().collect::<Vec<u16>>();
            let bytes: Vec<_> = data.into_iter().flat_map(|x| x.to_le_bytes().to_vec()).collect();
            let mut password_hashset = HashSet::new();
            password_hashset.insert(bytes);

            let user_account_control: HashSet<Vec<u8>>= match attrs.clone().into_iter().find(|(k, _)| k == &String::from("userAccountControl")) {
                Some((_, user_account_control)) => {
                    attrs.retain(|(k, _) | k != &String::from("userAccountControl"));
                    user_account_control.into_iter().map(|s| s.into_bytes()).collect()
                },
                None => vec![String::from("512")].into_iter().map(|s| s.into_bytes()).collect(),
            };

            attributes.push( Mod::Replace("unicodePwd".as_bytes().to_vec(), password_hashset));
            attributes.push(Mod::Replace("userAccountControl".as_bytes().to_vec(), user_account_control));
            let _ = match ldap.modify(element.dn.as_str(), attributes).await? {
                LdapResult { rc, text, .. } => {
                    if rc == 0 {
                        println!("[PW][{counter}/{count}][{rc}] {}", element.dn.as_str());
                    } else {
                        println!("[PW][{counter}/{count}][{rc}] {} {}", element.dn.as_str(), text);
                    }
                }
            };
        }

        // Attributes
        if attrs.len() > 0 {
            let attrs: Vec<Mod<String>> = attrs.into_iter()
                .map(|(k, v)|  Mod::Replace(k, v.into_iter().collect()))
                .collect();

            if args.control_relaxed == true {
                let _ = match ldap.with_controls(RelaxRules.critical()).modify(element.dn.as_str(), attrs).await? {
                    LdapResult { rc, text, .. } => {
                        if rc == 0 {
                            println!("[Modif][R][{counter}/{count}][{rc}] {}", element.dn.as_str());
                        } else {
                            println!("[Modif][R][{counter}/{count}][{rc}] {} {}", element.dn.as_str(), text);
                        }
                    }
                };
            } else {
                let _ = match ldap.modify(element.dn.as_str(), attrs).await? {
                    LdapResult { rc, text, .. } => {
                        if rc == 0 {
                            println!("[Modif][{counter}/{count}][{rc}] {}", element.dn.as_str());
                        } else {
                            println!("[Modif][{counter}/{count}][{rc}] {} {}", element.dn.as_str(), text);
                        }
                    }
                };
            }
        }

        std::thread::sleep(Duration::from_millis(args.process_delay));
    }
    Ok(())
}