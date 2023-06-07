use ldap3::{ SearchEntry };
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ExportToml {
    pub objects: Vec<LdapObject>
}

impl From<Vec<LdapObject>> for ExportToml {
    fn from(value: Vec<LdapObject>) -> Self {
        ExportToml { objects: value }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LdapObject {
    pub dn: String,
    pub cn: Option<String>,
    pub classes: Vec<String>,
    pub password: Option<String>,
    pub attrs: Option<Vec<(String,Vec<String>)>>
}

impl TryFrom<SearchEntry> for LdapObject {
    type Error = ();

    fn try_from(value: SearchEntry) -> Result<Self, Self::Error> {
        let cn = match value.attrs.get("cn") {
            Some(arr) => arr.get(0).cloned(),
            None => None
        };
        let classes = value.attrs.get("objectClass").unwrap().clone();

        let mut attrs: Vec<(String, Vec<String>)>= value.attrs.into_iter().collect();
        attrs.retain(|( key, _)|
            match key.as_str() {
                "cn" => false,
                "objectClass" => false,
                _ => true
            }
        );
        let attrs = match attrs.len() {
            0 => None,
            _ => Some(attrs)
        };

        Ok(LdapObject {
            dn: value.dn.clone(),
            cn,
            classes,
            password: None,
            attrs
        })
    }
}