//! Main Crate Error

use std::string::FromUtf16Error;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// For starter, to remove as code matures.
    #[error("Generic error: {0}")]
    Generic(String),

    /// For starter, to remove as code matures.
    #[error("Static error: {0}")]
    Static(&'static str),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Ldap(#[from] ldap3::LdapError),

    #[error(transparent)]
    UTF16(#[from] FromUtf16Error),

    #[error(transparent)]
    TOML(#[from] toml::de::Error)
}

/*
impl From<LdapError> for MyError {
    fn from(error: LdapError) -> Self {
        Error::Ldap {
            code: error.
            message: format!("{}", error),
        }
    }
}*/