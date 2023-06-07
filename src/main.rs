//#![allow(unused)] // For beginning only.

use std::time::Duration;
use crate::prelude::*;
use crate::args::{Args};
use ldap3::{ LdapConnAsync, LdapConnSettings };
use crate::args::Commands::{Import, Export};
use crate::export::export_objects;
use crate::import::import_objects;
use crate::utils::get_domain_controller::{get_domain_controller};

mod error;
mod prelude;
mod utils;
mod args;
mod structs;
mod export;
mod import;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse_args();

    // Retrieve Domain controller and convert to String for later use
    let domain = match args.domain_controller {
        Some( uri) => uri,
        None => {
            let domain = get_domain_controller();
            let domain = domain.unwrap();
            domain
        }
    };
    let ldap_url = match args.insecure {
        true => f!("ldap://{}", &domain),
        false =>  f!("ldaps://{}", &domain),
    };

    println!("Connecting to: {ldap_url}");
    // Establish Ldap Connection and perform gssapi bind
    let (conn, mut ldap) = LdapConnAsync::with_settings(
        LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(args.ldap_connection_timeout)),
        ldap_url.as_str(),
    ).await?;
    ldap3::drive!(conn);
    ldap.sasl_gssapi_bind(domain.as_str()).await?;

    match &args.command {
        Export(args) => export_objects(&mut ldap, args).await?,
        Import(args) => import_objects(&mut ldap, args).await?,
    };

    ldap.unbind().await?;

    Ok(())
}