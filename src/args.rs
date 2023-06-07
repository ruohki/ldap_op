use clap::{Parser, Subcommand, ValueEnum};
use regex::Regex;
use crate::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(long, value_name = "seconds", default_value = "60")]
    pub ldap_connection_timeout: u64,

    //FQDN of target domain controller
    #[arg(long, value_name = "fqdn")]
    pub domain_controller: Option<String>,

    #[arg(long)]
    pub insecure: bool
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Import(ImportArgs),
    Export(ExportArgs)
}

#[derive(clap::Args, Debug)]
pub struct ImportArgs {
    /// Export file to use for importing
    #[arg(short ='s', long, value_name = "file")]
    pub source_file: String,

    /// Use relax control to import
    #[arg(long)]
    pub control_relaxed: bool,

    /// Waits a little bit of time after each imported object
    #[arg(long, value_name = "milliseconds", default_value = "20")]
    pub process_delay: u64,

    /// Space separated list of Ldap properties to ignore while importing
    #[arg(short = 'i', long, value_name = "properties", num_args = 1..)]
    pub ignore_properties: Option<Vec<String>>,

    /// Renames the from_property_name to the to property_name (ex: givenName=sn so the givenName property will be renamed to sn)
    #[arg(long, value_name = "from_property_name=to_property_name", num_args = 1.., value_parser = check_remap_args)]
    pub remap_properties: Option<Vec<(String, String)>>,
}

#[derive(clap::Args, Debug)]
pub struct ExportArgs {
    /// Ldap filter to use while gathering objects to export
    #[arg(short = 'f', long, value_name = "fiter")]
    pub ldap_filter: String,

    /// Target file that contains the export
    #[arg(short ='t', long, value_name = "file")]
    pub target_file: String,

    /// Searchbase for Ldap operations
    #[arg(short = 'b', long, value_name = "base")]
    pub search_base: String,

    /// Searchscope for the export operation
    #[arg(short = 's', long, value_name = "scope", default_value = "sub-tree")]
    pub search_scope: Scope,

    /// Space separated list of Ldap properties to export for each Object
    #[arg(short = 'p', long, value_name = "properties", default_value = "sAMAccountName", num_args = 1..)]
    pub ldap_properties: Vec<String>,

    /// Replaces the domain part of all distinguished names
    #[arg(long, value_name = "target_domain", value_parser = check_is_domain)]
    pub target_domain: Option<String>,

    /// Sets the password for all exported accounts
    #[arg(long, value_name = "password")]
    pub user_password: Option<String>
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Scope {
    Base,
    OneLevel,
    SubTree
}

impl Args {
    pub fn parse_args() -> Self {
        Args::parse()
    }
}

fn check_is_domain(s: &str) -> Result<String> {
    let re = Regex::new(r"^[Dd][Cc]=[\w\-_]+,[Dd][Cc]=[\w\-_]+$").unwrap();
    match re.is_match(&s.to_string()) {
        true => Ok(s.to_string()),
        false => Err(Error::Static("The target domain needs to be in the format of DC=domain,DC=local"))
    }
}

fn check_remap_args(s: &str) -> Result<(String, String)> {
    let re = Regex::new(r"^([A-Za-z0-9\-_]+)=([A-Za-z0-9\-_]+)$").unwrap();
    match re.captures(&s.to_string()) {
        Some(captures) => {
            let key = captures[1].to_string().clone();  // Capture groups are indexed from 1.
            let value = captures[2].to_string().clone();  // Capture groups are indexed from 1.
            Ok((key, value))
        },
        None => Err(Error::Static("Remapping syntax is not correct"))
    }
}