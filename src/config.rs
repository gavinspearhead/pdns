use std::{borrow::Borrow, str::FromStr};

use clap::{arg, ArgAction, Command};
use serde::{Deserialize, Serialize};

use crate::{
    dns::DNS_RR_type,
    version::{AUTHOR, PROGNAME, VERSION},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Config {
    pub rr_type: Vec<crate::dns::DNS_RR_type>,
    pub interface: String,
    pub filter: String,
    pub output: String,
    pub output_type: String,
    pub database: String,
    pub server: String,
    pub port: u16,
    pub daemon: bool,
    pub promisc: bool,
    pub config_file: String,
    pub dbhostname: String,
    pub dbusername: String,
    pub dbport: String,
    pub dbpassword: String,
    pub dbname: String,
    pub toplistsize: usize,
    pub skip_list_file: String,
    pub pid_file: String,
    pub uid: String,
    pub gid: String,
    pub public_suffix_file: String,
    pub asn_database_file: String,
}

impl Config {
    pub fn new() -> Config {
        let mut c = Config {
            rr_type: Vec::<crate::dns::DNS_RR_type>::new(),
            interface: String::new(),
            filter: String::new(),
            output: String::new(),
            output_type: String::new(),
            database: String::new(),
            server: String::new(),
            port: 0,
            daemon: false,
            promisc: false,
            config_file: String::new(),
            dbhostname: String::new(),
            dbpassword: String::new(),
            dbport: String::new(),
            dbusername: String::new(),
            dbname: String::new(),
            toplistsize: 20,
            skip_list_file: String::new(),
            pid_file: String::new(),
            gid: String::new(),
            uid: String::new(),
            public_suffix_file: String::new(),
            asn_database_file: String::new(),
        };
        c.rr_type.extend(vec![
            DNS_RR_type::A,
            DNS_RR_type::AAAA,
            DNS_RR_type::NS,
            DNS_RR_type::PTR,
            DNS_RR_type::MX,
        ]);
        return c;
    }
    pub fn from_str(config_str: &str) -> Result<Config, serde_json::Error> {
        return serde_json::from_str(&config_str);
    }
}

pub fn parse_rrtypes(config_str: &str) -> Vec<DNS_RR_type> {
    let mut rrtypes: Vec<DNS_RR_type> = Vec::new();
    if config_str == "" {
        return rrtypes;
    } else if config_str == "*" {
        rrtypes = DNS_RR_type::to_vec();

        return rrtypes;
    }

    let elems = config_str.split(',');
    for i in elems {
        let a = DNS_RR_type::from_string(i);
        match a {
            Ok(p) => {
                rrtypes.push(p);
            }
            Err(_e) => {
                log::debug!("Invalid RR type: {}", i);
            }
        }
    }
    return rrtypes;
}

pub fn parse_config(mut config: &mut Config, mut pcap_path: &mut String, mut create_db: &mut bool) {
    let matches = Command::new("pdns")
        .version(VERSION)
        .author(AUTHOR)
        .about(PROGNAME)
        .arg(arg!(-c --config <VALUE>).required(false))
        .arg(arg!(-H --dbhostname <VALUE>).required(false))
        .arg(arg!(-T --dbport <VALUE>).required(false))
        .arg(arg!(-u --dbusername <VALUE>).required(false))
        .arg(arg!(-w --dbpassword <VALUE>).required(false))
        .arg(arg!(-p --path <VALUE>).required(false))
        .arg(arg!(-S --skip_list_file <VALUE>).required(false))
        .arg(arg!(-l --listen <VALUE>).required(false))
        .arg(arg!(-P --port <VALUE>).required(false))
        .arg(arg!(-r --rrtypes <VALUE>).required(false))
        .arg(arg!(-i --interface <VALUE>).required(false))
        .arg(arg!(-f --filter <VALUE>).required(false))
        .arg(arg!(-o --output <VALUE>).required(false))
        .arg(arg!(-d --database <VALUE>).required(false))
        .arg(arg!(-L --toplistsize <VALUE>).required(false))
        .arg(arg!(-U --uid <VALUE>).required(false))
        .arg(arg!(-F --public_suffix_file <VALUE>).required(false))
        .arg(arg!(-A --asn_database_file <VALUE>).required(false))
        .arg(arg!(-g --gid <VALUE>).required(false))
        .arg(
            arg!(--create_database)
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(-C --promisc <VALUE>)
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(-D - -daemon)
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(-I --pid_file <VALUE>)
                .required(false)
                .default_missing_value("/var/run/pdns.pid"),
        )
        .arg(
            arg!(-t --output_type <VALUE>)
                .required(false)
                .default_missing_value("csv"),
        )
        .get_matches();
    let empty_str = String::new();
    config.config_file = matches
        .get_one::<String>("config")
        .unwrap_or(&String::from_str(&empty_str).unwrap())
        .clone();

    if config.config_file != "" {
        let config_str = std::fs::read_to_string(&config.config_file).unwrap_or(String::new());
        if !config_str.is_empty() {
            match Config::from_str(&config_str) {
                Ok(mut x) => {
                    x.clone_into(config);
                }
                Err(_e) => {
                    let err_msg = format!("Failed to parse config file: {}", (config.config_file));
                    panic!("{}", err_msg);
                }
            }
        }
    }

    //  println!("config: {:#?}", config);
    *create_db = *matches.get_one::<bool>("create_database").unwrap_or(&false) ;

    config.server = matches
        .get_one::<String>("listen")
        .unwrap_or(&config.server)
        .clone();
    config.port = matches
        .get_one::<String>("port")
        .unwrap_or(&format!("{}", config.port))
        .clone()
        .parse::<u16>()
        .unwrap();
    matches
        .get_one::<String>("path")
        .unwrap_or(&empty_str)
        .clone_into(&mut pcap_path);
    config.interface = matches
        .get_one::<String>("interface")
        .unwrap_or(&config.interface)
        .clone();
    config.filter = matches
        .get_one::<String>("filter")
        .unwrap_or(&config.filter)
        .clone();
    config.skip_list_file = matches
        .get_one::<String>("skip_list_file")
        .unwrap_or(&config.skip_list_file)
        .clone();
    config.output = matches
        .get_one::<String>("output")
        .unwrap_or(&config.output)
        .clone();
    config.output_type = matches
        .get_one::<String>("output_type")
        .unwrap_or(&config.output_type)
        .clone();
    config.database = matches
        .get_one::<String>("database")
        .unwrap_or(&config.database)
        .clone();
    config.daemon = matches
        .get_one::<bool>("daemon")
        .unwrap_or(&config.daemon)
        .clone();
    config.promisc = matches
        .get_one::<bool>("promisc")
        .unwrap_or(&config.promisc)
        .clone();
    config.toplistsize = matches
        .get_one::<usize>("toplistsize")
        .unwrap_or(&config.toplistsize)
        .clone();
    config.pid_file = matches
        .get_one::<String>("pid_file")
        .unwrap_or(&config.pid_file)
        .clone();
    config.gid = matches
        .get_one::<String>("gid")
        .unwrap_or(&config.gid)
        .clone();
    config.uid = matches
        .get_one::<String>("uid")
        .unwrap_or(&config.uid)
        .clone();
    config.public_suffix_file = matches
        .get_one::<String>("public_suffix_file")
        .unwrap_or(&config.public_suffix_file)
        .clone();
    config.asn_database_file = matches
        .get_one::<String>("asn_database_file")
        .unwrap_or(&config.asn_database_file)
        .clone();

    let rr_types = parse_rrtypes(&matches.get_one("rrtypes").unwrap_or(&empty_str).clone());
    if !rr_types.is_empty() {
        config.rr_type = rr_types;
    }
}
