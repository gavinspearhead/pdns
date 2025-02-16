use clap::{arg, ArgAction, Command};
use serde::{Deserialize, Serialize};
use serde_json::Error;

use crate::{
    dns::DNS_RR_type,
    version::{AUTHOR, DESCRIPTION, PROGNAME, VERSION},
};
use std::{fs::File, io::BufReader, str::FromStr as _};
use tracing::{debug, error};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub(crate) struct Config {
    pub rr_type: Vec<DNS_RR_type>,
    pub interface: String,
    pub filter: String,
    pub output: String,
    pub output_type: String,
    pub database: String,
    pub http_server: String,
    pub http_port: u16,
    pub daemon: bool,
    pub promisc: bool,
    pub config_file: String,
    pub dbhostname: String,
    pub dbusername: String,
    pub dbport: u16,
    pub dbpassword: String,
    pub dbname: String,
    pub toplistsize: usize,
    pub skip_list_file: String,
    pub pid_file: String,
    pub uid: String,
    pub gid: String,
    pub public_suffix_file: String,
    pub asn_database_file: String,
    pub debug: bool,
    pub import_stats: String,
    pub export_stats: String,
    pub live_dump_port: u16,
    pub live_dump_host: String,
    pub clean_interval: i64,
    pub additional: bool,
    pub authority: bool,
    pub log_file: String,
    pub syslog: bool,
    pub create_db: bool,
    pub tcp_memory: u32,
    pub capture_tcp: bool,
}

impl Config {
    pub(crate) fn new() -> Config {
        let mut c = Config {
            rr_type: Vec::<DNS_RR_type>::new(),
            interface: String::new(),
            filter: String::new(),
            output: String::new(),
            output_type: String::new(),
            database: String::new(),
            http_server: String::new(),
            http_port: 0,
            daemon: false,
            promisc: false,
            config_file: String::new(),
            dbhostname: String::new(),
            dbpassword: String::new(),
            dbport: 0,
            dbusername: String::new(),
            dbname: String::new(),
            toplistsize: 20,
            skip_list_file: String::new(),
            pid_file: String::new(),
            gid: String::new(),
            uid: String::new(),
            public_suffix_file: String::new(),
            asn_database_file: String::new(),
            debug: false,
            import_stats: String::new(),
            export_stats: String::new(),
            live_dump_port: 0,
            live_dump_host: String::new(),
            log_file: String::new(),
            clean_interval: 0,
            authority: true,
            additional: true,
            syslog: true,
            create_db: false,
            tcp_memory: 10,
            capture_tcp: true,
        };
        c.rr_type.extend(vec![
            DNS_RR_type::A,
            DNS_RR_type::AAAA,
            DNS_RR_type::NS,
            DNS_RR_type::PTR,
            DNS_RR_type::MX,
        ]);
        c
    }
}

pub(crate) fn parse_rrtypes(config_str: &str) -> Vec<DNS_RR_type> {
    if config_str.is_empty() {
        return Vec::new();
    } else if config_str == "*" {
        return DNS_RR_type::collect_dns_rr_types();
    }

    let mut rrtypes: Vec<DNS_RR_type> = Vec::new();
    let elems = config_str.split(',').map(str::trim);
    for i in elems {
        if let Ok(a) = DNS_RR_type::from_string(i) {
            rrtypes.push(a);
        } else {
            error!("Invalid RR type: {i}");
        }
    }
    rrtypes
}

#[cfg(test)]
mod tests {
    use crate::{config::parse_rrtypes, dns::DNS_RR_type};
    #[test]
    fn test_parse_rrtypes1() {
        assert_eq!(
            parse_rrtypes("A,    AAAA,   A6,HTTPS"),
            vec![
                DNS_RR_type::A,
                DNS_RR_type::AAAA,
                DNS_RR_type::A6,
                DNS_RR_type::HTTPS
            ]
        );
    }
    #[test]
    fn test_parse_rrtypes2() {
        assert_eq!(
            parse_rrtypes("A,AAAA,A6,HTTPS, NS"),
            vec![
                DNS_RR_type::A,
                DNS_RR_type::AAAA,
                DNS_RR_type::A6,
                DNS_RR_type::HTTPS,
                DNS_RR_type::NS
            ]
        );
    }
}

pub(crate) fn parse_config(config: &mut Config, pcap_path: &mut String) {
    let matches =
        Command::new(PROGNAME)
            .version(VERSION)
            .author(AUTHOR)
            .about(DESCRIPTION)
            .name(DESCRIPTION)
            .flatten_help(true)
            .arg(
                arg!(-c --config <VALUE>)
                    .required(false)
                    .long_help("location of the config file"),
            )
            .arg(
                arg!(-N --dbname <VALUE>)
                    .required(false)
                    .long_help("name of the database"),
            )
            .arg(
                arg!(-H --dbhostname <VALUE>)
                    .required(false)
                    .long_help("hostname of the database"),
            )
            .arg(
                arg!(-T --dbport <VALUE>)
                    .required(false)
                    .long_help("port number of the database"),
            )
            .arg(
                arg!(-u --dbusername <VALUE>)
                    .required(false)
                    .long_help("username for the database"),
            )
            .arg(
                arg!(-w --dbpassword <VALUE>)
                    .required(false)
                    .long_help("password for the database"),
            )
            .arg(
                arg!(-p --path <VALUE>)
                    .required(false)
                    .long_help("Location of a pcap file to parse"),
            )
            .arg(arg!(-S --skip_list_file <VALUE>).required(false).long_help(
                "location of the file, containing regular expressions with domains to ignore",
            ))
            .arg(
                arg!(-l --http_server <VALUE>)
                    .required(false)
                    .long_help("Hostname or IP address for the internal web server to liste no"),
            )
            .arg(
                arg!(-O --tcp_memory <VALUE>)
                    .required(false)
                    .long_help("Amount of memory to use for each TCP connection)"),
            )
            .arg(
                arg!(-P --http_port <VALUE>).required(false).long_help(
                    "Port number for the internal web server to listen on (0 to disable)",
                ),
            )
            .arg(
                arg!(-r --rrtypes <VALUE>)
                    .required(false)
                    .long_help("Comma-separated list of RR types to record"),
            )
            .arg(
                arg!(-i --interface <VALUE>)
                    .required(false)
                    .long_help("Interface to listen on for packet capture"),
            )
            .arg(
                arg!(-f --filter <VALUE>)
                    .required(false)
                    .long_help("BPF filter definition (port 53)"),
            )
            .arg(
                arg!(-o --output <VALUE>)
                    .required(false)
                    .long_help("Write output to a file; - for standard out"),
            )
            .arg(
                arg!(-d --database <VALUE>)
                    .required(false)
                    .long_help("Write output to a database (mysql)"),
            )
            .arg(arg!(-E --clean_interval <VALUE>).required(false).long_help(
                "Interval in days after which unused records are removed from the database",
            ))
            .arg(
                arg!(-L --toplistsize <VALUE>)
                    .required(false)
                    .long_help("Number of entries in the statistics"),
            )
            .arg(
                arg!(-U --uid <VALUE>)
                    .required(false)
                    .long_help("UID to change to after dropping privileges"),
            )
            .arg(
                arg!(-F --public_suffix_file <VALUE>)
                    .required(false)
                    .long_help("Location of the public suffix file"),
            )
            .arg(
                arg!(-A --asn_database_file <VALUE>)
                    .required(false)
                    .long_help("Location of the ASN database (ip2asn-combined.tsv)"),
            )
            .arg(
                arg!(-g --gid <VALUE>)
                    .required(false)
                    .long_help("GID to change to after dropping privileges"),
            )
            .arg(
                arg!(--debug)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Enable debugging mode"),
            )
            .arg(
                arg!(--noauthority)
                    .required(false)
                    .action(ArgAction::SetFalse)
                    .long_help("Do not process authority records"),
            )
            .arg(
                arg!(--noadditional)
                    .required(false)
                    .action(ArgAction::SetFalse)
                    .long_help("Do not process addional records"),
            )
            .arg(
                arg!(--authority)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Process authority records"),
            )
            .arg(
                arg!(--additional)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Process addional records"),
            )
            .arg(
                arg!(--create_database)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Create a database"),
            ).arg(
            arg!(--no_capture_tcp)
                .required(false)
                .action(ArgAction::SetFalse)
                .conflicts_with("capture_tcp")
                .long_help("Do not capture DNS traffic on TCP"),
            ).arg(
            arg!(--capture_tcp)
                .required(false)
                .action(ArgAction::SetTrue)
                .long_help("Capture DNS traffic on TCP"),
            )
            .arg(
                arg!(-C --promisc)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Put the interface is promiscuous mode when capturing"),
            )
            .arg(
                arg!(-D --daemon)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Start as a background process (daemon)"),
            )
            .arg(
                arg!(-M --import_stats <VALUE>)
                    .required(false)
                    .default_missing_value("")
                    .long_help("Import stats from json file"),
            )
            .arg(
                arg!(-X --export_stats <VALUE>)
                    .required(false)
                    .default_missing_value("")
                    .long_help("Export stats to the parth in a json file at exit"),
            )
            .arg(
                arg!(-I --pid_file <VALUE>)
                    .required(false)
                    .default_missing_value("/var/run/pdns.pid")
                    .long_help("Location of the PID file"),
            )
            .arg(
                arg!(-t --output_type <VALUE>)
                    .required(false)
                    .default_missing_value("csv")
                    .long_help("Output format (CSV or JSON)"),
            )
            .arg(
                arg!(--live_dump_host <VALUE>)
                    .required(false)
                    .long_help("Hostname or IP address for the live dump to listen on"),
            )
            .arg(
                arg!(--live_dump_port <VALUE>)
                    .required(false)
                    .long_help("Port number for the live dump to listen on (0 to disable)"),
            )
            .arg(
                arg!(--log_file <VALUE>)
                    .required(false)
                    .long_help("Log to the file specified"),
            )
            .arg(
                arg!(--syslog)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Log to syslog"),
            )
            .arg(
                arg!(--nosyslog)
                    .required(false)
                    .action(ArgAction::SetFalse)
                    .long_help("Do not log to syslog"),
            )
            .get_matches();

    let empty_str = String::new();
    config.config_file.clone_from(
        matches
            .get_one::<String>("config")
            .unwrap_or(&String::from_str(&empty_str).unwrap()),
    );

    //let mut config = Config::parse();
    if !config.config_file.is_empty() {
        let file = File::open(&config.config_file).expect("Cannot open file");
        let reader = BufReader::new(file);
        let x: Result<Config, Error> = serde_json::from_reader(reader);
        let new_config = match x {
            Ok(y) => y,
            Err(e) => {
                panic!("Importing failed {e}");
            }
        };
        *config = new_config.clone();
    }
    config.http_server = matches
        .get_one::<String>("http_server")
        .unwrap_or(&config.http_server)
        .clone();
    config.tcp_memory = matches
        .get_one::<String>("tcp_memory")
        .unwrap_or(&format!("{}", &config.tcp_memory))
        .parse::<u32>()
        .unwrap();
    debug!("Memory: {}", config.tcp_memory);
    config.http_port = matches
        .get_one::<String>("http_port")
        .unwrap_or(&format!("{}", &config.http_port))
        .parse::<u16>()
        .unwrap();
    matches
        .get_one::<String>("path")
        .unwrap_or(&empty_str)
        .clone_into(pcap_path);
    config.interface = matches
        .get_one::<String>("interface")
        .unwrap_or(&config.interface)
        .clone();
    config.log_file = matches
        .get_one::<String>("log_file")
        .unwrap_or(&config.log_file)
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
    config.dbname = matches
        .get_one::<String>("dbname")
        .unwrap_or(&config.dbname)
        .clone();
    config.database = matches
        .get_one::<String>("database")
        .unwrap_or(&config.database)
        .clone();
    config.daemon = *matches.get_one::<bool>("daemon").unwrap_or(&config.daemon);
    config.debug = *matches.get_one::<bool>("debug").unwrap_or(&config.debug);
    config.promisc = *matches.get_one::<bool>("promisc").unwrap_or(&config.promisc);
    config.toplistsize = *matches
        .get_one::<usize>("toplistsize")
        .unwrap_or(&config.toplistsize);
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
    config.live_dump_host = matches
        .get_one::<String>("live_dump_host")
        .unwrap_or(&config.live_dump_host)
        .clone();
    config.live_dump_port = *matches
        .get_one::<u16>("live_dump_port")
        .unwrap_or(&config.live_dump_port);
    config.clean_interval = *matches
        .get_one::<i64>("clean_interval")
        .unwrap_or(&config.clean_interval);
    config.import_stats = matches
        .get_one::<String>("import_stats")
        .unwrap_or(&config.import_stats)
        .clone();
    config.export_stats = matches
        .get_one::<String>("export_stats")
        .unwrap_or(&config.export_stats)
        .clone();
    config.syslog = *matches.get_one::<bool>("syslog").unwrap_or(&config.syslog);
    config.syslog = *matches.get_one::<bool>("nosyslog").unwrap_or(&config.syslog);
    config.additional = *matches.get_one::<bool>("additional").unwrap_or(&config.additional);
    config.additional = *matches.get_one::<bool>("noadditional").unwrap_or(&config.additional);
    config.authority = *matches.get_one::<bool>("authority").unwrap_or(&config.authority);
    config.authority = *matches.get_one::<bool>("noauthority").unwrap_or(&config.authority);
    config.capture_tcp = *matches.get_one::<bool>("capture_tcp").unwrap_or(&config.capture_tcp);
    config.capture_tcp = *matches.get_one::<bool>("no_capture_tcp").unwrap_or(&config.capture_tcp);
    config.create_db = *matches.get_one::<bool>("create_database").unwrap_or(&false);

    let rr_types = parse_rrtypes(&matches.get_one("rrtypes").unwrap_or(&empty_str).clone());
    // let rr_types = parse_rrtypes(config.rr_type);
    if !rr_types.is_empty() {
        config.rr_type = rr_types;
    }
}
