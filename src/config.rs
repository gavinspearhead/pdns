use clap::{arg, builder::PossibleValuesParser, value_parser, ArgAction, Command};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Error;
use crate::dns_rr_type::DnsRRType;
use crate::version::{AUTHOR, DESCRIPTION, PROGNAME, VERSION};
use std::net::{IpAddr, ToSocketAddrs};
use std::{fs::File, io::BufReader};
use regex::{Regex, RegexBuilder};
use tracing::{debug, error};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub(crate) struct Config {
    pub rr_type: Vec<DnsRRType>,
    pub interface: Vec<String>,
    pub filter: String,
    pub output: String,
    pub output_type: String,
    pub database: String,
    pub http_server: String,
    pub http_port: u16,
    pub daemon: bool,
    pub promiscuous: bool,
    pub config_file: String,
    pub dbhostname: String,
    pub dbusername: String,
    pub dbport: u16,
    pub dbpassword: String,
    pub dbname: String,
    pub toplistsize: usize,
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
    pub log_file: String,
    pub clean_interval: i64,
    pub additional: bool,
    pub authority: bool,
    pub syslog: bool,
    pub create_database: bool,
    pub capture_tcp: bool,
    pub tcp_memory: u32,
    pub stats_dump_interval: u32,
    pub compress_stats: bool,
    pub ports: Vec<u16>,
    pub ignore_hosts: Vec<String>,
    pub ignore_addresses: Vec<IpAddr>,
    #[serde(deserialize_with = "deserialize_regex", serialize_with = "serialize_regex")]
    pub skip_domains: Vec<Regex>,
}

impl Config {
    pub fn new() -> Config {
        Config {
            rr_type: vec![
                DnsRRType::A,
                DnsRRType::AAAA,
                DnsRRType::NS,
                DnsRRType::PTR,
                DnsRRType::MX,
            ],
            interface: Vec::new(),
            filter: String::new(),
            output: String::new(),
            output_type: String::new(),
            database: String::new(),
            http_server: String::new(),
            http_port: 0,
            daemon: false,
            promiscuous: true,
            config_file: String::new(),
            dbhostname: String::new(),
            dbpassword: String::new(),
            dbport: 0,
            dbusername: String::new(),
            dbname: String::new(),
            toplistsize: 20,
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
            create_database: false,
            tcp_memory: 10,
            capture_tcp: true,
            stats_dump_interval: 3600,
            compress_stats: false,
            ports: vec![53],
            ignore_hosts: Vec::new(),
            ignore_addresses: Vec::new(),
            skip_domains: Vec::new(),
        }
    }
}


fn deserialize_regex<'de, D>(
    deserializer: D,
) -> Result<Vec<Regex>, D::Error>
where
    D: Deserializer<'de>,
{
    let patterns: Vec<String> = Vec::deserialize(deserializer)?;
    patterns
        .into_iter()
        .map(|pattern| {
            RegexBuilder::new(&pattern).case_insensitive(true).build().map_err(|e| {
                serde::de::Error::custom(format!("Invalid regex pattern '{pattern}': {e}"))
            })
        })
        .collect()
}

fn serialize_regex<S>(
    regexes: &[Regex],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let patterns: Vec<String> = regexes.iter().map(|r| r.as_str().to_string()).collect();
    patterns.serialize(serializer)
}


pub(crate) fn parse_rrtypes(config_str: &str) -> Vec<DnsRRType> {
    if config_str.is_empty() {
        return Vec::new();
    } else if config_str == "*" {
        return DnsRRType::collect_dns_rr_types();
    }
    let rrtypes: Vec<DnsRRType> = config_str
        .split(',')
        .map(str::trim)
        .filter_map(|i| {
            DnsRRType::from_string(i)
                .map_err(|_| error!("Invalid RR type: {i}"))
                .ok()
        })
        .collect();
    rrtypes
}

#[cfg(test)]
mod tests {
    use crate::config::{parse_hosts, parse_rrtypes, Config};
    use crate::dns_rr_type::DnsRRType;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_rrtypes1() {
        assert_eq!(
            parse_rrtypes("A,    AAAA,   A6,HTTPS"),
            vec![
                DnsRRType::A,
                DnsRRType::AAAA,
                DnsRRType::A6,
                DnsRRType::HTTPS
            ]
        );
    }

    #[test]
    fn test_parse_rrtypes2() {
        assert_eq!(
            parse_rrtypes("A,AAAA,A6,HTTPS, NS"),
            vec![
                DnsRRType::A,
                DnsRRType::AAAA,
                DnsRRType::A6,
                DnsRRType::HTTPS,
                DnsRRType::NS
            ]
        );
    }

    #[test]
    fn test_parse_hosts_ipv4_address() {
        let mut config = Config::new();
        config.ignore_hosts = vec!["192.0.2.1".to_string()];

        parse_hosts(&mut config);

        assert_eq!(
            config.ignore_addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
        );
    }

    #[test]
    fn test_parse_hosts_ipv6_address() {
        let mut config = Config::new();
        config.ignore_hosts = vec!["2001:db8::1".to_string()];

        parse_hosts(&mut config);

        assert_eq!(
            config.ignore_addresses,
            vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))]
        );
    }

    #[test]
    fn test_parse_hosts_hostname() {
        let mut config = Config::new();
        config.ignore_hosts = vec!["localhost".to_string()];

        parse_hosts(&mut config);

        assert!(!config.ignore_addresses.is_empty());
        assert!(
            config.ignore_addresses.iter().any(|ip| ip.is_loopback()),
            "expected localhost to resolve to at least one loopback address, got {:?}",
            config.ignore_addresses
        );
    }
}

pub(crate) fn parse_hosts(config: &mut Config) {
    let mut ignore_addresses: Vec<IpAddr> = Vec::new();
    for i in &config.ignore_hosts {
        if let Ok(ip) = i.parse() {
            ignore_addresses.push(ip);
        } else {
            let addresses = format!("{i}:0").to_socket_addrs();
            if let Ok(addrs) = addresses {
                for addr in addrs {
                    ignore_addresses.push(addr.ip());
                }
            } else {
                debug!("Error parsing address: {i}");
            }
        }
    }
    debug!("ignore_addresses {:?}", &ignore_addresses);
    config.ignore_addresses = ignore_addresses;
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
                    .value_parser(value_parser!(u16))
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
            .arg(
                arg!(-l --http_server <VALUE>)
                    .required(false)
                    .long_help("Hostname or IP address for the internal web server to liste no"),
            )
            .arg(
                arg!(-O --tcp_memory <VALUE>)
                    .value_parser(value_parser!(u32))
                    .required(false)
                    .long_help("Amount of memory to use for each TCP connection)"),
            )
            .arg(
                arg!(-P --http_port <VALUE>)
                    .required(false)
                    .value_parser(value_parser!(u16))
                    .long_help(
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
                    .value_delimiter(',')
                    .num_args(1..)
                    .value_parser(value_parser!(String))
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
            .arg(
                arg!(-E --clean_interval <VALUE>)
                    .required(false)
                    .value_parser(value_parser!(u32))
                    .long_help(
                "Interval in days after which unused records are removed from the database",
            ))
            .arg(
                arg!(-L --toplistsize <VALUE>)
                    .required(false)
                    .value_parser(value_parser!(u16))
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
                arg!(--nodebug)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Disable debugging mode"),
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
            )
            .arg(
                arg!(--nocapture_tcp)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .conflicts_with("capture_tcp")
                    .long_help("Do not capture DNS traffic on TCP"),
            )
            .arg(
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
                arg!(--nopromisc)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Do not put the interface is promiscuous mode when capturing"),
            )
            .arg(
                arg!(-D --daemon)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Start as a background process (daemon)"),
            )
            .arg(
                arg!(--nodaemon)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .long_help("Start as a foreground process"),
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
                    .value_parser(PossibleValuesParser::new(["json", "csv"]))
                    .long_help("Output format (json or csv)"),
            )
            .arg(
                arg!(--live_dump_host <VALUE>)
                    .required(false)
                    .long_help("Hostname or IP address for the live dump to listen on"),
            )
            .arg(
                arg!(--stats_dump_interval <VALUE>)
                    .required(false)
                    .value_parser(value_parser!(u32))
                    .long_help("Interval with which to dump the statistics"),
            )
            .arg(
                arg!(--live_dump_port <VALUE>)
                    .required(false)
                    .value_parser(value_parser!(u16))
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
            .arg(
                arg!(--ignore_hosts <HOSTS>)
                    .required(false)
                    .value_delimiter(',').num_args(1..).value_parser(value_parser!(String))
                    .long_help("hosts to ignore (comma separated)")
            )
            .arg(
                arg!(--ports <VALUE>).required(false)
                    .value_delimiter(',')
                    .num_args(1..)
                    .value_parser(value_parser!(u16))
                    .long_help(
                        "DNS Port numbers to listen on for packet capture, comma separated (default 53)",
                    ))
            
            .get_matches();

    let empty_str = String::new();
    config.config_file.clone_from(
        matches
            .get_one::<String>("config")
            .unwrap_or(&String::default()),
    );
    debug!("config file {}", config.config_file);
    //let mut config = Config::parse();
    if !config.config_file.is_empty() {
        debug!("Reading config file {}", config.config_file);
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
    config.tcp_memory = *matches
        .get_one::<u32>("tcp_memory")
        .unwrap_or(&config.tcp_memory);
    config.stats_dump_interval = *matches
        .get_one::<u32>("stats_dump_interval")
        .unwrap_or(&config.stats_dump_interval);
    config.http_port = *matches
        .get_one::<u16>("http_port")
        .unwrap_or(&config.http_port);
    matches
        .get_one::<String>("path")
        .unwrap_or(&empty_str)
        .clone_into(pcap_path);

    let interfaces: Vec<String> = matches
        .get_many::<String>("interface")
        .unwrap_or_default() // Returns an empty iterator if arg is missing
        .cloned() // Clone each &String to String
        .collect();

    if !interfaces.is_empty() {
        config.interface = interfaces;
    }
    config.log_file = matches
        .get_one::<String>("log_file")
        .unwrap_or(&config.log_file)
        .clone();
    config.filter = matches
        .get_one::<String>("filter")
        .unwrap_or(&config.filter)
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
    if matches.get_flag("daemon") {
        config.daemon = true;
    }
    if matches.get_flag("nodaemon") {
        config.daemon = false;
    }
    if matches.get_flag("debug") {
        config.debug = true;
    }
    if matches.get_flag("nodebug") {
        config.debug = false;
    }
    if matches.get_flag("promisc") {
        config.promiscuous = true;
    }
    if matches.get_flag("nopromisc") {
        config.promiscuous = false;
    }
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
    if matches.get_flag("syslog") {
        config.syslog = true;
    }
    if matches.get_flag("nosyslog") {
        config.syslog = false;
    }
    if matches.get_flag("additional") {
        config.additional = true;
    }
    if matches.get_flag("noadditional") {
        config.additional = false;
    }
    if matches.get_flag("authority") {
        config.authority = true;
    }
    if matches.get_flag("noauthority") {
        config.authority = false;
    }
    if matches.get_flag("capture_tcp") {
        config.capture_tcp = true;
    }
    if matches.get_flag("nocapture_tcp") {
        config.capture_tcp = false;
    }

    if matches.contains_id("create_database") {
        config.create_database = matches.get_flag("create_database");
    }
    let ports: Vec<u16> = matches
        .get_many::<u16>("ports")
        .unwrap_or_default() // Returns an empty iterator if arg is missing
        .copied() // &u16 -> u16
        .collect();
    if !ports.is_empty() {
        config.ports = ports;
    }
    let ignore_hosts: Vec<String> = matches
        .get_many::<String>("ignore_hosts")
        .unwrap_or_default()
        .map(String::clone)
        .collect();
    debug!("Ignore hosts {:?}", ignore_hosts);
    if !ignore_hosts.is_empty() {
        config.ignore_hosts = ignore_hosts;
    }

    let rr_types = parse_rrtypes(
        &matches
            .get_one::<String>("rrtypes")
            .unwrap_or(&empty_str)
            .clone(),
    );
    // let rr_types = parse_rrtypes(config.rr_type);
    if !rr_types.is_empty() {
        config.rr_type = rr_types;
    }
}
