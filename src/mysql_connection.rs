use std::process::exit;

use futures::executor::block_on;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};

use crate::{config::Config, dns::DNS_record};

pub(crate) struct Mysql_connection {
    pool: Pool<MySql>,
}

impl Mysql_connection {
    pub async fn connect(
        host: &str,
        user: &str,
        pass: &str,
        port: &str,
        dbname: &str,
    ) -> Mysql_connection {
        let database_url = format!("mysql://{}:{}@{}:{}/{}", user, pass, host, port, dbname);
        match MySqlPoolOptions::new()
            .max_connections(10)
            .connect(&database_url)
            .await
        {
            Ok(mysql_pool) => {
                // println!("Connection to the database is successful!");
                return Mysql_connection { pool: mysql_pool };
            }
            Err(err) => {
                log::error!("Failed to connect to the database: {:?}", err);
                std::process::exit(1);
            }
        };
    }
    pub fn insert_or_update_record(&mut self, record: &DNS_record) {
        let i = record;
        let ts = i.timestamp.timestamp();
        println!("QQQQ  {:?}", record);
        let q = r#"INSERT INTO pdns (QUERY,RR,MAPTYPE,ANSWER,TTL,COUNT,LAST_SEEN,FIRST_SEEN, DOMAIN, asn, asn_owner, prefix) VALUES (
                ?, ?, ? ,?, ?, ?, FROM_UNIXTIME(?),FROM_UNIXTIME(?), ?, ?,?,?) ON DUPLICATE KEY UPDATE
                TTL = if (TTL < ?, ?, TTL), COUNT = COUNT + ?, 
                LAST_SEEN = if (LAST_SEEN < FROM_UNIXTIME(?), FROM_UNIXTIME(?), LAST_SEEN),
                FIRST_SEEN = if (FIRST_SEEN > FROM_UNIXTIME(?), FROM_UNIXTIME(?), FIRST_SEEN), 
                asn = if (asn is null, ?, asn), 
                asn_owner = if (asn_owner is null, ?, asn_owner),
                prefix = if (prefix is null, ?, prefix) 
                "#;
        let q_res = block_on(
            sqlx::query(q)
                .bind(&i.name)
                .bind(&i.class)
                .bind(&i.rr_type)
                .bind(&i.rdata)
                .bind(i.ttl)
                .bind(i.count)
                .bind(ts)
                .bind(ts)
                .bind(&i.domain)
                .bind(&i.asn)
                .bind(&i.asn_owner)
                .bind(&i.prefix)
                .bind(i.ttl)
                .bind(i.ttl)
                .bind(i.count)
                .bind(ts)
                .bind(ts)
                .bind(ts)
                .bind(ts)
                .bind(&i.asn)
                .bind(&i.asn_owner)
                .bind(&i.prefix)
                .execute(&self.pool),
        );
        match q_res {
            Ok(_x) => {
                    println!("{:?}", _x);
            }
            Err(e) => {
                    println!("{:?}", e);
                log::error!("Error: {}", e);
            }
        }
    }
    pub fn create_database(&mut self) {
        let create_cmd = "CREATE TABLE `pdns` (
        `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `QUERY` varchar(255) NOT NULL DEFAULT '',
        `MAPTYPE` varchar(16) NOT NULL DEFAULT '',
        `RR` varchar(10) NOT NULL DEFAULT '',
        `ANSWER` varchar(255) NOT NULL DEFAULT '',
        `TTL` bigint(10) unsigned NOT NULL DEFAULT 0,
        `COUNT` bigint(20) unsigned NOT NULL DEFAULT 1,
        `FIRST_SEEN` datetime NOT NULL,
        `LAST_SEEN` datetime NOT NULL,
        `asn` int(8) DEFAULT NULL,
        `asn_owner` varchar(256) DEFAULT NULL,
        `prefix` varchar(128) DEFAULT NULL,
        `domain` varchar(255) DEFAULT NULL,
        `zone` int(8) DEFAULT 0,
        PRIMARY KEY (`ID`),
        UNIQUE KEY `MARQ` (`MAPTYPE`,`ANSWER`,`RR`,`QUERY`),
        KEY `query_idx` (`QUERY`),
        KEY `answer_idx` (`ANSWER`),
        KEY `LAST_SEEN` (`LAST_SEEN`),
        KEY `FIRSTSEEN` (`FIRST_SEEN`),
        KEY `domain_idx` (`domain`),
        KEY `asn` (`asn`)
      ) ENGINE=MyISAM  DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
      ";
        let q_res = block_on(sqlx::query(create_cmd).execute(&self.pool));
        match q_res {
            Ok(_x) => {
                //println!("{:?}", _x);
            }
            Err(e) => {
                log::error!("Error: {}", e);
                exit(-1);
            }
        }
    }
}

pub(crate) fn create_database(config: &Config) {
    if config.database != "" {
        let x = block_on(Mysql_connection::connect(
            &config.dbhostname,
            &config.dbusername,
            &config.dbpassword,
            &config.dbport,
            &config.dbname,
        ));
        let mut database_conn = Some(x);
        match database_conn {
            Some(ref mut _db) => {
                _db.create_database();
                eprintln!("Database created");
            }
            None => {
                log::error!("No database configured");
                panic!("No database configured");
            }
        }
    }
}
