use chrono::{Duration, Utc};
use futures::executor::block_on;
use log::error;
use sqlx::mysql::MySqlConnectOptions;
use sqlx::{mysql::MySqlPoolOptions, ConnectOptions, MySql, Pool};
use std::process::exit;
use std::str::FromStr;
use tracing::debug;

use crate::dns_record::DNS_record;
use crate::{config::Config, dns::DnsReplyType};

#[derive(Debug, Clone)]
pub(crate) struct Mysql_connection {
    pool: Pool<MySql>,
}

impl Mysql_connection {
    pub async fn connect(
        host: &str,
        user: &str,
        pass: &str,
        port: &u16,
        dbname: &str,
    ) -> Mysql_connection {
        let database_url = format!("mysql://{user}:{pass}@{host}:{port}/{dbname}");
        let connection_options = match MySqlConnectOptions::from_str(&database_url) {
            Ok(c) => c
                .log_statements(log::LevelFilter::Debug)
                .disable_statement_logging()
                .log_slow_statements(log::LevelFilter::Warn, std::time::Duration::from_secs(1)),
            Err(err) => {
                error!("Failed to connect to the database: {:?}", err);
                exit(1);
            }
        };
        match MySqlPoolOptions::new()
            .connect_with(connection_options)
            .await
        {
            Ok(mysql_pool) => {
                debug!("Connection to the database is successful!");
                Mysql_connection { pool: mysql_pool }
            }
            Err(err) => {
                error!("Failed to connect to the database: {:?}", err);
                exit(1);
            }
        }
    }
    pub fn insert_or_update_record(&mut self, dns_record: &DNS_record) {
        let ts = dns_record.timestamp.timestamp();
        let q_res = if dns_record.error == DnsReplyType::NOERROR {
            static Q: &str = r"INSERT INTO pdns (QUERY,RR,MAPTYPE,ANSWER,TTL,COUNT,LAST_SEEN,FIRST_SEEN,DOMAIN,asn,asn_owner,prefix) 
            VALUES (
                ?, ?, ? ,?, ?, ?, FROM_UNIXTIME(?),FROM_UNIXTIME(?), ?,
                NULLIF(?, 0),  
                NULLIF(?, ''),  
                NULLIF(?, '')
                )
                ON DUPLICATE KEY UPDATE
                TTL = GREATEST(TTL, ?), 
                COUNT = COUNT + ?, 
                LAST_SEEN = GREATEST(LAST_SEEN, FROM_UNIXTIME(?)),
                FIRST_SEEN = LEAST(FROM_UNIXTIME(?), FIRST_SEEN), 
                asn = COALESCE(asn, NULLIF(?, 0)),
                asn_owner = COALESCE(asn_owner, NULLIF(?, '')),
                prefix = COALESCE(prefix, NULLIF(?, ''))
                ";
            debug!("{} {} {} {}", dns_record.name, dns_record.rr_type, dns_record.rdata, dns_record.count);

            block_on(
                sqlx::query(Q)
                    .bind(&dns_record.name)
                    .bind(dns_record.class.to_str())
                    .bind(dns_record.rr_type.to_str())
                    .bind(&dns_record.rdata)
                    .bind(dns_record.ttl)
                    .bind(dns_record.count)
                    .bind(ts)
                    .bind(ts)
                    .bind(&dns_record.domain)
                  //  .bind(dns_record.asn)
                    .bind(dns_record.asn)
                  //  .bind(&dns_record.asn_owner)
                    .bind(&dns_record.asn_owner)
                    //.bind(&dns_record.prefix)
                    .bind(&dns_record.prefix)
                  //  .bind(dns_record.ttl)
                    .bind(dns_record.ttl)
                    .bind(dns_record.count)
                  //  .bind(ts)
                   // .bind(ts)
                    .bind(ts)
                    .bind(ts)
                  //  .bind(dns_record.asn)
                    .bind(dns_record.asn)
                    .bind(&dns_record.asn_owner)
                   // .bind(&dns_record.asn_owner)
                    .bind(&dns_record.prefix)
                  //  .bind(&dns_record.prefix)
                    .execute(&self.pool),
            )
        } else {
            static Q: &str= "INSERT INTO pdns_err (QUERY,RR,MAPTYPE,COUNT,LAST_SEEN,FIRST_SEEN,ERROR_VAL,EXT_ERROR_VAL) 
            VALUES (
                ? ,?, ?, ?, FROM_UNIXTIME(?),FROM_UNIXTIME(?), ?, ?   
                ) ON DUPLICATE KEY UPDATE
                COUNT = COUNT + ?,
                LAST_SEEN = GREATEST(LAST_SEEN, FROM_UNIXTIME(?)),
                FIRST_SEEN = LEAST(FROM_UNIXTIME(?), FIRST_SEEN) 
                ";
           // debug!("{} {} {} {}", i.name, i.rr_type, i.error as u16, i.count);
            block_on(
                sqlx::query(Q)
                    .bind(&dns_record.name)
                    .bind(dns_record.class.to_str())
                    .bind(dns_record.rr_type.to_str())
                    .bind(dns_record.count)
                    .bind(ts)
                    .bind(ts)
                    .bind(dns_record.error as u16)
                    .bind(dns_record.extended_error as u16)
                    .bind(dns_record.count)
                    .bind(ts)
                    .bind(ts)
                    //.bind(ts)
                  //  .bind(ts)
                    .execute(&self.pool),
            )
        };
        match q_res {
            Ok(x) => debug!("Success {x:?}"),
            Err(e) => {
                error!("Error: {e}");
                debug!("Error: {e}");
                debug!("Error: {e}");
                //exit(-1);
            }
        }
    }
    pub fn create_database(&mut self) {
        let create_cmd = r"CREATE TABLE If NOT EXISTS `pdns`  (
        `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `QUERY` varchar(255) NOT NULL DEFAULT '',
        `MAPTYPE` varchar(16) NOT NULL DEFAULT '',
        `RR` varchar(10) NOT NULL DEFAULT '',
        `ANSWER` text NOT NULL DEFAULT '',
        `TTL` bigint(10) unsigned NOT NULL DEFAULT 0,
        `COUNT` bigint(20) unsigned NOT NULL DEFAULT 1,
        `FIRST_SEEN` datetime NOT NULL,
        `LAST_SEEN` datetime NOT NULL,
        `asn` int(8) DEFAULT NULL,
        `asn_owner` varchar(256) DEFAULT NULL,
        `prefix` varchar(128) DEFAULT NULL,
        `domain` varchar(255) DEFAULT NULL,
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
        match block_on(sqlx::query(create_cmd).execute(&self.pool)) {
            Ok(x) => debug!("Success {x:?}"),
            Err(e) => {
                error!("Error: {e}");
                exit(-1);
            }
        }
        let create_cmd1 = r"CREATE TABLE IF NOT EXISTS `pdns_err` (
             `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `QUERY` varchar(255) NOT NULL DEFAULT '',
        `MAPTYPE` varchar(16) NOT NULL DEFAULT '',
        `RR` varchar(10) NOT NULL DEFAULT '',
        `ERROR_VAL` int(1) NOT NULL DEFAULT 0,
        `COUNT` bigint(20) unsigned NOT NULL DEFAULT 1,
        `FIRST_SEEN` datetime NOT NULL,
        `LAST_SEEN` datetime NOT NULL,
        PRIMARY KEY (`ID`),
        UNIQUE KEY `MARQ` (`MAPTYPE`,`ERROR_VAL`,`RR`,`QUERY`),
        KEY `query_idx` (`QUERY`),
        KEY `LAST_SEEN` (`LAST_SEEN`),
        KEY `FIRSTSEEN` (`FIRST_SEEN`)
      ) ENGINE=MyISAM  DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
      ";
        match block_on(sqlx::query(create_cmd1).execute(&self.pool)) {
            Ok(x) => debug!("Success {x:?}"),
            Err(e) => {
                error!("Error: {e}");
                exit(-1);
            }
        }
    }
    pub(crate) fn clean_database(self, config: &Config) {
        if config.clean_interval <= 0 {
            return;
        }
        let current_time = Utc::now() - Duration::days(config.clean_interval);
        debug!("Cleaning timestamp: {current_time}");

        static CLEAN_CMD: &str = "DELETE FROM pdns WHERE LAST_SEEN < ?";
        if let Err(e) = block_on(
            sqlx::query(CLEAN_CMD)
                .bind(current_time)
                .execute(&self.pool),
        ) {
            error!("Cannot execute cleanup query: {e}");
        }

        static CLEAN_CMD1: &str = "DELETE FROM pdns_err WHERE LAST_SEEN < ?";
        if let Err(e) = block_on(
            sqlx::query(CLEAN_CMD1)
                .bind(current_time)
                .execute(&self.pool),
        ) {
            error!("Cannot execute cleanup query: {e}");
        }
    }
}

pub(crate) fn create_database(config: &Config) {
    if !config.database.is_empty() {
        let x = block_on(Mysql_connection::connect(
            &config.dbhostname,
            &config.dbusername,
            &config.dbpassword,
            &config.dbport,
            &config.dbname,
        ));

        if let Some(ref mut db) = Some(x) {
            debug!("Database created");
            db.create_database();
        } else {
            error!("No database configured");
            panic!("No database configured");
        }
    }
}
