use std::process::exit;

use futures::executor::block_on;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use tracing::debug;

use crate::{
    config::Config,
    dns::{DNS_record, DnsReplyType},
};

#[derive(Debug, Clone)]
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
        let database_url = format!("mysql://{user}:{pass}@{host}:{port}/{dbname}");
        match MySqlPoolOptions::new()
            .max_connections(10)
            .connect(&database_url)
            .await
        {
            Ok(mysql_pool) => {
                debug!("Connection to the database is successful!");
                Mysql_connection { pool: mysql_pool }
            }
            Err(err) => {
                tracing::error!("Failed to connect to the database: {:?}", err);
                std::process::exit(1);
            }
        }
    }
    pub fn insert_or_update_record(&mut self, record: &DNS_record) {
        let i = record;
        let ts = i.timestamp.timestamp();
        let q_res = if record.error == DnsReplyType::NOERROR {
            let q = r"INSERT INTO pdns (QUERY,RR,MAPTYPE,ANSWER,TTL,COUNT,LAST_SEEN,FIRST_SEEN, DOMAIN, asn, asn_owner, prefix) VALUES (
                ?, ?, ? ,?, ?, ?, FROM_UNIXTIME(?),FROM_UNIXTIME(?), ?,  
                 if (length(?) > 0, ?, NULL),  
                 if (length(?) > 0, ?, NULL),
                  if (length(?) > 0, ?, NULL)) ON DUPLICATE KEY UPDATE
                TTL = if (TTL < ?, ?, TTL), COUNT = COUNT + ?, 
                LAST_SEEN = if (LAST_SEEN < FROM_UNIXTIME(?), FROM_UNIXTIME(?), LAST_SEEN),
                FIRST_SEEN = if (FIRST_SEEN > FROM_UNIXTIME(?), FROM_UNIXTIME(?), FIRST_SEEN), 
                asn = if (asn is null and LENGTH(?) > 0, ?, asn), 
                asn_owner = if (asn_owner is null and LENGTH(?) > 0, ?, asn_owner) ,
                prefix = if (prefix is null and LENGTH(?) > 0, ?, prefix) 
                ";
            tracing::debug!("{} {} {} {}", i.name, i.rr_type, i.rdata, i.count);
            block_on(
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
                    .bind(&i.asn)
                    .bind(&i.asn_owner)
                    .bind(&i.asn_owner)
                    .bind(&i.prefix)
                    .bind(&i.prefix)
                    .bind(i.ttl)
                    .bind(i.ttl)
                    .bind(i.count)
                    .bind(ts)
                    .bind(ts)
                    .bind(ts)
                    .bind(ts)
                    .bind(&i.asn)
                    .bind(&i.asn)
                    .bind(&i.asn_owner)
                    .bind(&i.asn_owner)
                    .bind(&i.prefix)
                    .bind(&i.prefix)
                    .execute(&self.pool),
            )
        } else {
            let q = r"INSERT INTO pdns_err (QUERY,RR,MAPTYPE,COUNT,LAST_SEEN,FIRST_SEEN, ERROR_VAL, EXT_ERROR_VAL) VALUES (
                ? ,?, ?, ?, FROM_UNIXTIME(?),FROM_UNIXTIME(?), ?, ?   
                ) ON DUPLICATE KEY UPDATE
                COUNT = COUNT + ?, 
                LAST_SEEN = if (LAST_SEEN < FROM_UNIXTIME(?), FROM_UNIXTIME(?), LAST_SEEN),
                FIRST_SEEN = if (FIRST_SEEN > FROM_UNIXTIME(?), FROM_UNIXTIME(?), FIRST_SEEN) 
                ";
            tracing::debug!("{} {} {} {}", i.name, i.rr_type, i.error as u16, i.count);
            block_on(
                sqlx::query(q)
                    .bind(&i.name)
                    .bind(&i.class)
                    .bind(&i.rr_type)
                    .bind(i.count)
                    .bind(ts)
                    .bind(ts)
                    .bind(i.error as u16)
                    .bind(i.extended_error as u16)
                    .bind(i.count)
                    .bind(ts)
                    .bind(ts)
                    .bind(ts)
                    .bind(ts)
                    .execute(&self.pool),
            )
        };
        match q_res {
            Ok(x) => {
                tracing::debug!("Success {:?}", x);
            }
            Err(e) => {
                tracing::error!("Error: {}", e);
            }
        }
    }
    pub fn create_database(&mut self) {
        let create_cmd = r"CREATE TABLE If NOT EXISTS `pdns`  (
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
            Ok(x) => {
                tracing::debug!("Success {:?}", x);
            }
            Err(e) => {
                tracing::error!("Error: {}", e);
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
            Ok(x) => {
                tracing::debug!("Success {:?}", x);
            }
            Err(e) => {
                tracing::error!("Error: {}", e);
                exit(-1);
            }
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
            tracing::debug!("Database created");
            db.create_database();
        } else {
            tracing::error!("No database configured");
            panic!("No database configured");
        }
    }
}
