use crate::config::Config;
use crate::statistics::Statistics;
use crate::tcp_connection::TCPConnections;
use crate::time_stats::STAT_ITEM::{DAY, HOUR, MINUTE, MONTH, SECOND};
use crate::version::VERSION;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use log::debug;
use parking_lot::Mutex;
use std::sync::Arc;
use chrono::{DateTime, Utc};

async fn get_version() -> impl Responder {
    HttpResponse::Ok().json(VERSION)
}
async fn get_aclass(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.aclass)
}
async fn get_qclass(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.qclass)
}
async fn get_atypes(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.atypes)
}
async fn get_qtypes(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.qtypes)
}
async fn get_errors(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.errors)
}
async fn get_ext_errors(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.extended_error)
}
async fn get_opcodes(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.opcodes)
}
async fn get_stats(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data)
}

async fn get_success(
    stats: web::Data<Arc<Mutex<Statistics>>>,
    path: web::Path<Vec<String>>,
) -> impl Responder {
    let stats_data = stats.lock().clone();
    match path.as_slice() {
        [] => HttpResponse::Ok().json(stats_data.success_time_stats),
        [part1] if part1 == "day" => {
            HttpResponse::Ok().json(stats_data.success_time_stats.get_item(&DAY))
        }
        [part1] if part1 == "minute" => {
            HttpResponse::Ok().json(stats_data.success_time_stats.get_item(&MINUTE))
        }
        [part1] if part1 == "hour" => {
            HttpResponse::Ok().json(stats_data.success_time_stats.get_item(&HOUR))
        }
        [part1] if part1 == "second" => {
            HttpResponse::Ok().json(stats_data.success_time_stats.get_item(&SECOND))
        }
        [part1] if part1 == "month" => {
            HttpResponse::Ok().json(stats_data.success_time_stats.get_item(&MONTH))
        }
        _ => HttpResponse::NotFound().body("Invalid route"),
    }
}
async fn get_total(
    stats: web::Data<Arc<Mutex<Statistics>>>,
    path: web::Path<Vec<String>>,
) -> impl Responder {
    let stats_data = stats.lock().clone();

    match path.as_slice() {
        [] => HttpResponse::Ok().json(stats_data.total_time_stats),
        [part1] if part1 == "day" => {
            HttpResponse::Ok().json(stats_data.total_time_stats.get_item(&DAY))
        }
        [part1] if part1 == "minute" => {
            HttpResponse::Ok().json(stats_data.total_time_stats.get_item(&MINUTE))
        }
        [part1] if part1 == "hour" => {
            HttpResponse::Ok().json(stats_data.total_time_stats.get_item(&HOUR))
        }
        [part1] if part1 == "second" => {
            HttpResponse::Ok().json(stats_data.total_time_stats.get_item(&SECOND))
        }
        [part1] if part1 == "month" => {
            HttpResponse::Ok().json(stats_data.total_time_stats.get_item(&MONTH))
        }
        _ => HttpResponse::NotFound().body("Invalid route"),
    }
}
async fn get_blocked(
    stats: web::Data<Arc<Mutex<Statistics>>>,
    path: web::Path<Vec<String>>,
) -> impl Responder {
    let stats_data = stats.lock().clone();

    match path.as_slice() {
        [] => HttpResponse::Ok().json(stats_data.blocked_time_stats),
        [part1] if part1 == "day" => {
            HttpResponse::Ok().json(stats_data.blocked_time_stats.get_item(&DAY))
        }
        [part1] if part1 == "minute" => {
            HttpResponse::Ok().json(stats_data.blocked_time_stats.get_item(&MINUTE))
        }
        [part1] if part1 == "hour" => {
            HttpResponse::Ok().json(stats_data.blocked_time_stats.get_item(&HOUR))
        }
        [part1] if part1 == "second" => {
            HttpResponse::Ok().json(stats_data.blocked_time_stats.get_item(&SECOND))
        }
        [part1] if part1 == "month" => {
            HttpResponse::Ok().json(stats_data.blocked_time_stats.get_item(&MONTH))
        }
        _ => HttpResponse::NotFound().body("Invalid route"),
    }
}
async fn get_sources(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.sources)
}
async fn get_topnx(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.topnx)
}
async fn get_top_domains(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.topdomain)
}
async fn get_destinations(stats: web::Data<Arc<Mutex<Statistics>>>) -> impl Responder {
    let stats_data = stats.lock().clone();
    HttpResponse::Ok().json(stats_data.destinations)
}
async fn get_config(config: web::Data<Config>) -> impl Responder {
    let mut config_copy = config.get_ref().clone();
    if !config_copy.dbpassword.is_empty() {
        "****".clone_into(&mut config_copy.dbpassword);
    }
    HttpResponse::Ok().json(&config_copy)
}
async fn get_debug(tcp_list: web::Data<Arc<Mutex<TCPConnections>>>) -> impl Responder {
    let tcp_data = tcp_list.lock().clone();
    HttpResponse::Ok().json(&tcp_data)
}

async fn get_uptime(start_time: web::Data<DateTime<Utc>>) -> impl Responder {
    let uptime = Utc::now().signed_duration_since(**start_time.clone());
    let days = uptime.num_days();
    let hours = uptime.num_hours() % 24;
    let minutes = uptime.num_minutes() % 60;
    let seconds = uptime.num_seconds() % 60;
    let uptime_str = format!("{} days, {} hours, {} minutes, {} seconds", days, hours, minutes, seconds);
    HttpResponse::Ok().json(uptime_str)
}


async fn get_endpoints() -> impl Responder {
    let endpoints = vec![
        "/",
        "/aclass",
        "/atypes",
        "/blocked",
        "/blocked/day",
        "/blocked/hour",
        "/blocked/minute",
        "/blocked/month",
        "/blocked/second",
        "/config",
        "/debug",
        "/destinations",
        "/errors",
        "/ext_errors",
        "/opcodes",
        "/qclass",
        "/qtypes",
        "/sources",
        "/stats",
        "/success/",
        "/success/day",
        "/success/hour",
        "/success/minute",
        "/success/month",
        "/success/second",
        "/top_domains",
        "/topnx",
        "/total",
        "/total/day",
        "/total/hour",
        "/total/minute",
        "/total/month",
        "/total/second",
        "/uptime",
        "/version",
    ];
    HttpResponse::Ok().json(endpoints)
}
#[actix_web::main]
pub(crate) async fn listen(
    stats: &Arc<Mutex<Statistics>>,
    tcp_list: &Arc<Mutex<TCPConnections>>,
    config: &Config,
    start_time: DateTime<Utc>,
) -> std::io::Result<()> {
    if config.http_server.is_empty() || config.http_port == 0 {
        return Ok(());
    }
    debug!("Listening on {}:{}", config.http_server, config.http_port);
    let stats_clone = Arc::clone(stats);
    let tcp_list_clone = Arc::clone(tcp_list);
    let config_clone = config.clone();
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(stats_clone.clone())) // Share statistics across handlers
            .app_data(web::Data::new(config_clone.clone())) // Share config across handlers
            .app_data(web::Data::new(tcp_list_clone.clone())) // Share config across handlers
            .app_data(web::Data::new(start_time)) // Share config across handlers
            .service(
                web::scope("/success")
                    .route("", web::get().to(get_success))
                    .route("/{tail:.*}", web::get().to(get_success)),
            )
            .service(
                web::scope("/blocked")
                    .route("", web::get().to(get_blocked))
                    .route("/{tail:.*}", web::get().to(get_blocked)),
            )
            .service(
                web::scope("/total")
                    .route("", web::get().to(get_total))
                    .route("/{tail:.*}", web::get().to(get_total)),
            )
            .route("/stats", web::get().to(get_stats))
            .route("/opcodes", web::get().to(get_opcodes))
            .route("/ext_errors", web::get().to(get_ext_errors))
            .route("/errors", web::get().to(get_errors))
            .route("/version", web::get().to(get_version))
            .route("/qtypes", web::get().to(get_qtypes))
            .route("/qclass", web::get().to(get_qclass))
            .route("/aclass", web::get().to(get_aclass))
            .route("/atypes", web::get().to(get_atypes))
            .route("/sources", web::get().to(get_sources))
            .route("/destinations", web::get().to(get_destinations))
            .route("/top_domains", web::get().to(get_top_domains))
            .route("/topnx", web::get().to(get_topnx))
            .route("/config", web::get().to(get_config))
            .route("/debug", web::get().to(get_debug))
            .route("/uptime", web::get().to(get_uptime))
            .route("/", web::get().to(get_endpoints))
    })
    .bind(format!("{}:{}", config.http_server, config.http_port))?
    .run()
    .await
}
