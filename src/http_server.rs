use crate::config::Config;
use crate::statistics::Statistics;
use crate::tcp_connection::TCP_Connections;
use crate::version::VERSION;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use log::debug;
use parking_lot::Mutex;
use std::sync::Arc;
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
            HttpResponse::Ok().json(stats_data.success_time_stats.per_day.items)
        }
        [part1] if part1 == "minute" => {
            HttpResponse::Ok().json(stats_data.success_time_stats.per_minute.items)
        }
        [part1] if part1 == "hour" => {
            HttpResponse::Ok().json(stats_data.success_time_stats.per_hour.items)
        }
        [part1] if part1 == "second" => {
            HttpResponse::Ok().json(stats_data.success_time_stats.per_second.items)
        }
        [part1] if part1 == "month" => {
            HttpResponse::Ok().json(stats_data.success_time_stats.per_month.items)
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
            HttpResponse::Ok().json(stats_data.total_time_stats.per_day.items)
        }
        [part1] if part1 == "minute" => {
            HttpResponse::Ok().json(stats_data.total_time_stats.per_minute.items)
        }
        [part1] if part1 == "hour" => {
            HttpResponse::Ok().json(stats_data.total_time_stats.per_hour.items)
        }
        [part1] if part1 == "second" => {
            HttpResponse::Ok().json(stats_data.total_time_stats.per_second.items)
        }
        [part1] if part1 == "month" => {
            HttpResponse::Ok().json(stats_data.total_time_stats.per_month.items)
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
            HttpResponse::Ok().json(stats_data.blocked_time_stats.per_day.items)
        }
        [part1] if part1 == "minute" => {
            HttpResponse::Ok().json(stats_data.blocked_time_stats.per_minute.items)
        }
        [part1] if part1 == "hour" => {
            HttpResponse::Ok().json(stats_data.blocked_time_stats.per_hour.items)
        }
        [part1] if part1 == "second" => {
            HttpResponse::Ok().json(stats_data.blocked_time_stats.per_second.items)
        }
        [part1] if part1 == "month" => {
            HttpResponse::Ok().json(stats_data.blocked_time_stats.per_month.items)
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
async fn get_debug(tcp_list: web::Data<Arc<Mutex<TCP_Connections>>>) -> impl Responder {
    let tcp_data = tcp_list.lock().clone();
    HttpResponse::Ok().json(&tcp_data)
}
#[actix_web::main]
pub(crate) async fn listen(
    stats: &Arc<Mutex<Statistics>>,
    tcp_list: &Arc<Mutex<TCP_Connections>>,
    config: &Config,
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
    })
    .bind(format!("{}:{}", config.http_server, config.http_port))?
    .run()
    .await
}
