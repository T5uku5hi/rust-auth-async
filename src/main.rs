#[macro_use]
extern crate diesel;

use actix_web::{dev::ServiceRequest, web, App, Error, HttpServer};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};

use actix_web_httpauth::extractors::bearer::{BearerAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::middleware::HttpAuthentication;

mod errors;
mod handlers;
mod models;
mod schema;
mod auth;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

async fn validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, Error> {
    let config = req
        .app_data::<Config>()
        .map(|data| data.get_ref().clone())
        .unwrap_or_else(Default::default);
    match auth::validate_token(credentials.token()) {
        Ok(res) => {
            if res == true {
                Ok(req)
            } else {
                Err(AuthenticationError::from(config).into())
            }
        }
        Err(_) => Err(AuthenticationError::from(config).into()),
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    std::env::set_var("RUST_LOG", "actix_web=debug");
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // create db connection pool
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool: Pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");

    // Start http server
    HttpServer::new(move || {
        let auth = HttpAuthentication::bearer(validator);
        App::new()
            .wrap(auth)
            .data(pool.clone())
            .route("/users", web::get().to(handlers::get_users))
            .route("/users/{id}", web::get().to(handlers::get_user_by_id))
            .route("/users", web::post().to(handlers::add_user))
            .route("/users/{id}", web::delete().to(handlers::delete_user))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
#[test]
fn it_works() {
    use curl::easy::{Easy, List};
    dotenv::dotenv().ok();
    let token = std::env::var("ACCESS_TOKEN").expect("ACCESS_TOKEN must be set");
    let mut list = List::new();
    list.append(&("Authorization: Bearer ".to_owned() + &token)).unwrap();
    let mut easy = Easy::new();
    easy.url("http://localhost:8080/users").unwrap();
    easy.http_headers(list).unwrap();
    easy.perform().unwrap();

    assert_eq!(easy.response_code().unwrap(), 200);
}

#[test]
fn no_auth_header() {
    use curl::easy::Easy;
    let mut easy = Easy::new();
    easy.url("http://localhost:8080/users").unwrap();
    easy.perform().unwrap();

    assert_eq!(easy.response_code().unwrap(), 401);
}

#[test]
fn invalid_auth_header() {
    use curl::easy::{Easy, List};
    let mut list = List::new();
    list.append("Authorization: Bearer XXXX").unwrap();
    let mut easy = Easy::new();
    easy.url("http://localhost:8080/users").unwrap();
    easy.http_headers(list).unwrap();
    easy.perform().unwrap();

    assert_eq!(easy.response_code().unwrap(), 401);
}