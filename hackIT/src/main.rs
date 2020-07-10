mod challenge;

#[macro_use]
extern crate dotenv_codegen;

use actix_files::Files;
use actix_web::{middleware, App, HttpResponse, HttpServer, Error, web, get};
use actix::clock::delay_for;
use tokio_postgres::{NoTls, Error as DbError,Client};

use dotenv;

use std::sync::Mutex;
use std::time::Duration;

struct AppState {
    db_client: Mutex<Client>,
}

#[get("/completions")]
async fn get_completions( data: web::Data<AppState>) -> Result<HttpResponse, Error>{

    // Will cause panic if mutex is poisoned. This is intentional since the client could be corrupted"
    let db = data.db_client.lock().unwrap();
    
    let query = db.query("SELECT \"challenge_id\" FROM \"completions\" WHERE \"user\" = 'peppe'",&[]).await;

    match query {
        Ok(rows) => {
            let mut res = Vec::new();
            for row in rows {
                let challenge: String = row.get("challenge_id");
                res.push(challenge);
            }
            Ok(HttpResponse::Ok().body(res.join(",")))
        },
        Err(e) => {
            Ok(HttpResponse::InternalServerError().body("Error, faild to run db query"))
        }
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();


    let url = dotenv!("DATABASE_URL");
    let mut connection_attempt = tokio_postgres::connect(&url, NoTls).await;

    while let Err(e) = connection_attempt {
        eprintln!("Error establishing connection to db: {}\n Reattempting connection in 10 seconds", e);
        delay_for(Duration::new(10,0)).await;
        connection_attempt = tokio_postgres::connect(&url, NoTls).await;
    }

    let (client, connection) = connection_attempt.expect("Internal Error: database connection failiure was not handled");

    println!("Successfully connected to db");

    // Run connection in seperate thread
    actix::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    let app_state = web::Data::new(AppState{
        db_client : Mutex::new(client),
    });

    let host = "0.0.0.0";
    let port = dotenv!("HTTP_PORT");
    let bind = format!("{0}:{1}",host,port);
    
    HttpServer::new( move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .service(get_completions)
            .service(Files::new("/static","static/").show_files_listing())
            .service(Files::new("/","static/").index_file("index.html"))
    })
	
    .bind(&bind)?
    .run()
    .await
}
