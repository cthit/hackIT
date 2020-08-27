#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate diesel;

use serde::Serialize;
use rocket::State;

use rocket::http::{Cookie, Cookies, RawStr};
use rocket::response::{Flash, Redirect};
use rocket_contrib::templates::Template;


use oauth2::basic::BasicClient;

use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use std::env;

pub mod db;
pub mod challenge;
mod schema;

use crate::challenge::{Challenges,load_challenges};
use crate::db::{Record};

#[database("hackit")]
struct UserRecordsConn(diesel::PgConnection);

#[get("/records")]
fn records( conn : UserRecordsConn ) -> Template {

    let recs = Record::all(&conn).unwrap();

    #[derive(Serialize)]
    struct Context{
	records : Vec<Record>,
    }
    
    let ctx = Context{ records: recs };
    
    Template::render("records",&ctx)
}

#[get("/challenges")]
fn challenges(chs : State<ConstState>) -> Template {

    #[derive(Serialize)]
    struct Context<'a> {
	names : Vec<&'a String>,
    }
    
    let ctx = Context { names : chs.challenges.keys().collect() };
    Template::render("challenges",&ctx)
}

#[get("/")]
fn index(chs : State<ConstState>, mut cookies: Cookies) -> Template {

    #[derive(Serialize)]
    struct Context<'a>{
	name : &'static str,
    auth : String,
    auth_url : &'a str,
    }

    let tkn = match cookies.get_private("gamma_access_token") {
        Some(c) => c.value().to_string(),
        _       => "You are not logged in...".to_string(),
    };

    let ctx = Context{ name : "Yoda", auth : tkn, auth_url : &chs.auth_url};
    
    Template::render("index",&ctx)
}

#[get("/auth/gamma?<code>&<state>")]
fn gamma_auth(chs : State<ConstState>,mut cookies: Cookies, code : &RawStr, state : &RawStr) -> Redirect {
    let token = chs.oauth
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request(http_client).unwrap();

    cookies.add_private(Cookie::new("gamma_access_token",token.access_token().secret().to_string()));
    Redirect::to("/")

}

struct ConstState{
    challenges : Challenges,
    oauth      : oauth2::basic::BasicClient,
    auth_url   : String,
}

fn main() {

    
    let gamma_client_id = ClientId::new(
        env::var("GAMMA_CLIENT_ID").expect("Missing the GAMMA_CLIENT_ID environment variable."),
    );
    let gamma_client_secret = ClientSecret::new(
        env::var("GAMMA_CLIENT_SECRET")
            .expect("Missing the GAMMA_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new("http://localhost:8081/api/oauth/authorize".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("http://gamma-backend:8081/api/oauth/token".to_string())
        .expect("Invalid token endpoint URL");

    let client = BasicClient::new(
        gamma_client_id,
        Some(gamma_client_secret),
        auth_url,
        Some(token_url),
    )

    .set_redirect_url(
        RedirectUrl::new("http://localhost:8000/auth/gamma".to_string()).expect("Invalid redirect URL"),
    );

    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .url();
    

    rocket::ignite()
	.attach(Template::fairing())
	.attach(UserRecordsConn::fairing())
	.manage(ConstState{ challenges : load_challenges("test_challenges"), oauth : client, auth_url : authorize_url.to_string()})
	.mount("/", routes![index,records,challenges,gamma_auth]).launch();
}

