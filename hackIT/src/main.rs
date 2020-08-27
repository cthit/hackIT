#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate diesel;

use serde::{Serialize};
use rocket::State;

use rocket::http::{Cookie, Cookies, RawStr};
use rocket::response::{Flash, Redirect};
use rocket::request::FlashMessage;
use rocket_contrib::templates::Template;


mod db;
mod challenge;
mod schema;
mod gamma;

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

    let tkn = match cookies.get_private("nick") {
        Some(c) => c.value().to_string(),
        _       => "You are not logged in...".to_string(),
    };

    let (auth_url,csrf_state) = gamma::gen_auth_url(&chs.oauth);


    let ctx = Context{ name : "Yoda", auth : tkn, auth_url : &auth_url};
    cookies.add_private(Cookie::new("csrf_state",csrf_state.secret().to_string()));
    
    Template::render("index",&ctx)
}

#[get("/auth/gamma?<code>&<state>")]
fn gamma_auth(chs : State<ConstState>,mut cookies: Cookies, code : &RawStr, state : &RawStr) -> Result<Redirect,Flash<Redirect>> {

    let csrf_state = match cookies.get_private("csrf_state") {
        Some(c) => c.value().to_string(),
        _       => return Err(Flash::error(Redirect::to("/"),"Invalid auth request: Error #002. Please contact digit@chalmers.it")),

    };

    if csrf_state != state.to_string() {
        return Err(Flash::error(Redirect::to("/"),"Invalid auth request: Error #003. Please contact digit@chalmers.it"))
    }

    let access_token = gamma::validate_code(&code.to_string(),&chs.oauth);

    let username = match gamma::get_nick(&access_token) {
        Ok(nick) => nick,
        _        => return Err(Flash::error(Redirect::to("/"),"Invalid auth request: Error #004. Please contact digit@chalmers.it"))
    };
 
    cookies.add_private(Cookie::new("nick",username));
    Ok(Redirect::to("/"))

}

struct ConstState{
    challenges : Challenges,
    oauth      : oauth2::basic::BasicClient,
}

fn main() {

    let gamma_client = gamma::init_gamma();

    rocket::ignite()
	.attach(Template::fairing())
	.attach(UserRecordsConn::fairing())
	.manage(ConstState{ challenges : load_challenges("test_challenges"), oauth : gamma_client})
	.mount("/", routes![index,records,challenges,gamma_auth]).launch();
}

