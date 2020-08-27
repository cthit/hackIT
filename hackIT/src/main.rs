#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate diesel;

use serde::Serialize;
use rocket::State;

use rocket::http::{Cookie, Cookies, RawStr};
use rocket::response::{Flash, Redirect};
use rocket::request::{Form,FlashMessage};
use rocket_contrib::templates::Template;


mod db;
mod challenge;
mod schema;
mod gamma;

use crate::challenge::{Challenge,Challenges,load_challenges};
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
fn challenges(chs : State<ConstState>, flash: Option<FlashMessage>) -> Template {

    #[derive(Serialize)]
    struct Context<'a> {
        names : Vec<&'a String>,
        flash : Option<String>,
    }
    
    let ctx = Context { names : chs.challenges.keys().collect(), flash : flash.map(|x| x.msg().to_string())};
    Template::render("challenges",&ctx)
}

#[get("/challenges/<id>")]
fn get_challenge(cs : State<ConstState>, id : &RawStr, flash: Option<FlashMessage>) -> Option<Template> {
    let challenge = cs.challenges.get(&id.to_string())?;

    #[derive(Serialize)]
    struct Context<'a> {
        challenge : &'a Challenge,
        flash     : Option<String>,
    };

    let ctx = Context { challenge : challenge, flash : flash.map(|x| x.msg().to_string())};
    Some(Template::render("detail_view",&ctx))
}

#[derive(FromForm)]
struct UserAnswer {
    ans : String,
}

#[post("/challenges/<id>",data = "<answer>")]
fn check_answer(cs : State<ConstState>, mut cookies : Cookies, id : &RawStr, answer : Form<UserAnswer>) -> Option<Flash<Redirect>>{
    let qa_selector = cookies.get_private("challenge_selector")?.value().parse::<u32>().unwrap_or(0);
    let challenge = cs.challenges.get(&id.to_string())?;

    let (_,a) = challenge::get_qa(qa_selector,&challenge);

    if a == &answer.into_inner().ans {
        Some(Flash::success(Redirect::to("/challenges/"),format!("Congratulation, you completed {}",challenge.name)))
    }
    else {
        Some(Flash::error(Redirect::to(format!("/challenges/{}/",id.to_string())),"Sorry, but that anwser is incorrect"))
    }

}

#[get("/challenges/<id>/scenario")]
fn get_challenge_scenario(cs : State<ConstState>, mut cookies : Cookies, id : &RawStr) -> Option<String>{
    let qa_selector = cookies.get_private("challenge_selector").unwrap().value().parse::<u32>().unwrap_or(0);
    let challenge = cs.challenges.get(&id.to_string())?;

    
    let (q,_) = challenge::get_qa(qa_selector,&challenge);
    Some(q.to_string())
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

    let challenge_qa_selector : u32 = username.as_bytes().into_iter().map(|x| x.count_ones()).sum();
 
    cookies.add_private(Cookie::new("nick",username));
    cookies.add_private(Cookie::new("challenge_selector",format!("{}",challenge_qa_selector)));
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
	.mount("/", routes![index,records,challenges,gamma_auth,get_challenge,get_challenge_scenario,check_answer]).launch();
}

