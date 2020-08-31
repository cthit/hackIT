#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use] extern crate rocket;
#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate diesel;

use serde::Serialize;

use rocket::{State,Outcome};
use rocket::http::{Cookie, Cookies, RawStr, Status};
use rocket::response::{Flash, Redirect};
use rocket::request::{Form,FlashMessage,Request,FromRequest};
use rocket_contrib::templates::Template;
use rocket_contrib::serve::StaticFiles;


mod db;
mod challenge;
mod schema;
mod gamma;

use crate::challenge::{Challenge,Challenges,load_challenges};
use crate::db::{Record};

#[database("hackit")]
struct UserRecordsConn(diesel::PgConnection);


struct User {
    name : String,
    challenge_selector : u32,
}

impl<'a,'r> FromRequest<'a,'r> for User {

    type Error = &'static str;

    fn from_request(request: &'a Request<'r>) -> rocket::request::Outcome<Self,Self::Error>{
        let maybe_nick = request.cookies().get_private("nick");
        let maybe_cs   = request.cookies().get_private("challenge_selector");

        if let (Some(nick_cookie),Some(cs_cookie)) = (maybe_nick,maybe_cs) {
            let challenge_selector_parsed = cs_cookie.value()
                .to_string()
                .parse::<u32>();

            if let Ok(challenge_selector) = challenge_selector_parsed{
                return Outcome::Success(User{name : nick_cookie.value().to_string(), challenge_selector : challenge_selector})
            }
            return Outcome::Failure((Status::BadRequest,"Error proccessing session, please delete your cookies and try again"))
        }
        else{
            Outcome::Forward(())
        }
    }
}

#[get("/challenges")]
fn challenges(chs : State<ConstState>, conn : UserRecordsConn, user : User, flash: Option<FlashMessage>) -> Template {

    let completed = Record::get_completion_ids(&conn,&user.name).unwrap_or(vec![]);

    let challenge_statuses : Vec<(&Challenge,bool)> = chs.challenges.values().map(|x| (x,completed.contains(&x.id)) ).collect();

    let mut beginner : Vec<(&String, bool)> = vec![];
    let mut intermediate : Vec<(&String, bool)> = vec![];
    let mut expert : Vec<(&String, bool)> = vec![];

    for (challenge,is_complete) in challenge_statuses {
        match challenge.lvl {
            1 => beginner.push((&challenge.id,is_complete)),
            2 => intermediate.push((&challenge.id,is_complete)),
            3 => expert.push((&challenge.id,is_complete)),
            _ => ()
        };
    }



    #[derive(Serialize)]
    struct Context<'a> {
        beginner : Vec<(&'a String, bool)>,
        intermediate : Vec<(&'a String, bool)>,
        expert : Vec<(&'a String, bool)>,
        flash : Option<String>,
        nick : String,
    }
    
    let ctx = Context { beginner : beginner, intermediate : intermediate, expert : expert, flash : flash.map(|x| x.msg().to_string()), nick : user.name.to_string()};
    Template::render("challenges",&ctx)
}

#[get("/challenges", rank = 2)]
fn challenges_redirect() -> Redirect {
    Redirect::to("/")
}

#[get("/challenges/<id>")]
fn get_challenge(cs : State<ConstState>, _user : User, id : &RawStr, flash: Option<FlashMessage>) -> Option<Template> {
    let challenge = cs.challenges.get(&id.to_string())?; 

    #[derive(Serialize)]
    struct Context<'a> {
        challenge : &'a Challenge,
        flash     : Option<String>,
        nick : String,
    };

    let ctx = Context { challenge : challenge, flash : flash.map(|x| x.msg().to_string()), nick : _user.name.to_string()};
    Some(Template::render("detail_view",&ctx))
}

#[get("/challenges/<_id>", rank = 2)]
fn get_challenge_redirect(_id : &RawStr) -> Redirect {
    Redirect::to("/")
}

#[derive(FromForm)]
struct UserAnswer {
    ans : String,
}

#[post("/challenges/<id>",data = "<answer>")]
fn check_answer(cs : State<ConstState>, conn : UserRecordsConn, user : User, id : &RawStr, answer : Form<UserAnswer>) -> Result<Flash<Redirect>,Status>{

    let challenge = cs.challenges.get(&id.to_string()).ok_or(Status::NotFound)?;

    let (_,a) = challenge::get_qa(user.challenge_selector,&challenge);

    if a == &answer.into_inner().ans {
        let res = match Record::insert(&conn,&user.name,&challenge.id) {
                    Ok(_) => Ok(Flash::success(Redirect::to("/challenges/"),format!("You have completed {}, nice!",challenge.name))),
                    Err(_) => Err(Status::InternalServerError),
        };
        return res
    }
    else {
        Ok(Flash::error(Redirect::to(format!("/challenges/{}/",id.to_string())),"Sorry, but that anwser is incorrect"))
    }

}

#[get("/challenges/<id>/scenario")]
fn get_challenge_scenario(cs : State<ConstState>, user : User, id : &RawStr) -> Option<String>{
    let challenge = cs.challenges.get(&id.to_string())?;

    let (q,_) = challenge::get_qa(user.challenge_selector,&challenge);
    Some(q.to_string())
}

#[get("/challenges/<_id>/scenario", rank = 2)]
fn get_challenge_scenario_redirect(_id : &RawStr) -> Redirect {
    Redirect::to("/")
}

#[get("/")]
fn index_redirect(_user:User) -> Redirect {
    Redirect::to("/challenges")
}

#[get("/", rank = 2)]
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

#[get("/logout")]
fn logout(mut cookies : Cookies) -> Redirect {
    cookies.remove_private(Cookie::named("nick"));
    cookies.remove_private(Cookie::named("challenge_selector"));
    Redirect::to("/")
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
	    .mount("/", routes![index,index_redirect,challenges,challenges_redirect,gamma_auth,get_challenge,get_challenge_redirect,get_challenge_scenario,get_challenge_scenario_redirect,check_answer,logout])
      .mount("/static", StaticFiles::from(concat!(env!("CARGO_MANIFEST_DIR"), "/static")))
      .launch();

}
