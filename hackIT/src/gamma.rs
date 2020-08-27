use std::env;

use serde::{Deserialize};

use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    TokenResponse, TokenUrl,
};

pub fn validate_code(code : &str, client : &BasicClient) -> String{
    client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request(http_client).unwrap().access_token().secret().to_string()
}

pub fn gen_auth_url(client : &BasicClient) -> (String,oauth2::CsrfToken) {
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .url();
    
    (authorize_url.to_string(),csrf_state)
}

pub fn get_nick(access_token : &str) -> Result<String,reqwest::Error> {
    #[derive(Deserialize)]
    struct User {
        nick : String,
    }

    let client = reqwest::blocking::Client::new();
    let resp : User = client.get("http://gamma-backend:8081/api/users/me")
        .bearer_auth(access_token)
        .send()?.json()?;


    Ok(resp.nick)
}


pub fn init_gamma() -> BasicClient {
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

    return client;
}