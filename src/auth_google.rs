use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use oauth2::basic::BasicClient;
use oauth2::TokenResponse;
use ::reqwest::Client;
use reqwest::Error as ReqwestError;
use tera::{Tera, Value};

use crate::OAuthRequest;

//FUNCIONES DE AUTENTICACIÓN

pub async fn auth_login(client: web::Data<BasicClient>, session: Session) -> impl Responder {
    // Genera un token CSRF aleatorio
    let state = oauth2::CsrfToken::new_random();
    // Almacena el token CSRF en la sesión
    session.insert("csrf_token", state.secret()).unwrap();
    // Genera la URL de autorización con el parámetro scope
    let (auth_url, _csrf_token) = client
        .authorize_url(|| state)
        .add_scope(oauth2::Scope::new("openid email profile".to_string()))
        .url();
    // Redirige al usuario a la URL de autorización
    HttpResponse::Found()
        .append_header((actix_web::http::header::LOCATION, auth_url.to_string()))
        .finish()
}

pub async fn auth_callback(
    query: web::Query<OAuthRequest>,
    client: web::Data<BasicClient>,
    session: Session,
) -> impl Responder {
    // Recupera el valor de state almacenado en la sesión
    let stored_state: Option<String> = session.get("csrf_token").unwrap();

    if let Some(stored_state) = stored_state {
        if query.state != stored_state {
            return HttpResponse::BadRequest().body("Invalid state parameter");
        }
    } else {
        return HttpResponse::BadRequest().body("State parameter not found in session");
    }

    let token_result = client
        .exchange_code(oauth2::AuthorizationCode::new(query.code.clone()))
        .request_async(oauth2::reqwest::async_http_client)
        .await;

        match token_result {
            Ok(token) => {
                let access_token = token.access_token().secret().to_string();
                session.insert("access_token", access_token.clone()).unwrap();
                // Redirigir al usuario a la página /user después de obtener el token de acceso
                HttpResponse::Found()
                    .append_header(("LOCATION", "/user"))
                    .finish()
            }
            Err(err) => HttpResponse::InternalServerError().body(format!("Error: {:?}", err)),
        }
    }

    pub async fn get_user_info(session: Session, tera: web::Data<Tera>, _req: HttpRequest) -> impl Responder {
        if let Some(access_token) = session.get::<String>("access_token").unwrap() {
            // Aquí deberías hacer una solicitud a la API de Google para obtener los datos del usuario
            // Por simplicidad, vamos a usar datos ficticios
            let user_info = get_user_info_from_google(&access_token).await.unwrap();
    
            let mut ctx = tera::Context::new();
            ctx.insert("email", &user_info["email"]);
            ctx.insert("name", &user_info["name"]);
            ctx.insert("profile", &user_info["profile"]);
    
            let rendered = tera.render("user.html", &ctx).unwrap();
            HttpResponse::Ok()
                .content_type("text/html")
                .body(rendered)
        } else {
            HttpResponse::Unauthorized().body("No access token found")
        }
    }

    pub async fn get_user_info_from_google(access_token: &str) -> Result<Value, ReqwestError> {
        let client = Client::new();
        let response = client
            .get("https://www.googleapis.com/oauth2/v3/userinfo")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await?;
        let user_info: Value = response.json().await?;
        Ok(user_info)
    }
