use actix_session::{CookieSession, Session};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder, HttpMessage, middleware::Logger};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenResponse, TokenUrl};
use ::reqwest::Client;
use serde::Deserialize;
use reqwest::Error as ReqwestError;
use sqlx::{MySqlPool, Row};
use tera::{Tera, Value};
use std::fs::{OpenOptions, create_dir_all};
use log::LevelFilter;
use env_logger::Builder;
use actix_files as fs;
use generador_de_nonces::NonceMiddleware;

//MODULOS
mod generador_de_nonces;





#[derive(Debug, Deserialize)]
struct OAuthRequest {
    code: String,
    state: String,
}

//FUNCIONES DE AUTENTICACIÓN

async fn auth_login(client: web::Data<BasicClient>, session: Session) -> impl Responder {
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

async fn auth_callback(
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

    async fn get_user_info(session: Session, tera: web::Data<Tera>, _req: HttpRequest) -> impl Responder {
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

    async fn get_user_info_from_google(access_token: &str) -> Result<Value, ReqwestError> {
        let client = Client::new();
        let response = client
            .get("https://www.googleapis.com/oauth2/v3/userinfo")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await?;
        let user_info: Value = response.json().await?;
        Ok(user_info)
    }


//DEFINIMOS LAS RUTAS Y SUS RESPUESTAS

async fn index(tera: web::Data<Tera>, req: HttpRequest) -> impl Responder {
    let mut ctx = tera::Context::new();
    if let Some(nonce) = req.extensions().get::<String>() {
        ctx.insert("nonce", nonce);
    } else {
        return HttpResponse::NotFound().body("Nonce not found");
    }

    let pool = MySqlPool::connect("mysql://diego:1234@localhost/actix1").await.unwrap();
    let user = User::get_user_by_id(web::Data::new(pool.clone()), 1).await.unwrap();
    ctx.insert("registrodeusuarios", &user);

    let rendered = tera.render("index.html", &ctx).unwrap();
    HttpResponse::Ok().content_type("text/html").body(rendered)
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Comentario {
    id: i32,
    comentario: String,
}

async fn obtener_comentarios() -> impl Responder {
    let pool = MySqlPool::connect("mysql://diego:1234@localhost/actix1")
        .await
        .unwrap();
    let registros = sqlx::query("SELECT * FROM comentarios")
        .fetch_all(&pool)
        .await
        .unwrap();
    let mut comentarios = Vec::new();
    for registro in registros {
        let comentario = Comentario {
            id: registro.get("id"),
            comentario: registro.get("comentario"),
        };
        comentarios.push(comentario);
    }
    HttpResponse::Ok().json(comentarios)
}



#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct User {
    id: i32,
    name: String,
    email: String,
}

impl User {
    // Método para obtener un usuario por su ID
    async fn get_user_by_id(pool: web::Data<sqlx::Pool<sqlx::MySql>>, id: i32) -> Result<User, sqlx::Error> {
        let row = sqlx::query("SELECT * FROM registrodeusuarios WHERE id = ?")
            .bind(id)
            .fetch_one(&**pool)
            .await?;
        let user = User {
            id: row.get("id"),
            name: row.get("name"),
            email: row.get("email"),
        };
        Ok(user)
    }
}

// Macro para iniciar el servidor
#[actix_rt::main]
async fn main() {
    // Crear el directorio de logs si no existe
    let _ = create_dir_all("log");

    // Configurar el logger para escribir en log/log.txt
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("log/log.txt")
        .unwrap();

    let client_id = ClientId::new("client".to_string());
    let client_secret = ClientSecret::new("secret".to_string());
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string()).expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).expect("Invalid token URL");

    let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(RedirectUrl::new("http://localhost:8080/auth/callback".to_string()).expect("Invalid redirect URL"));

    // Inicializar el logger
    Builder::new()
        .filter(None, LevelFilter::Info)
        .write_style(env_logger::WriteStyle::Always)
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .init();

    // Inicializar el motor de plantillas Tera
    let tera = Tera::new("templates/**/*").unwrap();
    println!("Server started at http://127.0.0.1:8080");

    // Iniciar el servidor
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(tera.clone()))
            .app_data(web::Data::new(client.clone()))
            .wrap(Logger::default())
            .wrap(NonceMiddleware)
    
            .service(fs::Files::new("/templates", "./templates").show_files_listing())
            .wrap(CookieSession::signed(&[0; 32]).secure(false)) // Configurar la sesión
            .service(web::resource("/").route(web::get().to(index)))
            .service(web::resource("/auth/login").route(web::get().to(auth_login)))
            .service(web::resource("/auth/callback").route(web::get().to(auth_callback)))
            .service(web::resource("/user").route(web::get().to(get_user_info)))
            .service(web::resource("/obtener_comentarios").route(web::get().to(obtener_comentarios)))
            
    })
    .bind("127.0.0.1:8080")
    .unwrap()
    .run()
    .await
    .unwrap();
}
