use actix_session::CookieSession;
use actix_web::{web, App, HttpServer, middleware::Logger};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use serde::Deserialize;
use tera::Tera;
use std::fs::{OpenOptions, create_dir_all};
use log::LevelFilter;
use env_logger::Builder;
use actix_files as fs;
//MODULOS
mod generador_de_nonces;
mod auth_google;
mod rutas;

use generador_de_nonces::NonceMiddleware;
use auth_google::{auth_login, auth_callback, get_user_info};
use rutas::{index, obtener_comentarios};
#[derive(Debug, Deserialize)]
struct OAuthRequest {
    code: String,
    state: String,
}

/* 
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
    */

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
