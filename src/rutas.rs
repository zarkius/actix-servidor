use actix_web::{web, HttpRequest, HttpResponse, Responder, HttpMessage};
use sqlx::{MySqlPool, Row};
use tera::Tera;

//DEFINIMOS LAS RUTAS Y SUS RESPUESTAS
pub async fn index(tera: web::Data<Tera>, req: HttpRequest) -> impl Responder {
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

pub async fn obtener_comentarios() -> impl Responder {
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