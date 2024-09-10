use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder, Error, HttpMessage, middleware::Logger};
use futures::future::{ok, Ready};
use futures::Future;
use rand::Rng;
use sqlx::{MySqlPool, Row};
use std::pin::Pin;
use std::task::{Context, Poll};
use tera::Tera;
use std::fs::{OpenOptions, create_dir_all};
use log::LevelFilter;
use env_logger::Builder;
use mysql::{self, serde};


//DEFINIMOS MIDDLEWARE QUE GENERA UN NONCE ALEATORIO Y LO INSERTA EN EL CONTEXTO DE LA PETICIÓN
struct NonceMiddleware;

impl<S, B> Transform<S, ServiceRequest> for NonceMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = NonceMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(NonceMiddlewareService { service })
    }
}

//DEFINIMOS UNA ESTRUCTURA QUE CONTIENE EL SERVICIO Y AÑADE EL NONCE AL HEADER DE LA RESPUESTA

struct NonceMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for NonceMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let nonce: String = generate_nonce();
        req.extensions_mut().insert(nonce.clone());
        let fut: <S as Service<ServiceRequest>>::Future = self.service.call(req);
        Box::pin(async move {
            let mut res: ServiceResponse<B> = fut.await?;
            res.headers_mut().insert(
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_str(&format!(
                    "default-src 'self'; script-src 'nonce-{}' 'unsafe-inline'; base-uri 'self'",
                    nonce
                ))
                .unwrap(),
            );
            Ok(res)
        })
    }
}


//FUNCION QUE GENERA UN NONCE ALEATORIO
fn generate_nonce() -> String { // Función para generar un nonce aleatorio
    let nonce: [u8; 16] = rand::thread_rng().gen(); // Generar un nonce aleatorio
    base64::encode(&nonce) // Codificar el nonce en base64 y devolverlo
}


//DEFINIMOS LAS RUTAS Y SUS RESPUESTAS


async fn index(tera: web::Data<Tera>, req: HttpRequest) -> impl Responder { // Función para la ruta principal
    let mut ctx: tera::Context = tera::Context::new(); // Crear un contexto para la plantilla
    if let Some(nonce) = req.extensions().get::<String>() { // Obtener el nonce del contexto de la petición
        ctx.insert("nonce", nonce); // Insertar el nonce en el contexto
    } else { // Si no se encuentra el nonce
        return HttpResponse::NotFound().body("Nonce not found"); // Responder con un error
    }

        let pool: MySqlPool = MySqlPool::connect("mysql://diego:11211121@localhost/actix1").await.unwrap();
        let user = User::get_user_by_id(web::Data::new(pool.clone()), 1).await.unwrap();
        ctx.insert("registrodeusuarios", &user);

        
    let rendered: String = tera.render("index.html", &ctx).unwrap();
    HttpResponse::Ok().content_type("text/html").body(rendered)
}

async fn create_item(_req: HttpRequest) -> impl Responder { // Función para crear un item
    HttpResponse::Ok().body("Item created") // Respuesta simple
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
    let _ = create_dir_all("log"); // Crear el directorio log si no existe


    // Configurar el logger para escribir en log/log.txt
    let log_file = OpenOptions::new()
        .create(true) // Crear el archivo si no existe
        .write(true) // Habilitar la escritura
        .append(true) // Habilitar la escritura al final del archivo
        .open("log/log.txt") // Abrir el archivo log/log.txt
        .unwrap(); // Manejar errores con unwrap


        // Inicializar el logger
    Builder::new()
        .filter(None, LevelFilter::Info) // Configurar el nivel de registro aquí
        .write_style(env_logger::WriteStyle::Always) // Forzar el estilo de escritura
        .target(env_logger::Target::Pipe(Box::new(log_file))) // Escribir en el archivo log/log.txt
        .init(); // Inicializar el logger

    // Inicializar el motor de plantillas Tera
    let tera: Tera = Tera::new("templates/**/*").unwrap(); // Cargar todas las plantillas en la carpeta templates
    println!("Server started at http://127.0.0.1:8080"); // Imprimir mensaje de inicio

    // Iniciar el servidor
    let _ = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(tera.clone())) // Añadir motor de plantillas Tera
            .wrap(Logger::default()) // Añadir middleware de registro
            .wrap(NonceMiddleware) // Añadir middleware de Nonce
            .service(web::resource("/").route(web::get().to(index))) // Ruta principal
            .service(web::resource("/create").route(web::post().to(create_item))) // Ruta de creación de item
    })
    .bind("127.0.0.1:8080")
    .unwrap()
    .run()
    .await;

}