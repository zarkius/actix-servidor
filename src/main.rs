use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder, Error, HttpMessage, middleware::Logger};
use futures::future::{ok, Ready};
use futures::Future;
use rand::Rng;
use std::pin::Pin;
use std::task::{Context, Poll};
use tera::Tera;
use std::fs::{OpenOptions, create_dir_all};
use log::LevelFilter;
use env_logger::Builder;

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
        let nonce = generate_nonce();
        req.extensions_mut().insert(nonce.clone());
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
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

fn generate_nonce() -> String {
    let nonce: [u8; 16] = rand::thread_rng().gen();
    base64::encode(&nonce)
}

async fn index(tera: web::Data<Tera>, req: HttpRequest) -> impl Responder {
    let mut ctx = tera::Context::new();
    if let Some(nonce) = req.extensions().get::<String>() {
        ctx.insert("nonce", nonce);
    } else {
        return HttpResponse::NotFound().body("Nonce not found");
    }

    let rendered = tera.render("index.html", &ctx).unwrap();
    HttpResponse::Ok().content_type("text/html").body(rendered)
}

async fn create_item(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("Item created")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Crear el directorio de logs si no existe
    create_dir_all("log")?;

    // Configurar el logger para escribir en log/log.txt
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("log/log.txt")
        .unwrap();

    Builder::new()
        .filter(None, LevelFilter::Info) // Configurar el nivel de registro aquí
        .write_style(env_logger::WriteStyle::Always)
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .init();

    let tera = Tera::new("templates/**/*").unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(tera.clone()))
            .wrap(Logger::default()) // Añadir middleware de registro
            .wrap(NonceMiddleware)
            .service(web::resource("/").route(web::get().to(index)))
            .service(web::resource("/create").route(web::post().to(create_item)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}