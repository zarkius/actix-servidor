


use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage};
use futures::future::{ok, Ready};
use futures::Future;
use rand::Rng;
use std::pin::Pin;
use std::task::{Context, Poll};

pub(crate) struct NonceMiddleware;

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

pub struct NonceMiddlewareService<S> {
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
            // Ignorar el nonce en las rutas /oauth/login y /oauth/callback
            if res.request().path() != "/oauth/login" && res.request().path() != "/oauth/callback" {
                res.headers_mut().insert(
                    HeaderName::from_static("content-security-policy"),
                    HeaderValue::from_str(&format!("script-src 'nonce-{}'", nonce)).unwrap(),
                );
            }
            Ok(res)
        })
    }
}

//FUNCION QUE GENERA UN NONCE ALEATORIO
fn generate_nonce() -> String {
    let nonce: [u8; 16] = rand::thread_rng().gen();
    base64::encode(&nonce)
}