#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate iron;
extern crate iron_jwt;
extern crate bodyparser;
extern crate router;

use iron::prelude::*;
use iron::Handler;
use iron::status;
use iron::typemap;
use bodyparser::Struct;
use router::Router;
use iron_jwt::{JWTConfig, JWTMiddleware};

#[derive(Serialize, Deserialize)]
struct Claims {}

impl typemap::Key for Claims {
    type Value = Self;
}

fn hello(_req: &mut Request) -> IronResult<Response> {
    Ok(Response::with((status::Ok, "Hello, JWT")))
}

fn privileged(_req: &mut Request) -> IronResult<Response> {
    Ok(Response::with((status::Ok, "Privileged")))
}

#[derive(Debug)]
struct AuthError;
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Authentication error")
    }
}
impl std::error::Error for AuthError {
    fn description(&self) -> &str {
        "authentication error"
    }
}

struct AuthHandler(JWTMiddleware<Claims>);
impl Handler for AuthHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        #[derive(Clone, Deserialize)]
        struct Params {
            username: String,
            password: String,
        }
        let params = req.get::<Struct<Params>>()
                        .ok()
                        .and_then(|p| p)
                        .ok_or_else(|| IronError::new(AuthError, status::BadRequest))?;

        if params.username != "user1" || params.password != "user1" {
            return Err(IronError::new(AuthError, status::Unauthorized));
        }

        let claims = Claims {};
        let access_token = self.0.generate_token(claims).unwrap();
        #[derive(Serialize)]
        struct Payload {
            access_token: String,
        }
        let payload = Payload { access_token };
        let payload = serde_json::to_string(&payload).unwrap();
        Ok(Response::with((status::Created, payload)))
    }
}

fn main() {
    let secret_key = "secret-key";
    let config = JWTConfig {
        secret: secret_key.as_bytes().into(),
        header: Default::default(),
        validation: Default::default(),
    };
    let jwt = JWTMiddleware::new(config);

    let mut router = Router::new();
    router.get("/", hello, "hello");

    let mut privileged = Chain::new(privileged);
    privileged.link_before(jwt.clone());
    router.get("/privileged", privileged, "privileged");

    let auth = AuthHandler(jwt);
    router.post("/auth", auth, "auth");

    Iron::new(router).http("0.0.0.0:3000").unwrap();
}
