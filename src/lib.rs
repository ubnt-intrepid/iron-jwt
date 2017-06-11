extern crate iron;
extern crate jsonwebtoken as jwt;
extern crate serde;
extern crate serde_json;

use std::fmt;
use std::error::Error;
use std::marker::PhantomData;
use iron::{Request, IronResult, IronError};
use iron::headers::{Authorization, Bearer};
use iron::middleware::BeforeMiddleware;
use iron::status;
use iron::typemap;
use serde::{Serialize, Deserialize};

// re-exports
pub use jwt::Header as HeaderConfig;
pub use jwt::Validation as ValidationConfig;


#[derive(Debug)]
pub struct JWTError(pub &'static str);

impl fmt::Display for JWTError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "JWT error: {}", self.0)
    }
}

impl Error for JWTError {
    fn description(&self) -> &str {
        "JWT error"
    }
}


/// marker trait to represent trait alias.
pub trait JWTClaims<'de>
    where Self: 'static + Send + Sync + Serialize + Deserialize<'de> + typemap::Key<Value = Self>
{
}

impl<'de, T> JWTClaims<'de> for T
    where T: 'static + Send + Sync + Serialize + Deserialize<'de> + typemap::Key<Value = T>
{
}


#[derive(Clone, Default)]
pub struct JWTConfig {
    pub secret: Vec<u8>,
    pub header: HeaderConfig,
    pub validation: ValidationConfig,
}


///
pub struct JWTMiddleware<T>
    where for<'de> T: JWTClaims<'de>
{
    config: JWTConfig,
    _marker: PhantomData<T>,
}

impl<T> Clone for JWTMiddleware<T>
    where for<'de> T: JWTClaims<'de>
{
    fn clone(&self) -> Self {
        JWTMiddleware {
            config: self.config.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T> JWTMiddleware<T>
    where for<'de> T: JWTClaims<'de>
{
    pub fn new(config: JWTConfig) -> Self {
        JWTMiddleware {
            config,
            _marker: PhantomData,
        }
    }

    pub fn generate_token(&self, claims: T) -> IronResult<String> {
        let claims = serde_json::to_value(claims)
            .map_err(|err| IronError::new(err, status::InternalServerError))?;
        jwt::encode(&self.config.header, &claims, self.config.secret.as_slice())
            .map_err(|err| IronError::new(err, status::InternalServerError))
    }

    pub fn extract_claims(&self, req: &mut Request) -> IronResult<Option<T>> {
        let &Authorization(Bearer { ref token }) =
            match req.headers
                     .get::<Authorization<Bearer>>() {
                Some(token) => token,
                None => return Ok(None),
            };
        jwt::decode(&token,
                    self.config.secret.as_slice(),
                    &self.config.validation)
            .map_err(|err| IronError::new(err, status::Unauthorized))
            .map(|token_data| Some(token_data.claims))
    }
}

impl<T> BeforeMiddleware for JWTMiddleware<T>
    where for<'de> T: JWTClaims<'de> + typemap::Key<Value = T>
{
    fn before(&self, req: &mut Request) -> IronResult<()> {
        self.extract_claims(req)
            .and_then(|c| c.ok_or(IronError::new(JWTError(""), status::Unauthorized)))
            .map(|claims| { req.extensions.insert::<T>(claims); })
    }
}
