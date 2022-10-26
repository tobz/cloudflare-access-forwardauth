use std::collections::{hash_map::Iter, HashMap};

use axum::{
    headers,
    http::{header::HeaderName, HeaderValue},
};
use openidconnect::{
    core::{
        CoreGenderClaim, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    },
    AccessToken, AdditionalClaims, IdToken,
};
use serde::{Deserialize, Serialize};

pub type CloudflareAccessIdToken = IdToken<
    CloudflareAccessCustomClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

/// The "custom" claims from a Cloudflare Access JWT token.
#[derive(Debug, Deserialize, Serialize)]
pub struct CloudflareAccessCustomClaims {
    /// The custom claims.
    ///
    /// These are deroved from the additional "OIDC Claims" specified in the configuration of an
    /// OpenID Connect provider on the Cloudflare Access side.
    custom: HashMap<String, String>,
}

impl CloudflareAccessCustomClaims {
    /// Gets an iterator for visiting all custom claim mapping pairs, in arbitrary order.
    pub fn claims(&self) -> Iter<'_, String, String> {
        self.custom.iter()
    }
}

impl AdditionalClaims for CloudflareAccessCustomClaims {}

/// The [`Cf-Access-Jwt-Assertion`][1] header sent by Cloudflare Access.
///
/// [1]: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/
pub struct CloudflareAccessOIDCAccessToken(pub AccessToken);

impl headers::Header for CloudflareAccessOIDCAccessToken {
    fn name() -> &'static HeaderName {
        static HEADER_NAME: HeaderName = HeaderName::from_static("cf-access-jwt-assertion");
        &HEADER_NAME
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let value = values.next().ok_or_else(headers::Error::invalid)?;

        value
            .to_str()
            .map(|s| CloudflareAccessOIDCAccessToken(AccessToken::new(s.to_string())))
            .map_err(|_| headers::Error::invalid())
    }

    fn encode<E>(&self, _: &mut E)
    where
        E: Extend<HeaderValue>,
    {
    }
}
