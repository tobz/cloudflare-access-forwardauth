use std::collections::HashMap;

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
use serde_json::Value;

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
    #[serde(default)]
    custom: HashMap<String, Value>,

    /// The Cloudflare Access Service Auth Token ID.
    ///
    /// When using Service Auth tokens to authenticate requests, the client ID will be sent as the
    /// "common name" in the JWT to identify which service token was used.
    #[serde(rename = "common_name")]
    service_token_id: Option<String>,
}

impl CloudflareAccessCustomClaims {
    /// Gets an iterator for visiting all custom claim mapping pairs, in arbitrary order.
    pub fn claims(&self) -> impl Iterator<Item = (&str, &str)> {
        self.custom
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|v| (k.as_str(), v)))
    }

    /// Gets the service token ID, if it exists.
    pub fn get_service_token_id(&self) -> Option<&str> {
        self.service_token_id.as_deref()
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
