use std::{future::ready, net::SocketAddr, str::FromStr, sync::Arc};

use axum::{
    extract::Path,
    headers::HeaderName,
    http::HeaderValue,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router, TypedHeader,
};
use convert_case::{Case, Casing};
use hyper::{Body, HeaderMap, Request, StatusCode};
use openidconnect::{ClientId, IdTokenVerifier, Nonce};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, Span};

use crate::validation::{
    service_auth::ServiceAuthTokenHeaderMap,
    token::{CloudflareAccessIdToken, CloudflareAccessOIDCAccessToken},
    SignatureState,
};

async fn readiness(Extension(state): Extension<Arc<SignatureState>>) -> Response<Body> {
    let status = if state.has_jwks_loaded() {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap()
}

async fn validate(
    Path(audience): Path<String>,
    TypedHeader(access_token): TypedHeader<CloudflareAccessOIDCAccessToken>,
    Extension(state): Extension<Arc<SignatureState>>,
    Extension(token_map): Extension<Arc<ServiceAuthTokenHeaderMap>>,
) -> impl IntoResponse {
    // If we have no JWKS data yet, we can't validate anything.
    let jwks = match state.jwks() {
        Some(jwks) => jwks,
        None => {
            error!("Validation request made before JWKS data was refreshed.");
            return (StatusCode::INTERNAL_SERVER_ERROR, None, ());
        }
    };

    // Now construct the validator, and don't bother validating the nonce.
    // TODO: _Can_ we actually validate it? Does it matter? Not clear.
    let verifier =
        IdTokenVerifier::new_public_client(ClientId::new(audience), state.issuer_url(), jwks);

    let nonce_verifier = |_: Option<&Nonce>| Ok(());

    let id_token = CloudflareAccessIdToken::from_str(access_token.0.secret()).expect("weeee");
    match id_token.claims(&verifier, &nonce_verifier) {
        Ok(claims) => {
            let cf_claims = claims.additional_claims();

            let mut headers = HeaderMap::new();

            // For each additional claim, we just turn it into an `X-Foo-Bar`-style header. This
            // means that even for "basic" claims like email or username or group, they must be
            // specified in the "OIDC Claims" section of the OIDC authentiation settings so they get
            // added to the right spot in the claims.
            for (claim_name, claim_value) in cf_claims.claims() {
                let claim_header_name = format!("X-{}", claim_name).to_case(Case::Train);
                let header_name = match HeaderName::from_str(&claim_header_name) {
                    Ok(header_name) => header_name,
                    Err(_) => {
                        debug!(
                            "Received invalid header name '{}' as part of custom claims.",
                            claim_name
                        );
                        continue;
                    }
                };

                let header_value = match HeaderValue::from_str(claim_value) {
                    Ok(header_value) => header_value,
                    Err(_) => {
                        debug!(
                            "Received invalid header value '{}' as part of custom claims.",
                            claim_value
                        );
                        continue;
                    }
                };

                headers.insert(header_name, header_value);
            }

            // If we have a service auth token, add any mapped headers to the header map.
            if let Some(service_auth_token_id) = cf_claims.get_service_token_id() {
                if let Some(mapped_headers) =
                    token_map.get_header_map_for_token(service_auth_token_id)
                {
                    for (header_name, header_value) in mapped_headers.iter() {
                        headers.insert(header_name.clone(), header_value.clone());
                    }
                }
            }

            (StatusCode::OK, Some(headers), ())
        }
        Err(e) => {
            error!(
                error = %e,
                "Failed to verify access token claims.",
            );
            (StatusCode::UNAUTHORIZED, None, ())
        }
    }
}

pub async fn run_api_endpoint(
    listen_address: &SocketAddr,
    state: Arc<SignatureState>,
    token_map: Arc<ServiceAuthTokenHeaderMap>,
) -> Result<(), String> {
    let app = Router::new()
        .route("/health/ready", get(readiness))
        .route("/health/live", get(|| ready(())))
        .route("/validate/:audience", get(validate))
        .layer(Extension(state))
        .layer(Extension(token_map))
        .layer(
            TraceLayer::new_for_http().on_request(|request: &Request<_>, _: &Span| {
                info!(
                    path = request.uri().path(),
                    method = %request.method(),
                    "Got request."
                );
            }),
        );

    info!("Listening on {}.", listen_address);

    axum::Server::bind(listen_address)
        .serve(app.into_make_service())
        .await
        .map_err(|e| format!("Failed to serve HTTP: {}", e))
}
