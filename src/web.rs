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
use hyper::{Body, HeaderMap, StatusCode, Request};
use openidconnect::{ClientId, IdTokenVerifier, Nonce};
use tower_http::trace::TraceLayer;
use tracing::{error, info, Span};

use crate::validation::{
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
) -> impl IntoResponse {
    // If we have no JWKS data yet, we can't validate anything.
    let jwks = match state.jwks() {
        Some(jwks) => jwks,
        None => {
            error!("Validation request made before JWKS data was refreshed.");
            return (StatusCode::INTERNAL_SERVER_ERROR, None, ());
        }
    };

    // Now construct the validater, and don't bother validating the nonce.
    // TODO: _Can_ we actually validate it? Does it matter? Not clear.
    let verifier =
        IdTokenVerifier::new_public_client(ClientId::new(audience), state.issuer_url(), jwks);

    let nonce_verifier = |_: Option<&Nonce>| Ok(());

    let id_token = CloudflareAccessIdToken::from_str(access_token.0.secret()).expect("weeee");
    match id_token.claims(&verifier, &nonce_verifier) {
        Ok(claims) => {
            // For each additional claim, we just turn it into an `X-Foo-Bar`-style header. This
            // means that even for "basic" claims like email or username or group, they must be
            // specified in the "OIDC Claims" section of the OIDC authentiation settings so they get
            // added to the right spot in the claims.
            let headers = claims.additional_claims().claims().try_fold(
                HeaderMap::new(),
                |mut acc, (claim_name, claim_value)| {
                    let claim_header_name = format!("X-{}", claim_name).to_case(Case::Train);
                    let header_name = HeaderName::from_str(&claim_header_name);
                    let header_value = HeaderValue::from_str(claim_value);
                    header_name
                        .map_err(|_| format!("Invalid header name '{}'", claim_header_name))
                        .and_then(|hn| {
                            header_value
                                .map_err(|_| {
                                    format!(
                                        "Invalid header value for header '{}'",
                                        claim_header_name
                                    )
                                })
                                .map(move |hv| {
                                    acc.append(hn, hv);
                                    acc
                                })
                        })
                },
            );

            match headers {
                Ok(headers) => (StatusCode::OK, Some(headers), ()),
                Err(e) => {
                    error!(
                        error = %e,
                        "Failed to add response headers to valid authorization response.",
                    );
                    (StatusCode::UNAUTHORIZED, None, ())
                }
            }
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
) -> Result<(), String> {
    let app = Router::new()
        .route("/health/ready", get(readiness))
        .route("/health/live", get(|| ready(())))
        .route("/validate/:audience", get(validate))
        .layer(Extension(state))
        .layer(TraceLayer::new_for_http()
            .on_request(|request: &Request<_>, _: &Span| {
                info!(
                    path = request.uri().path(),
                    method = %request.method(),
                    "Got request."
                );
            }));

    info!("Listening on {}.", listen_address);

    axum::Server::bind(listen_address)
        .serve(app.into_make_service())
        .await
        .map_err(|e| format!("Failed to serve HTTP: {}", e))
}
