use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwapOption;
use hyper::{body::to_bytes, Body, Client, Request};
use hyper_tls::HttpsConnector;
use openidconnect::{
    core::CoreJsonWebKeySet, HttpRequest, HttpResponse, IssuerUrl, JsonWebKeySetUrl,
};
use tokio::time::{interval, sleep};
use tracing::{error, info};

pub mod token;

pub struct SignatureState {
    issuer_url: IssuerUrl,
    jwks_url: JsonWebKeySetUrl,
    jwks: ArcSwapOption<CoreJsonWebKeySet>,
}

impl SignatureState {
    pub fn from_issuer_url(issuer_url: IssuerUrl) -> Result<Self, String> {
        let jwks_url = issuer_url
            .join("cdn-cgi/access/certs")
            .map_err(|e| format!("Failed to construct JWKS URL from  issuer: {}", e))
            .map(JsonWebKeySetUrl::from_url)?;

        Ok(Self {
            issuer_url,
            jwks_url,
            jwks: ArcSwapOption::const_empty(),
        })
    }

    pub fn issuer_url(&self) -> IssuerUrl {
        self.issuer_url.clone()
    }

    pub fn has_jwks_loaded(&self) -> bool {
        self.jwks.load().is_some()
    }

    pub fn jwks(&self) -> Option<CoreJsonWebKeySet> {
        self.jwks.load().as_ref().map(|jwks| jwks.as_ref().clone())
    }
}

pub async fn manage_jwks_refreshing(state: Arc<SignatureState>) {
    info!("Starting background JWKS refresh task.");

    // This task manages the refreshing of the JWKS (JSON Web Key Set) data which is used to verify
    // that the given tokens we're being asked to validate come from the configured authentication
    // domain. We specifically handle the initial refresh when the application first starts, as well
    // as periodic refreshes to pull in updates as web keys are rolled, and so on.

    // Create our interval so that we try and refresh the web keys every hour. `Interval` will
    // always tick immediately after being created, so we drain the first tick manually.
    let mut refresh_interval = interval(Duration::from_secs(3600));
    refresh_interval.tick().await;

    loop {
        let new_jwks_result =
            CoreJsonWebKeySet::fetch_async(&state.jwks_url, drive_http_request).await;
        match new_jwks_result {
            Err(e) => {
                error!(
                    jwks_url = state.jwks_url.as_str(),
                    "Error during refreshing JWKS data: {}. Retrying in 5 seconds.", e,
                );
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            Ok(new_jwks) => {
                let should_update = match state.jwks.load().as_ref() {
                    None => true,
                    Some(existing_jwks) => existing_jwks.as_ref() != &new_jwks,
                };

                if should_update {
                    state.jwks.store(Some(Arc::new(new_jwks)));
                    info!(jwks_url = state.jwks_url.as_str(), "Refreshed JWKS data.");
                }
            }
        }

        // Wait until it's time to refresh the keys.
        refresh_interval.tick().await;
    }
}

pub async fn drive_http_request(mut request: HttpRequest) -> Result<HttpResponse, hyper::Error> {
    let client = {
        let https = HttpsConnector::new();
        Client::builder().build(https)
    };

    let mut request_builder = Request::builder()
        .method(request.method)
        .uri(request.url.as_str());
    request_builder.headers_mut().replace(&mut request.headers);
    let request = request_builder
        .body(Body::from(request.body))
        .expect("should not fail to build request");

    let response = client.request(request).await?;

    let status_code = response.status();
    let headers = response.headers().to_owned();
    let chunks = to_bytes(response.into_body()).await?;
    Ok(HttpResponse {
        status_code,
        headers,
        body: chunks.to_vec(),
    })
}
