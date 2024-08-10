//! Provides a way to get the real IP address of the client, to the best of our ability.

use axum::{extract::FromRequestParts, response::IntoResponse};
use http::{header::HeaderName, request::Parts, HeaderValue, StatusCode};
use std::{
    hash::Hash,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    str::FromStr,
};

/// Wrapper around `std::net::IpAddr` that can be extracted from the request parts.
///
/// This extractor will try to get the real IP address of the client, using the following headers:
/// - `x-forwarded-for`
/// - `x-real-ip`
/// - `client-ip` (used by some load balancers)
/// - `x-cluster-client-ip` (used by AWS sometimes)
/// - `cf-connecting-ip` (used by Cloudflare sometimes)
///
/// If none of these headers are found, it will return a 400 Bad Request via [`IpAddrRejection`],
/// or the error can be handled with a custom rejection handler with [`RateLimitLayerBuilder::handle_error`](crate::RateLimitLayerBuilder::handle_error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RealIp(pub IpAddr);

impl Deref for RealIp {
    type Target = IpAddr;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// IP Address not found, returns a 400 Bad Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpAddrRejection;

impl IntoResponse for IpAddrRejection {
    fn into_response(self) -> axum::response::Response {
        StatusCode::BAD_REQUEST.into_response()
    }
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for RealIp {
    type Rejection = IpAddrRejection;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        fn parse_ip(s: &HeaderValue) -> Option<IpAddr> {
            s.to_str().ok().and_then(|s| s.split(',').next().and_then(|s| IpAddr::from_str(s.trim()).ok()))
        }

        static HEADERS: [HeaderName; 5] = [
            HeaderName::from_static("x-forwarded-for"),
            HeaderName::from_static("x-real-ip"),
            HeaderName::from_static("client-ip"), // used by some load balancers
            HeaderName::from_static("x-cluster-client-ip"), // used by AWS sometimes
            HeaderName::from_static("cf-connecting-ip"), // used by Cloudflare sometimes
        ];

        for header in &HEADERS {
            if let Some(real_ip) = parts.headers.get(header).and_then(parse_ip) {
                return Ok(RealIp(real_ip));
            }
        }

        #[cfg(feature = "tokio")]
        if let Some(info) = parts.extensions.get::<axum::extract::ConnectInfo<SocketAddr>>() {
            return Ok(RealIp(info.ip()));
        }

        Err(IpAddrRejection)
    }
}
