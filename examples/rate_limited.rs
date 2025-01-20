use std::{net::SocketAddr, time::Duration};

use axum::{
    extract::Extension,
    routing::{get, post, Router},
};
use axum_gcra::{extensions::RateLimiter, gcra::Quota, real_ip::RealIpPrivacyMask, RateLimitLayer};
use http::Method;

#[tokio::main]
async fn main() {
    type Hash = rustc_hash::FxBuildHasher;
    type Key = (RealIpPrivacyMask,); // note there can be multiple keys, but for this example we only use the IP address

    #[rustfmt::skip]
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/build", get(|| async { "Build info" }))
        .route("/penalize", get(|rl: Extension<RateLimiter<Key, Hash>>| async move {
            println!("{:?}", rl.key());

            rl.penalize(Duration::from_secs(50)).await;

            "You came to the wrong neighborhood"
        }))
        .route("/reset", post(|rl: Extension<RateLimiter<Key, Hash>>| async move {
            rl.reset().await;
        }))
        .route_layer(
            // the key is a tuple of the client's IP address and a constant value
            // `Extract` is a helper type that allows using stateless key extractors
            RateLimitLayer::<Key, (), Hash>::builder(())
            .with_default_quota(Quota::simple(Duration::from_secs(5)))
            // these could be simplified using a macro to insert the quota values using `add_quota` alongside the routes above
            .with_route((Method::GET, "/build"), Quota::simple(Duration::from_secs(2)))
            .with_route((Method::POST, "/reset"), Quota::simple(Duration::from_millis(1)))
            .with_extension(true) // required for the `Extension` extractor to work
            .with_global_fallback(true)
            .with_gc_interval(Duration::from_secs(5))
            .default_handle_error(),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    // `into_make_service_with_connect_info` is required to access the connection IP address
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async { _ = tokio::signal::ctrl_c().await })
        .await
        .unwrap();
}
