#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![warn(clippy::perf, clippy::style)]

use std::{
    any::TypeId,
    borrow::Cow,
    collections::HashMap,
    convert::Infallible,
    future::{Future, Ready},
    hash::{BuildHasher, Hash},
    ops::Deref,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    error_handling::HandleErrorLayer,
    extract::{FromRequestParts, MatchedPath as AxumMatchedPath, Request},
    response::{IntoResponse, Response},
};
use http::{request::Parts, Extensions, Method};
use tower::{Layer, Service};

type RandomState = foldhash::fast::RandomState;

#[cfg(feature = "real_ip")]
pub mod real_ip;

#[cfg(all(doc, feature = "real_ip"))]
use real_ip::RealIp; // needed for the doc link in the README

/// Trait for user-provided keys used to identify rate limiter entries.
///
/// Keys should be uniquely identifiable to avoid rate limiting other users,
/// e.g. using a user ID or IP address.
///
/// Keys must also implement [`FromRequestParts`] to extract the key from the request
/// within the rate limiter layer/service.
pub trait Key: Hash + Eq + Send + Sync + 'static {}

impl<K> Key for K where K: Hash + Eq + Send + Sync + 'static {}

pub trait State: Clone + Send + Sync + 'static {}

impl<S: Clone + Send + Sync + 'static> State for S {}

pub mod gcra;
pub use gcra::RateLimitError;

/// Interval for garbage collection of the rate limiter, which can be either
/// a number of requests or a time duration.
///
/// The default is 8192 requests.
///
/// Time durations require the `tokio` cargo feature to be enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GCInterval {
    /// Run garbage collection after a number of requests.
    ///
    /// This may temporarily block a request if the rate limiter is being cleaned,
    /// as that single request needs to wait on all parts of the table to be cleaned.
    ///
    /// Setting this to `u64::MAX` will disable garbage collection entirely.
    Requests(u64),

    /// Run garbage collection on a timed interval using a background task.
    ///
    /// This does not block the request, since it runs externally to the request.
    #[cfg(feature = "tokio")]
    Time(Duration),
}

impl Default for GCInterval {
    fn default() -> Self {
        GCInterval::Requests(8192)
    }
}

impl GCInterval {
    fn to_requests(self) -> u64 {
        match self {
            GCInterval::Requests(n) => n,

            #[cfg(feature = "tokio")]
            GCInterval::Time(_) => u64::MAX,
        }
    }
}

impl From<u64> for GCInterval {
    fn from(n: u64) -> Self {
        GCInterval::Requests(n)
    }
}

#[cfg(feature = "tokio")]
impl From<Duration> for GCInterval {
    fn from(d: Duration) -> Self {
        GCInterval::Time(d)
    }
}

/// A route for rate limiting, consisting of a path and method.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Route<'a> {
    pub method: Cow<'a, Method>,
    pub path: Cow<'a, str>,
}

impl<'a, P> From<(Method, P)> for Route<'a>
where
    P: Into<Cow<'a, str>>,
{
    fn from((method, path): (Method, P)) -> Self {
        Self {
            path: path.into(),
            method: Cow::Owned(method),
        }
    }
}

macro_rules! decl_route_methods {
    ($($fn:ident => $method:ident),*) => {
        impl<'a> Route<'a> {
            /// Create a new route with the given method and path.
            pub fn new(method: Method, path: impl Into<Cow<'a, str>>) -> Self {
                Route {
                    method: Cow::Owned(method),
                    path: path.into(),
                }
            }

            $(
                #[doc = concat!("Create a new route with the [`", stringify!($method), "`](Method::", stringify!($method), ") method.")]
                pub fn $fn(path: impl Into<Cow<'a, str>>) -> Route<'a> {
                    Route::new(Method::$method, path)
                }
            )*
        }
    };
}

decl_route_methods! {
    get     => GET,
    post    => POST,
    put     => PUT,
    delete  => DELETE,
    patch   => PATCH,
    options => OPTIONS,
    head    => HEAD,
    trace   => TRACE,
    connect => CONNECT
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RouteWithKey<T> {
    path: MatchedPath,
    method: Method,
    key: T,
}

impl<T> RouteWithKey<T> {
    #[inline]
    fn as_route(&self) -> Route {
        Route {
            path: Cow::Borrowed(&*self.path),
            method: Cow::Borrowed(&self.method),
        }
    }
}

/// Hashmap of quotas for rate limiting, mapping a path as passed to [`Router`](axum::Router) to a [`gcra::Quota`].
type Quotas = HashMap<Route<'static>, gcra::Quota, RandomState>;

#[derive(Debug, Clone)]
enum MatchedPath {
    Fallback,
    Axum(AxumMatchedPath),
}

impl Deref for MatchedPath {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        match self {
            MatchedPath::Fallback => "",
            MatchedPath::Axum(path) => path.as_str(),
        }
    }
}

impl PartialEq for MatchedPath {
    fn eq(&self, other: &Self) -> bool {
        let a = &**self;
        let b = &**other;

        // compare Arc pointers first
        a.as_ptr() == b.as_ptr() || a == b
    }
}

impl Eq for MatchedPath {}

impl Hash for MatchedPath {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (**self).hash(state);
    }
}

/// Rate limiter [`Service`] for axum.
///
/// This struct is not meant to be used directly, but rather through the [`RateLimitLayerBuilder`].
///
/// Note: The limiter is shared across all clones of the layer and service.
pub struct RateLimitService<I, K: Key = (), S: State = (), H: BuildHasher = RandomState> {
    inner: I,
    layer: RateLimitLayer<K, S, H>,
}

#[cfg(feature = "tokio")]
#[derive(Default, Clone)]
struct BuilderDropNotify {
    notify: Arc<tokio::sync::Notify>,
}

/// Builder for the rate limiter layer.
///
/// This struct is used to configure the rate limiter before building it.
pub struct RateLimitLayerBuilder<K = (), S = (), H: BuildHasher = RandomState> {
    quotas: Quotas,
    default_quota: gcra::Quota,
    set_ext: Option<Box<dyn SetExtension<K, S, H>>>,
    global_fallback: bool,
    gc_interval: GCInterval,
    state: S,

    #[cfg(feature = "tokio")]
    shutdown: BuilderDropNotify,
}

impl<K, S, H: BuildHasher> Drop for RateLimitLayerBuilder<K, S, H> {
    fn drop(&mut self) {
        #[cfg(feature = "tokio")]
        self.shutdown.notify.notify_waiters();
    }
}

/// Rate limiter [`Layer`] for axum.
///
/// This struct is not meant to be used directly, but rather through the [`RateLimitLayerBuilder`].
///
/// Note: The limiter is shared across all clones of the layer and service.
pub struct RateLimitLayer<K: Key = (), S = (), H: BuildHasher = RandomState> {
    builder: Arc<RateLimitLayerBuilder<K, S, H>>,
    limiter: Arc<gcra::RateLimiter<RouteWithKey<K>, H>>,
}

/// Object-safe trait for setting an extension on a request.
///
/// Used to insert the rate limiter into the request's extensions,
/// without knowing the type of the key except when the handler is defined and not further.
trait SetExtension<K: Key, S, H: BuildHasher>: Send + Sync + 'static {
    fn set_extension(&self, req: &mut Extensions, key: &RouteWithKey<K>, layer: RateLimitLayer<K, S, H>);
}

struct DoSetExtension;

impl<K: Key, S, H: BuildHasher> SetExtension<K, S, H> for DoSetExtension
where
    K: Clone,
    S: State,
    H: Send + Sync + 'static,
{
    fn set_extension(&self, req: &mut Extensions, key: &RouteWithKey<K>, layer: RateLimitLayer<K, S, H>) {
        req.insert(extensions::RateLimiter::<K, S, H> {
            key: key.clone(),
            layer,
        });
    }
}

impl<K: Key, S: State, H: BuildHasher> Clone for RateLimitLayer<K, S, H> {
    fn clone(&self) -> Self {
        Self {
            limiter: self.limiter.clone(),
            builder: self.builder.clone(),
        }
    }
}

impl<I: Clone, K: Key, S: State, H: BuildHasher> Clone for RateLimitService<I, K, S, H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<K: Key, S: State, H: BuildHasher> RateLimitLayer<K, S, H> {
    /// Begin building a new rate limiter layer starting with the default configuration.
    #[must_use]
    pub fn builder(state: S) -> RateLimitLayerBuilder<K, S, H> {
        RateLimitLayerBuilder::new(state)
    }
}

impl<K: Key, S: State, H: BuildHasher> RateLimitLayerBuilder<K, S, H> {
    #[must_use]
    pub fn new(state: S) -> Self {
        RateLimitLayerBuilder {
            state,
            quotas: Default::default(),
            default_quota: Default::default(),
            set_ext: None,
            global_fallback: false,
            gc_interval: GCInterval::default(),

            #[cfg(feature = "tokio")]
            shutdown: BuilderDropNotify::default(),
        }
    }

    /// Insert a route entry into the quota table for the rate limiter.
    pub fn add_route(&mut self, route: impl Into<Route<'static>>, quota: gcra::Quota) {
        self.add_routes(Some((route.into(), quota)));
    }

    /// Insert a route entry into the quota table for the rate limiter.
    #[must_use]
    pub fn with_route(mut self, route: impl Into<Route<'static>>, quota: gcra::Quota) -> Self {
        self.add_route(route.into(), quota);
        self
    }

    /// Insert many route entries into the quota table for the rate limiter.
    pub fn add_routes(&mut self, quotas: impl IntoIterator<Item = (impl Into<Route<'static>>, gcra::Quota)>) {
        self.quotas.extend(quotas.into_iter().map(|(route, quota)| (route.into(), quota)));
    }

    /// Insert many route entries into the quota table for the rate limiter.
    #[must_use]
    pub fn with_routes(
        mut self,
        quotas: impl IntoIterator<Item = (impl Into<Route<'static>>, gcra::Quota)>,
    ) -> Self {
        self.add_routes(quotas);
        self
    }

    /// Fallback quota for rate limiting if no specific quota is found for the path.
    #[must_use]
    pub fn with_default_quota(mut self, default_quota: gcra::Quota) -> Self {
        self.default_quota = default_quota;
        self
    }

    /// Set whether to use a global fallback shared rate-limiter for all paths not explicitly defined.
    #[must_use]
    pub fn with_global_fallback(mut self, global_fallback: bool) -> Self {
        self.global_fallback = global_fallback;
        self
    }

    /// Set the interval for which garbage collection for the rate limiter will occur.
    /// Garbage collection in this case is defined as removing old expired requests
    /// from the rate limiter table to avoid it growing indefinitely.
    ///
    /// The default is 8192 requests.
    ///
    /// If the `tokio` feature is enabled, this can also be a time [`Duration`],
    /// and a background task will be spawned to clean the rate limiter at the
    /// given time interval. Cleanup is asynchronous and will not block the request
    /// in this case.
    #[must_use]
    pub fn with_gc_interval(mut self, gc_interval: impl Into<GCInterval>) -> Self {
        self.gc_interval = gc_interval.into();
        self
    }

    /// Set whether to insert the [`RateLimiter`](extensions::RateLimiter) extension into the request
    /// to allow for manual rate limiting control downstream.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// use axum::{extract::Extension, routing::get, Router};
    /// use axum_gcra::{RateLimitLayer, extensions::RateLimiter};
    ///
    /// // Note this must be identical to the key used in the rate limiter layer
    /// type Key = ();
    ///
    /// let app = Router::<()>::new()
    ///     // access the rate limiter for this request
    ///     .route("/", get(|rl: Extension<RateLimiter<Key>>| async move {
    ///         rl.penalize(Duration::from_secs(50)).await;
    ///     }))
    ///     .route_layer(RateLimitLayer::<Key>::builder().with_extension(true).default_handle_error());
    #[must_use]
    pub fn with_extension(mut self, extend: bool) -> Self
    where
        K: Clone,
        H: Send + Sync + 'static,
    {
        self.set_ext = match extend {
            true => Some(Box::new(DoSetExtension) as Box<dyn SetExtension<K, S, H>>),
            false => None,
        };
        self
    }
}

impl<K: Key + Default, S: State + Default> Default for RateLimitLayerBuilder<K, S> {
    fn default() -> Self {
        RateLimitLayerBuilder::new(Default::default())
    }
}

/// Error wrapper for rate limiting errors or inner service errors.
#[derive(Debug)]
pub enum Error<Inner, Rejection> {
    /// Inner service error.
    ///
    /// For most axum services, this will be a [`Infallible`].
    Inner(Inner),

    /// Rate limiting error.
    ///
    /// This error is returned when the rate limiter has blocked the request,
    /// and will be passed to the [error handler](RateLimitLayerBuilder::handle_error).
    RateLimit(RateLimitError),

    /// Key extraction rejection.
    KeyRejection(Rejection),
}

impl<Inner, Rejection> IntoResponse for Error<Inner, Rejection>
where
    Inner: IntoResponse,
    Rejection: IntoResponse,
{
    fn into_response(self) -> Response {
        match self {
            Error::RateLimit(e) => e.into_response(),
            Error::KeyRejection(e) => e.into_response(),
            Error::Inner(e) => e.into_response(),
        }
    }
}

use futures_util::{future::BoxFuture, TryFuture};

pin_project_lite::pin_project! {
    #[doc(hidden)]
    #[project = RateLimitedResponseProj]
    pub enum RateLimitedResponse<B, I: Service<Request<B>>, S, K: FromRequestParts<S>> {
        RateLimiting {
            #[pin] f: BoxFuture<'static, Result<Parts, Error<I::Error, K::Rejection>>>,

            inner: I, // storing `I` separately helps avoid an `I: Sync` bound
            body: Option<B>, // similar story, helps avoid `B: Send + 'static` bound
        },

        Inner { #[pin] f: I::Future },
    }
}

impl<B, I, S, K> Future for RateLimitedResponse<B, I, S, K>
where
    I: Service<Request<B>, Future: TryFuture<Ok = I::Response, Error = I::Error>>,
    S: State,
    K: FromRequestParts<S>,
{
    type Output = Result<I::Response, Error<I::Error, K::Rejection>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.as_mut().project() {
                RateLimitedResponseProj::RateLimiting { inner, body, f } => match ready!(f.try_poll(cx)) {
                    Ok(req) => {
                        let req = Request::from_parts(req, body.take().expect("body is Some"));
                        let f = inner.call(req);
                        self.set(RateLimitedResponse::Inner { f })
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                },
                RateLimitedResponseProj::Inner { f } => match ready!(f.try_poll(cx)) {
                    Ok(ok) => return Poll::Ready(Ok(ok)),
                    Err(e) => return Poll::Ready(Err(Error::Inner(e))),
                },
            }
        }
    }
}

impl<K: Key, S: State, H: BuildHasher> RateLimitLayer<K, S, H> {
    async fn req_peek_key<F>(
        &self,
        mut key: RouteWithKey<K>,
        now: std::time::Instant,
        peek: F,
    ) -> Result<(), RateLimitError>
    where
        F: FnOnce(&RouteWithKey<K>),
    {
        let quota = match self.builder.quotas.get(&key.as_route()).copied() {
            Some(quota) => quota,
            None => {
                if self.builder.global_fallback {
                    key.path = MatchedPath::Fallback;
                }

                self.builder.default_quota
            }
        };

        self.limiter.req_peek_key(key, quota, now, peek).await
    }
}

async fn get_user_key<K, S>(parts: &mut Parts, state: &S) -> Result<K, K::Rejection>
where
    K: Key + FromRequestParts<S>,
{
    use core::mem::{size_of, transmute_copy};

    #[inline(always)]
    fn same_ty<A: 'static, B: 'static>() -> bool {
        let b = TypeId::of::<B>();

        // check same type or 1-tuple of the same layout
        TypeId::of::<A>() == b || (TypeId::of::<(A,)>() == b && size_of::<A>() == size_of::<B>())
    }

    // poor man's specialization

    if same_ty::<K, ()>() {
        return Ok(unsafe { transmute_copy::<_, K>(&()) });
    }

    #[cfg(feature = "real_ip")]
    if same_ty::<K, real_ip::RealIp>() {
        #[rustfmt::skip]
        let ip = parts.extensions.get::<real_ip::RealIp>().copied()
            .or_else(|| real_ip::get_ip_from_parts(parts));

        if let Some(ip) = ip {
            return Ok(unsafe { transmute_copy::<_, K>(&ip) });
        }
    }

    #[cfg(feature = "real_ip")]
    if same_ty::<K, real_ip::RealIpPrivacyMask>() {
        #[rustfmt::skip]
        let ip = parts.extensions.get::<real_ip::RealIp>().copied()
            .or_else(|| real_ip::get_ip_from_parts(parts));

        if let Some(ip) = ip {
            return Ok(unsafe { transmute_copy::<_, K>(&real_ip::RealIpPrivacyMask::from(ip)) });
        }
    }

    match K::from_request_parts(parts, state).await {
        Ok(key) => Ok(key),
        Err(rejection) => Err(rejection),
    }
}

impl<I, K, S, B, H> Service<Request<B>> for RateLimitService<I, K, S, H>
where
    I: Service<Request<B>, Future: TryFuture<Ok = I::Response, Error = I::Error>> + Clone + Send + 'static,
    K: Key + FromRequestParts<S>,
    S: State,
    H: BuildHasher + Send + Sync + 'static,
{
    type Response = I::Response;
    type Error = Error<I::Error, K::Rejection>;
    type Future = RateLimitedResponse<B, I, S, K>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Inner(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        // try to get the current time as close as possible to the request
        let now = Instant::now();

        let path = match req.extensions().get::<AxumMatchedPath>() {
            Some(path) => MatchedPath::Axum(path.clone()),
            None => MatchedPath::Fallback,
        };

        let (mut parts, body) = req.into_parts();

        let layer = self.layer.clone();

        RateLimitedResponse::RateLimiting {
            inner: self.inner.clone(),
            body: Some(body), // once told me

            f: Box::pin(async move {
                let key = RouteWithKey {
                    key: get_user_key(&mut parts, &layer.builder.state).await.map_err(Error::KeyRejection)?,
                    path,
                    method: parts.method.clone(),
                };

                let res = layer.req_peek_key(key, now, |key| {
                    if let Some(ref set_ext) = layer.builder.set_ext {
                        // set_extension will clone the key internally
                        set_ext.set_extension(&mut parts.extensions, key, layer.clone());
                    }
                });

                match res.await {
                    Ok(()) => Ok(parts),
                    Err(e) => Err(Error::RateLimit(e)),
                }
            }),
        }
    }
}

impl<K, S, I, H> Layer<I> for RateLimitLayer<K, S, H>
where
    K: Key,
    S: State,
    H: BuildHasher,
{
    type Service = RateLimitService<I, K, S, H>;

    fn layer(&self, inner: I) -> Self::Service {
        RateLimitService {
            inner,
            layer: self.clone(),
        }
    }
}

use tower::layer::util::Stack;

impl<K, S: State, H: BuildHasher> RateLimitLayerBuilder<K, S, H>
where
    K: Key + FromRequestParts<S>,
    H: Default + Send + Sync + 'static,
{
    /// Build the [`RateLimitLayer`].
    ///
    /// This will create a new rate limiter and, if the `tokio` feature is
    /// enabled and the [GC interval](RateLimitLayerBuilder::with_gc_interval)
    /// is a time [`Duration`], spawn a background task for garbage collection.
    ///
    /// By itself, `RateLimitLayer` cannot be directly inserted into an [`axum::Router`],
    /// as it requires a [`HandleErrorLayer`] to handle rate limiting errors.
    /// Use [`RateLimitLayerBuilder::handle_error`] or [`RateLimitLayerBuilder::default_handle_error`] to create a stack
    /// with the rate limiter layer and the error-handler layer combined.
    #[must_use]
    pub fn build(self) -> RateLimitLayer<K, S, H> {
        let limiter = Arc::new(gcra::RateLimiter::new(self.gc_interval.to_requests(), H::default()));

        #[cfg(feature = "tokio")]
        if let GCInterval::Time(d) = self.gc_interval {
            let limiter = limiter.clone();
            let signal = self.shutdown.clone();

            _ = tokio::task::spawn(async move {
                let mut interval = tokio::time::interval(d);
                loop {
                    tokio::select! { biased;
                        _ = signal.notify.notified() => break,
                        _ = interval.tick() => {},
                    }

                    limiter.clean(Instant::now()).await;

                    // also close task if no more references to the limiter
                    if Arc::strong_count(&limiter) == 1 {
                        break;
                    }
                }
            });
        }

        RateLimitLayer {
            limiter,
            builder: Arc::new(self),
        }
    }

    /// Create a new rate limiter layer with the provided error-handler callback.
    ///
    /// Returns a [`Stack`]-ed layer with the rate limiter layer and the error-handler layer combined
    /// that can be directly inserted into an [`axum::Router`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use axum::{Router, http::StatusCode};
    /// use axum_gcra::RateLimitLayer;
    ///
    /// let builder = RateLimitLayer::<()>::builder();
    ///
    /// let app = Router::<()>::new().route_layer(
    ///    builder.handle_error(|e| async move {
    ///       StatusCode::TOO_MANY_REQUESTS
    ///    }));
    /// ```
    #[must_use]
    pub fn handle_error<F, R>(self, cb: F) -> Stack<RateLimitLayer<K, S, H>, HandleErrorLayer<F, ()>>
    where
        F: Fn(Error<Infallible, K::Rejection>) -> R + Clone,
    {
        Stack::new(self.build(), HandleErrorLayer::new(cb))
    }

    /// Create a new rate limiter layer with the default error-handler callback that simply returns the error
    /// as a [`Response`].
    ///
    /// Returns a [`Stack`]-ed layer with the rate limiter layer and the error-handler layer combined
    /// that can be directly inserted into an [`axum::Router`].
    #[allow(clippy::type_complexity)]
    #[must_use]
    pub fn default_handle_error(
        self,
    ) -> Stack<
        RateLimitLayer<K, S, H>,
        HandleErrorLayer<impl Fn(Error<Infallible, K::Rejection>) -> Ready<Response> + Clone, ()>,
    >
    where
        K::Rejection: IntoResponse,
    {
        self.handle_error(|e| core::future::ready(e.into_response()))
    }
}

/// Defines the [`RateLimiter`](extensions::RateLimiter) extension for the request's extensions,
/// extractable with [`Extension<RateLimiter<Key>>`](axum::extract::Extension).
pub mod extensions {
    use super::*;

    /// [`Request`] extension to access the internal rate limiter used during that request,
    /// such as to apply a penalty or reset the rate limit.
    ///
    /// Note that the `K: Key` and `H: BuildHasher` types must be the
    /// exact same as those given to the [`RateLimitLayerBuilder`]/[`RateLimitLayer`].
    pub struct RateLimiter<K: Key = (), S = (), H: BuildHasher = RandomState> {
        pub(crate) key: RouteWithKey<K>,
        pub(crate) layer: RateLimitLayer<K, S, H>,
    }

    impl<K: Key + Clone, S: State, H: BuildHasher> Clone for RateLimiter<K, S, H> {
        fn clone(&self) -> Self {
            Self {
                key: self.key.clone(),
                layer: self.layer.clone(),
            }
        }
    }

    impl<K: Key, S: State, H: BuildHasher> RateLimiter<K, S, H> {
        /// Get the key used to identify the rate limiter entry.
        #[inline(always)]
        pub fn key(&self) -> &K {
            &self.key.key
        }

        /// Get the path of the route that was rate limited.
        pub fn path(&self) -> &str {
            &self.key.path
        }

        /// Get the method of the route that was rate limited.
        pub fn method(&self) -> &Method {
            &self.key.method
        }

        /// Get the quota for the route that was rate limited.
        pub fn quota(&self) -> gcra::Quota {
            self.layer.builder.quotas.get(&self.key.as_route()).copied().expect("no quota found for route")
        }

        /// See [`gcra::RateLimiter::penalize`] for more information.
        pub async fn penalize(&self, penalty: Duration) -> bool {
            self.layer.limiter.penalize(&self.key, penalty).await
        }

        /// See [`gcra::RateLimiter::penalize_sync`] for more information.
        pub fn penalize_sync(&self, penalty: Duration) -> bool {
            self.layer.limiter.penalize_sync(&self.key, penalty)
        }

        /// See [`gcra::RateLimiter::reset`] for more information.
        pub async fn reset(&self) -> bool {
            self.layer.limiter.reset(&self.key).await
        }

        /// See [`gcra::RateLimiter::reset_sync`] for more information.
        pub fn reset_sync(&self) -> bool {
            self.layer.limiter.reset_sync(&self.key)
        }

        /// See [`gcra::RateLimiter::clean`] for more information.
        pub async fn clean(&self, before: Instant) {
            self.layer.limiter.clean(before).await;
        }

        /// See [`gcra::RateLimiter::clean_sync`] for more information.
        pub fn clean_sync(&self, before: Instant) {
            self.layer.limiter.clean_sync(before);
        }
    }
}
