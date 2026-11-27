//! Open tuna.am tunnels from Rust code.
//!
//! [`listen`] returns a [`Tunnel`] that accepts connections arriving at the
//! tunnel's public address as byte streams. [`forward`] proxies them to a
//! local address.
//!
//! A tunnel survives network failures: it reconnects with backoff and keeps
//! its public address. It ends on [`Tunnel::close`], [`Tunnel::abort`] or a
//! permanent error (see [`Error::is_permanent`]).
//!
//! The SDK runs on the Tokio runtime.

mod api;

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::client::{self, DisconnectReason, Msg};
use russh::keys::{PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, ChannelStream};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};

use api::{Api, ConnectRequest, ConnectResponse};

/// The SDK version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The tuna.am API used when [`Options::server_url`] is empty.
pub const DEFAULT_SERVER_URL: &str = "https://api.tuna.am";

const CLIENT_VERSION: u32 = 2;
const SSH_USER: &str = "tuna";
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const EVENTS_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const KEEPALIVE_MAX_UNANSWERED: usize = 2;
const EVENTS_COMMAND: &str = "events";
const MAX_EVENT_LINE: usize = 64 << 10;
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(15);

/// Tunnel protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    /// HTTP tunnel with a public `https://` address.
    #[default]
    Http,
    /// TCP tunnel with a public `tcp://host:port` address.
    Tcp,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Tcp => "tcp",
        }
    }
}

/// Callback that receives tunnel events.
pub type EventHandler = Arc<dyn Fn(&Event) + Send + Sync>;

/// Tunnel configuration. Every field is optional.
#[derive(Clone, Default)]
pub struct Options {
    /// A tuna.am API key with the `tunnels:connect` scope.
    /// Defaults to the `TUNA_API_KEY` environment variable.
    pub api_key: String,
    /// Tunnel protocol, HTTP by default.
    pub protocol: Protocol,
    /// Needed only for names and ports reserved in the legacy "ru" or "nl"
    /// zones. Empty lets the server pick the zone.
    pub location: String,
    /// A reserved subdomain for HTTP tunnels.
    pub subdomain: String,
    /// A custom domain for HTTP tunnels.
    pub domain: String,
    /// A reserved TCP port or its alias.
    pub port: String,
    /// Enables the PROXY protocol header (1 or 2) for TCP tunnels.
    pub proxy_protocol: u8,
    /// Client CIDRs allowed to reach a TCP tunnel.
    pub cidr_allow: Vec<String>,
    /// Client CIDRs rejected by a TCP tunnel.
    pub cidr_deny: Vec<String>,
    /// The tuna.am API address. Defaults to [`DEFAULT_SERVER_URL`].
    pub server_url: String,
    /// Reported to the server. Defaults to `tuna-sdk-rust/<VERSION>`.
    pub client_name: String,
    /// Limits how long [`listen`] and [`forward`] wait for the tunnel to come
    /// up for the first time. `None` means no limit. Reconnects are not
    /// limited.
    pub connect_timeout: Option<Duration>,
    /// Receives tunnel events. Calls never overlap, but they come from the
    /// tunnel's own tasks, so the handler must return quickly.
    pub on_event: Option<EventHandler>,
}

/// A change in the tunnel state.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// Sent once, when the tunnel comes up for the first time.
    Connected {
        /// The public address.
        url: String,
    },
    /// Sent when the tunnel comes up again after a failure.
    Reconnected {
        /// The public address.
        url: String,
    },
    /// Sent after a failed attempt or a lost connection, before the next attempt.
    Reconnecting {
        /// The cause.
        error: Error,
        /// The delay before the next attempt.
        retry_in: Duration,
    },
    /// A server message for the user.
    Banner {
        /// The message text.
        message: String,
    },
    /// The session time limit is near.
    SessionExpiring {
        /// The time left.
        expires_in: Duration,
    },
    /// The server closed the tunnel for good.
    Terminated {
        /// The machine-readable cause, e.g. "deleted" or "session_limit".
        reason: String,
        /// Human-readable text.
        message: String,
    },
    /// [`forward`] could not reach the local address.
    LocalError {
        /// The cause.
        error: Error,
    },
}

impl Event {
    /// The event name: "connected", "reconnecting", "terminated" and so on.
    pub fn name(&self) -> &'static str {
        match self {
            Event::Connected { .. } => "connected",
            Event::Reconnected { .. } => "reconnected",
            Event::Reconnecting { .. } => "reconnecting",
            Event::Banner { .. } => "banner",
            Event::SessionExpiring { .. } => "session_expiring",
            Event::Terminated { .. } => "terminated",
            Event::LocalError { .. } => "local_error",
        }
    }
}

/// A tunnel error.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// The options are invalid.
    InvalidOptions(String),
    /// An error response from the tuna.am API.
    Server {
        /// The HTTP status code.
        status: u16,
        /// The machine-readable error code.
        code: String,
        /// The human-readable error text.
        message: String,
        /// Identifies the request for tuna.am support.
        request_id: String,
        /// The delay requested by the server, if any.
        retry_after: Option<Duration>,
        /// The response came before the tunnel was up for the first time.
        before_connect: bool,
    },
    /// The server closed the tunnel for good.
    Terminated {
        /// The machine-readable cause, e.g. "deleted" or "session_limit".
        reason: String,
    },
    /// The node stopped answering keepalive requests.
    KeepAliveTimeout,
    /// A network or SSH failure; the tunnel retries after it.
    Network(String),
    /// The tunnel did not come up within [`Options::connect_timeout`].
    ConnectTimeout {
        /// The configured timeout.
        after: Duration,
        /// The last failed attempt, if any.
        last: Option<Box<Error>>,
    },
    /// The tunnel was closed.
    Closed,
}

impl Error {
    /// Reports whether retrying after the error is pointless.
    pub fn is_permanent(&self) -> bool {
        match self {
            Error::Terminated { .. } | Error::InvalidOptions(_) => true,
            Error::Server {
                status,
                code,
                before_connect,
                ..
            } => {
                (300..400).contains(status)
                    || (*before_connect
                        && (400..500).contains(status)
                        && *status != 408
                        && *status != 429)
                    || matches!(
                        code.as_str(),
                        "PaymentRequired"
                            | "Unauthorized"
                            | "AuthorizationRequired"
                            | "Forbidden"
                            | "BadRequest"
                            | "NotFound"
                            | "UpgradeRequired"
                    )
            }
            _ => false,
        }
    }
}

fn terminate_message(reason: &str) -> String {
    match reason {
        "deleted" => "tunnel was deleted".into(),
        "suspended" => "tunnel was suspended".into(),
        "session_limit" => "session time limit reached".into(),
        "session_ended" => "client session ended".into(),
        "reconnect" => "tunnel was taken over by another connection".into(),
        _ => format!("tunnel terminated by server ({reason})"),
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidOptions(m) | Error::Network(m) => write!(f, "tuna: {m}"),
            Error::Server {
                message,
                request_id,
                ..
            } if !request_id.is_empty() => write!(f, "tuna: {message} (request id {request_id})"),
            Error::Server { message, .. } => write!(f, "tuna: {message}"),
            Error::Terminated { reason } => write!(f, "tuna: {}", terminate_message(reason)),
            Error::KeepAliveTimeout => f.write_str("tuna: keepalive timeout"),
            Error::ConnectTimeout { after, last } => {
                write!(f, "tuna: tunnel did not come up within {after:?}")?;
                match last {
                    Some(e) => write!(f, " (last attempt: {e})"),
                    None => Ok(()),
                }
            }
            Error::Closed => f.write_str("tuna: tunnel closed"),
        }
    }
}

impl std::error::Error for Error {}

/// Connects the tunnel and returns once it is up or a permanent error occurs.
///
/// Use [`Options::connect_timeout`] to limit the wait for the first
/// connection. Dropping the returned [`Tunnel`] closes it like
/// [`Tunnel::close`].
pub async fn listen(options: Options) -> Result<Tunnel, Error> {
    start(options, String::new()).await
}

/// Proxies tunnel connections to `local_addr` (`host:port` or
/// `unix:///path.sock`). Runs until a permanent error occurs; dropping the
/// future closes the tunnel together with every proxied connection.
pub async fn forward(options: Options, local_addr: &str) -> Result<(), Error> {
    let tunnel = start(options, local_addr.to_owned()).await?;
    let _abort = AbortOnDrop(tunnel.shared.clone());
    tunnel.wait().await
}

struct AbortOnDrop(Arc<Shared>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn start(mut o: Options, forwards_to: String) -> Result<Tunnel, Error> {
    if o.api_key.is_empty() {
        o.api_key = std::env::var("TUNA_API_KEY").unwrap_or_default();
    }
    if o.api_key.is_empty() {
        return Err(Error::InvalidOptions(
            "API key is required: set Options::api_key or TUNA_API_KEY".into(),
        ));
    }
    if o.server_url.is_empty() {
        o.server_url = DEFAULT_SERVER_URL.into();
    }
    if o.client_name.is_empty() {
        o.client_name = format!("tuna-sdk-rust/{VERSION}");
    }
    if o.client_name.chars().any(char::is_control) {
        return Err(Error::InvalidOptions(
            "client_name must not contain control characters".into(),
        ));
    }
    let api = Api::new(&o.server_url, &o.client_name)?;

    let (conns_tx, conns_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (done_tx, done_rx) = watch::channel(None);
    let shared = Arc::new(Shared {
        on_event: o.on_event.take(),
        emit_lock: Mutex::new(()),
        url: Mutex::new(String::new()),
        last_err: Mutex::new(None),
        closing: watch::Sender::new(false),
        aborted: watch::Sender::new(false),
    });
    let connect_timeout = o.connect_timeout;
    let runner = Runner {
        o,
        api,
        forwards_to,
        shared: shared.clone(),
        conns: conns_tx,
        ready: Some(ready_tx),
        done: done_tx,
        session_id: String::new(),
        banner_shown: false,
        ever_up: false,
    };
    tokio::spawn(runner.run());
    let tunnel = Tunnel {
        shared,
        conns: tokio::sync::Mutex::new(conns_rx),
        done: done_rx,
    };
    let up = match connect_timeout {
        Some(after) => match tokio::time::timeout(after, ready_rx).await {
            Ok(r) => r.is_ok(),
            Err(_) => {
                tunnel.shared.abort();
                let last = lock(&tunnel.shared.last_err).take().map(Box::new);
                return Err(Error::ConnectTimeout { after, last });
            }
        },
        None => ready_rx.await.is_ok(),
    };
    if up {
        return Ok(tunnel);
    }
    Err(match tunnel.wait().await {
        Err(e) => e,
        Ok(()) => Error::Closed,
    })
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct Shared {
    on_event: Option<EventHandler>,
    emit_lock: Mutex<()>,
    url: Mutex<String>,
    last_err: Mutex<Option<Error>>,
    closing: watch::Sender<bool>,
    aborted: watch::Sender<bool>,
}

impl Shared {
    fn emit(&self, e: Event) {
        if let Some(h) = &self.on_event {
            let _guard = lock(&self.emit_lock);
            h(&e);
        }
    }

    fn close(&self) {
        self.closing.send_replace(true);
    }

    fn abort(&self) {
        self.close();
        self.aborted.send_replace(true);
    }
}

/// An open tunnel. It survives reconnects; [`Tunnel::accept`] fails only
/// after [`Tunnel::close`] or a permanent error.
pub struct Tunnel {
    shared: Arc<Shared>,
    conns: tokio::sync::Mutex<mpsc::UnboundedReceiver<Stream>>,
    done: watch::Receiver<Option<Result<(), Error>>>,
}

impl Tunnel {
    /// Waits for the next connection to the public address. Returns
    /// [`Error::Closed`] after [`Tunnel::close`].
    pub async fn accept(&self) -> Result<Stream, Error> {
        let mut closing = self.shared.closing.subscribe();
        if *closing.borrow() {
            return Err(Error::Closed);
        }
        let mut conns = self.conns.lock().await;
        tokio::select! {
            c = conns.recv() => match c {
                Some(c) => Ok(c.counted()),
                None => Err(match self.done.borrow().clone() {
                    Some(Err(e)) => e,
                    _ => Error::Closed,
                }),
            },
            _ = until(&mut closing) => Err(Error::Closed),
        }
    }

    /// Returns the current public address, e.g. `https://name.tuna.am` or
    /// `tcp://ru.tuna.am:40000`.
    pub fn url(&self) -> String {
        lock(&self.shared.url).clone()
    }

    /// Stops accepting connections and reconnecting. Connections accepted
    /// earlier keep working: the tunnel stays connected to the node until the
    /// last of them is closed. Use [`Tunnel::abort`] to cut them off as well.
    pub fn close(&self) {
        self.shared.close();
    }

    /// Closes the tunnel together with every accepted connection.
    pub fn abort(&self) {
        self.shared.abort();
    }

    /// Waits until the tunnel stops for good: `Ok` after [`Tunnel::close`]
    /// once the last accepted connection is closed, or the permanent error.
    pub async fn wait(&self) -> Result<(), Error> {
        let mut done = self.done.clone();
        match done.wait_for(Option::is_some).await {
            Ok(r) => r.clone().unwrap_or(Ok(())),
            Err(_) => Ok(()),
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.close();
    }
}

/// A connection to the tunnel's public address.
pub struct Stream {
    inner: ChannelStream<Msg>,
    active: Arc<watch::Sender<usize>>,
    counted: bool,
}

impl Stream {
    fn counted(mut self) -> Stream {
        self.active.send_modify(|n| *n += 1);
        self.counted = true;
        self
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if self.counted {
            self.active.send_modify(|n| *n -= 1);
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

struct Runner {
    o: Options,
    api: Api,
    forwards_to: String,
    shared: Arc<Shared>,
    conns: mpsc::UnboundedSender<Stream>,
    ready: Option<oneshot::Sender<()>>,
    done: watch::Sender<Option<Result<(), Error>>>,
    session_id: String,
    banner_shown: bool,
    ever_up: bool,
}

struct Node {
    handle: Arc<client::Handle<NodeHandler>>,
    chans: mpsc::UnboundedReceiver<Channel<Msg>>,
    lost: oneshot::Receiver<Error>,
}

impl Runner {
    async fn run(mut self) {
        let mut closing = self.shared.closing.subscribe();
        let mut backoff = MIN_BACKOFF;
        let result = loop {
            let (connected, mut err) = self.session().await;
            if *closing.borrow() {
                break Ok(());
            }
            if let Error::Server { before_connect, .. } = &mut err {
                *before_connect = !self.ever_up;
            }
            *lock(&self.shared.last_err) = Some(err.clone());
            if err.is_permanent() {
                if let Error::Terminated { reason } = &err {
                    self.shared.emit(Event::Terminated {
                        reason: reason.clone(),
                        message: terminate_message(reason),
                    });
                }
                break Err(err);
            }
            if connected {
                backoff = MIN_BACKOFF;
            }
            let wait = retry_delay(backoff, &err);
            self.shared.emit(Event::Reconnecting {
                error: err,
                retry_in: wait,
            });
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = until(&mut closing) => break Ok(()),
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        };
        self.done.send_replace(Some(result));
    }

    async fn session(&mut self) -> (bool, Error) {
        let mut closing = self.shared.closing.subscribe();
        let (cr, mut node) = tokio::select! {
            r = self.setup() => match r {
                Ok(v) => v,
                Err(e) => return (false, e),
            },
            _ = until(&mut closing) => return (false, Error::Closed),
        };

        let mut events = tokio::spawn(events(node.handle.clone(), self.shared.clone()));
        let mut events_done = false;

        let url = cr.public_url(self.o.protocol.as_str());
        *lock(&self.shared.url) = url.clone();
        if self.ever_up {
            self.shared.emit(Event::Reconnected { url });
        } else {
            self.ever_up = true;
            self.shared.emit(Event::Connected { url });
            if let Some(ready) = self.ready.take() {
                let _ = ready.send(());
            }
        }

        let active = Arc::new(watch::Sender::new(0usize));
        let mut idle = active.subscribe();
        let mut aborted = self.shared.aborted.subscribe();
        let mut is_closing = false;
        let err = loop {
            tokio::select! {
                biased;
                r = &mut events, if !events_done => {
                    events_done = true;
                    if let Ok(Some(e)) = r {
                        break e;
                    }
                }
                lost = &mut node.lost => {
                    if !events_done
                        && let Ok(Ok(Some(e))) = tokio::time::timeout(EVENTS_DRAIN_TIMEOUT, &mut events).await
                    {
                        break e;
                    }
                    break lost.unwrap_or_else(|_| connection_lost());
                }
                ch = node.chans.recv() => {
                    let Some(ch) = ch else {
                        break connection_lost();
                    };
                    let inner = ch.into_stream();
                    if is_closing {
                        continue;
                    }
                    let stream = Stream { inner, active: active.clone(), counted: false };
                    if self.forwards_to.is_empty() {
                        let _ = self.conns.send(stream);
                    } else {
                        tokio::spawn(pipe(stream.counted(), self.forwards_to.clone(), self.shared.clone()));
                    }
                }
                _ = until(&mut closing), if !is_closing => {
                    is_closing = true;
                }
                _ = until_zero(&mut idle), if is_closing => {
                    break Error::Closed;
                }
                _ = until(&mut aborted) => {
                    break Error::Closed;
                }
            }
        };
        events.abort();
        let _ = node
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
        (true, err)
    }

    async fn setup(&mut self) -> Result<(ConnectResponse, Node), Error> {
        let cr = self
            .api
            .connect(&ConnectRequest {
                client_version: CLIENT_VERSION,
                client_name: &self.o.client_name,
                sdk_version: VERSION,
                forwards_to: &self.forwards_to,
                protocol: self.o.protocol.as_str(),
                location: &self.o.location,
                subdomain: &self.o.subdomain,
                domain: &self.o.domain,
                token: &self.o.api_key,
                os: os(),
                arch: arch(),
                port_or_alias: &self.o.port,
                tunnel_session_id: &self.session_id,
                proxy_protocol: self.o.proxy_protocol,
                cidr_allow_list: &self.o.cidr_allow,
                cidr_deny_list: &self.o.cidr_deny,
            })
            .await?;
        self.session_id = cr.tunnel_session_id.clone();
        if !cr.banner.is_empty() && !self.banner_shown {
            self.banner_shown = true;
            self.shared.emit(Event::Banner {
                message: cr.banner.clone(),
            });
        }
        let mut node = dial(&cr).await?;
        let forward = node.handle.tcpip_forward("127.0.0.1", 0);
        tokio::select! {
            biased;
            lost = &mut node.lost => return Err(lost.unwrap_or_else(|_| connection_lost())),
            r = forward => if let Err(e) = r {
                if let Ok(lost) = node.lost.try_recv() {
                    return Err(lost);
                }
                return Err(Error::Network(format!("remote forward: {e}")));
            },
        }
        Ok((cr, node))
    }
}

async fn until(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
}

async fn until_zero(rx: &mut watch::Receiver<usize>) {
    let _ = rx.wait_for(|n| *n == 0).await;
}

fn connection_lost() -> Error {
    Error::Network("connection to node lost".into())
}

fn retry_delay(backoff: Duration, err: &Error) -> Duration {
    let wait = MAX_BACKOFF.min(MIN_BACKOFF + random_below(backoff));
    match err {
        Error::Server {
            retry_after: Some(ra),
            ..
        } if *ra > wait => *ra,
        _ => wait,
    }
}

fn random_below(d: Duration) -> Duration {
    let nanos = d.as_nanos() as u64;
    if nanos == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos(RandomState::new().build_hasher().finish() % nanos)
}

fn os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    }
}

fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        arch => arch,
    }
}

struct NodeHandler {
    host_keys: Vec<PublicKey>,
    chans: mpsc::UnboundedSender<Channel<Msg>>,
    lost: Option<oneshot::Sender<Error>>,
}

impl client::Handler for NodeHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => self
                .host_keys
                .iter()
                .any(|k| k.key_data() == key.key_data()),
            _ => false,
        })
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let _ = self.chans.send(channel);
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        let err = match reason {
            DisconnectReason::ReceivedDisconnect(info) => {
                Error::Network(format!("node closed the connection: {}", info.message))
            }
            DisconnectReason::Error(russh::Error::KeepaliveTimeout) => Error::KeepAliveTimeout,
            DisconnectReason::Error(e) => Error::Network(format!("connection to node lost: {e}")),
        };
        if let Some(lost) = self.lost.take() {
            let _ = lost.send(err);
        }
        Ok(())
    }
}

async fn dial(cr: &ConnectResponse) -> Result<Node, Error> {
    let host_keys = cr
        .host_keys
        .iter()
        .map(|k| PublicKey::from_openssh(k.key.trim()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::Network(format!("parse host key: {e}")))?;
    let addr = cr.address.as_str();
    let timed_out = || Error::Network(format!("connect to node {addr}: timed out"));
    let tcp = tokio::time::timeout(DIAL_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| timed_out())?
        .map_err(|e| Error::Network(format!("connect to node {addr}: {e}")))?;
    let _ = tcp.set_nodelay(true);

    let (chans_tx, chans) = mpsc::unbounded_channel();
    let (lost_tx, lost) = oneshot::channel();
    let handler = NodeHandler {
        host_keys,
        chans: chans_tx,
        lost: Some(lost_tx),
    };
    let config = Arc::new(client::Config {
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX_UNANSWERED,
        nodelay: true,
        ..Default::default()
    });
    let handshake = async {
        let mut handle =
            client::connect_stream(config, tcp, handler)
                .await
                .map_err(|e| match e {
                    russh::Error::UnknownKey => {
                        Error::Network(format!("host key verification failed for {addr}"))
                    }
                    e => Error::Network(format!("SSH handshake with {addr}: {e}")),
                })?;
        let auth = handle
            .authenticate_password(SSH_USER, cr.token.as_str())
            .await
            .map_err(|e| Error::Network(format!("SSH authentication with {addr}: {e}")))?;
        if !auth.success() {
            return Err(Error::Network(format!("node {addr} rejected the token")));
        }
        Ok(handle)
    };
    let handle = tokio::time::timeout(DIAL_TIMEOUT, handshake)
        .await
        .map_err(|_| timed_out())??;
    Ok(Node {
        handle: Arc::new(handle),
        chans,
        lost,
    })
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NodeEvent {
    #[serde(rename = "type")]
    kind: String,
    reason: String,
    expires_in: i64,
}

fn parse_event(line: &[u8]) -> Option<Result<Event, Error>> {
    let ev: NodeEvent = serde_json::from_slice(line).ok()?;
    match ev.kind.as_str() {
        "terminate" => Some(Err(Error::Terminated { reason: ev.reason })),
        "session_expiring" => Some(Ok(Event::SessionExpiring {
            expires_in: Duration::from_secs(ev.expires_in.max(0) as u64),
        })),
        _ => None,
    }
}

async fn events(handle: Arc<client::Handle<NodeHandler>>, shared: Arc<Shared>) -> Option<Error> {
    let mut ch = handle.channel_open_session().await.ok()?;
    ch.exec(true, EVENTS_COMMAND).await.ok()?;
    let mut buf = Vec::new();
    while let Some(msg) = ch.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                buf.extend_from_slice(&data);
                while let Some(i) = buf.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=i).collect();
                    match parse_event(&line) {
                        Some(Err(e)) => {
                            let _ = ch.close().await;
                            return Some(e);
                        }
                        Some(Ok(e)) => shared.emit(e),
                        None => {}
                    }
                }
                if buf.len() > MAX_EVENT_LINE {
                    return None;
                }
            }
            ChannelMsg::Failure | ChannelMsg::Eof | ChannelMsg::Close => return None,
            _ => {}
        }
    }
    None
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn connect_local(addr: &str) -> io::Result<Box<dyn Io>> {
    if let Some(path) = addr.strip_prefix("unix://") {
        #[cfg(unix)]
        return Ok(Box::new(tokio::net::UnixStream::connect(path).await?));
        #[cfg(not(unix))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unix sockets are not supported here: {path}"),
        ));
    }
    Ok(Box::new(tokio::net::TcpStream::connect(addr).await?))
}

async fn pipe(remote: Stream, addr: String, shared: Arc<Shared>) {
    let local = match tokio::time::timeout(DIAL_TIMEOUT, connect_local(&addr)).await {
        Ok(Ok(local)) => local,
        Ok(Err(e)) => {
            shared.emit(Event::LocalError {
                error: Error::Network(format!("dial {addr}: {e}")),
            });
            return;
        }
        Err(_) => {
            shared.emit(Event::LocalError {
                error: Error::Network(format!("dial {addr}: timed out")),
            });
            return;
        }
    };
    let (mut rr, mut rw) = tokio::io::split(remote);
    let (mut lr, mut lw) = tokio::io::split(local);
    tokio::select! {
        _ = tokio::io::copy(&mut rr, &mut lw) => {}
        _ = tokio::io::copy(&mut lr, &mut rw) => {}
    }
}

#[cfg(test)]
mod tests;
