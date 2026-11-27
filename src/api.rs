use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HOST, LOCATION, RETRY_AFTER, USER_AGENT};
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::Error;

const API_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_SIZE: usize = 1 << 20;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

#[derive(Serialize)]
pub(crate) struct ConnectRequest<'a> {
    pub client_version: u32,
    pub client_name: &'a str,
    pub sdk_version: &'a str,
    pub forwards_to: &'a str,
    pub protocol: &'a str,
    pub location: &'a str,
    pub subdomain: &'a str,
    pub domain: &'a str,
    pub token: &'a str,
    pub os: &'a str,
    pub arch: &'a str,
    pub port_or_alias: &'a str,
    pub tunnel_session_id: &'a str,
    pub proxy_protocol: u8,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub cidr_allow_list: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub cidr_deny_list: &'a [String],
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ConnectResponse {
    pub tunnel_session_id: String,
    pub token: String,
    pub address: String,
    pub banner: String,
    pub public_url: String,
    pub domain_name: String,
    pub endpoint_port: u32,
    pub host_keys: Vec<HostKey>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct HostKey {
    pub key: String,
}

impl ConnectResponse {
    pub fn public_url(&self, protocol: &str) -> String {
        if !self.public_url.is_empty() {
            return self.public_url.clone();
        }
        if protocol == "tcp" {
            return format!("tcp://{}:{}", self.domain_name, self.endpoint_port);
        }
        format!("https://{}", self.domain_name)
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ErrorBody {
    code: String,
    error: String,
    request_id: String,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub(crate) struct Api {
    uri: Uri,
    user_agent: String,
    tls: Arc<ClientConfig>,
}

pub(crate) fn check_server_url(s: &str) -> Result<Uri, Error> {
    let invalid = || Error::InvalidOptions(format!("invalid server URL {s:?}: want https://host"));
    let uri: Uri = format!("{}/v1/connect", s.trim_end_matches('/'))
        .parse()
        .map_err(|_| invalid())?;
    match (uri.scheme_str(), uri.host()) {
        (Some("https" | "http"), Some(h)) if !h.is_empty() => Ok(uri),
        _ => Err(invalid()),
    }
}

impl Api {
    pub fn new(server_url: &str, user_agent: &str) -> Result<Api, Error> {
        use rustls_platform_verifier::BuilderVerifierExt;
        let tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .and_then(|b| b.with_platform_verifier())
            .map_err(|e| Error::InvalidOptions(format!("TLS setup: {e}")))?
            .with_no_client_auth();
        Ok(Api {
            uri: check_server_url(server_url)?,
            user_agent: user_agent.to_owned(),
            tls: Arc::new(tls),
        })
    }

    pub async fn connect(&self, req: &ConnectRequest<'_>) -> Result<ConnectResponse, Error> {
        let body = serde_json::to_vec(req).map_err(|e| Error::Network(e.to_string()))?;
        let (status, retry_after, location, body) =
            tokio::time::timeout(API_TIMEOUT, self.post(body))
                .await
                .map_err(|_| Error::Network("API request timed out".into()))??;
        if (200..300).contains(&status) {
            return serde_json::from_slice(&body)
                .map_err(|e| Error::Network(format!("invalid API response: {e}")));
        }
        Err(server_error(
            status,
            retry_after.as_deref(),
            location.as_deref(),
            &body,
        ))
    }

    async fn post(
        &self,
        body: Vec<u8>,
    ) -> Result<(u16, Option<String>, Option<String>, Bytes), Error> {
        let net = |e: &dyn std::fmt::Display| Error::Network(format!("API request: {e}"));
        let https = self.uri.scheme_str() == Some("https");
        let host = self.uri.host().unwrap_or_default();
        let bare_host = host.trim_start_matches('[').trim_end_matches(']');
        let port = self.uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let tcp = TcpStream::connect((bare_host, port))
            .await
            .map_err(|e| net(&e))?;
        let io: Box<dyn Io> = if https {
            let name = ServerName::try_from(bare_host.to_owned()).map_err(|e| net(&e))?;
            Box::new(
                TlsConnector::from(self.tls.clone())
                    .connect(name, tcp)
                    .await
                    .map_err(|e| net(&e))?,
            )
        } else {
            Box::new(tcp)
        };
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(|e| net(&e))?;
        tokio::spawn(conn);
        let authority = self.uri.authority().map(|a| a.as_str()).unwrap_or(host);
        let req = Request::post(self.uri.path())
            .header(HOST, authority)
            .header(USER_AGENT, &self.user_agent)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| net(&e))?;
        let resp = sender.send_request(req).await.map_err(|e| net(&e))?;
        let header = |name| {
            resp.headers()
                .get(name)
                .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok())
                .map(str::to_owned)
        };
        let status = resp.status().as_u16();
        let retry_after = header(RETRY_AFTER);
        let location = header(LOCATION);
        let body = Limited::new(resp.into_body(), MAX_RESPONSE_SIZE)
            .collect()
            .await
            .map_err(|e| net(&*e))?
            .to_bytes();
        Ok((status, retry_after, location, body))
    }
}

pub(crate) fn server_error(
    status: u16,
    retry_after: Option<&str>,
    location: Option<&str>,
    body: &[u8],
) -> Error {
    let redirect = (300..400).contains(&status);
    let mut b: ErrorBody = if redirect {
        ErrorBody::default()
    } else {
        serde_json::from_slice(body).unwrap_or_default()
    };
    if redirect {
        b.error = format!(
            "server redirects to {:?}, check the server URL",
            location.unwrap_or_default()
        );
    } else if b.error.is_empty() {
        b.error = format!("server responded with status {status}");
    }
    Error::Server {
        status,
        code: b.code,
        message: b.error,
        request_id: b.request_id,
        retry_after: retry_after
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(|s| Duration::from_secs(s).min(MAX_RETRY_AFTER)),
        before_connect: false,
    }
}
