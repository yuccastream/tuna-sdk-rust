use super::*;
use api::{ConnectRequest, ConnectResponse, check_server_url, server_error};

fn server(status: u16, code: &str, before_connect: bool) -> Error {
    Error::Server {
        status,
        code: code.into(),
        message: "m".into(),
        request_id: String::new(),
        retry_after: None,
        before_connect,
    }
}

#[test]
fn permanent_errors() {
    for code in [
        "BadRequest",
        "Unauthorized",
        "AuthorizationRequired",
        "Forbidden",
        "NotFound",
        "PaymentRequired",
        "UpgradeRequired",
    ] {
        assert!(server(400, code, false).is_permanent(), "{code}");
    }
    assert!(server(404, "", true).is_permanent());
    assert!(!server(404, "", false).is_permanent());
    assert!(!server(408, "", true).is_permanent());
    assert!(!server(429, "", true).is_permanent());
    assert!(!server(503, "ServiceUnavailable", true).is_permanent());
    assert!(server(301, "", false).is_permanent());
    assert!(Error::Terminated { reason: "x".into() }.is_permanent());
    assert!(!Error::KeepAliveTimeout.is_permanent());
    assert!(!Error::Network("x".into()).is_permanent());
}

#[test]
fn error_texts() {
    assert_eq!(
        Error::KeepAliveTimeout.to_string(),
        "tuna: keepalive timeout"
    );
    assert_eq!(
        Error::Terminated {
            reason: "deleted".into()
        }
        .to_string(),
        "tuna: tunnel was deleted"
    );
    assert_eq!(
        Error::Terminated {
            reason: "odd".into()
        }
        .to_string(),
        "tuna: tunnel terminated by server (odd)"
    );
    let e = server_error(
        401,
        None,
        None,
        br#"{"code":"Unauthorized","error":"bad key","request_id":"r1"}"#,
    );
    assert_eq!(e.to_string(), "tuna: bad key (request id r1)");
}

#[test]
fn server_error_parsing() {
    match server_error(404, None, None, b"<html>not found</html>") {
        Error::Server { code, message, .. } => {
            assert_eq!(code, "");
            assert_eq!(message, "server responded with status 404");
        }
        e => panic!("{e:?}"),
    }
    match server_error(
        302,
        None,
        Some("https://x.example/"),
        b"{\"code\":\"NotFound\"}",
    ) {
        Error::Server { code, message, .. } => {
            assert_eq!(code, "");
            assert!(message.contains("https://x.example/"), "{message}");
        }
        e => panic!("{e:?}"),
    }
    let retry = |v| match server_error(503, Some(v), None, b"") {
        Error::Server { retry_after, .. } => retry_after,
        e => panic!("{e:?}"),
    };
    assert_eq!(retry("3"), Some(Duration::from_secs(3)));
    assert_eq!(retry("3600"), Some(Duration::from_secs(300)));
    assert_eq!(retry("0"), None);
    assert_eq!(retry("soon"), None);
}

#[test]
fn retry_delay_bounds_and_jitter() {
    let net = Error::Network("x".into());
    let mut seen = std::collections::HashSet::new();
    for backoff in [
        MIN_BACKOFF,
        Duration::from_secs(8),
        MAX_BACKOFF,
        MAX_BACKOFF * 2,
    ] {
        for _ in 0..50 {
            let d = retry_delay(backoff, &net);
            assert!(d >= MIN_BACKOFF && d <= MAX_BACKOFF, "{d:?}");
            seen.insert(d);
        }
    }
    assert!(seen.len() > 10);
    let mut e = server(503, "", false);
    if let Error::Server { retry_after, .. } = &mut e {
        *retry_after = Some(Duration::from_secs(120));
    }
    assert_eq!(retry_delay(MIN_BACKOFF, &e), Duration::from_secs(120));
}

#[test]
fn public_url_fallback() {
    let mut cr = ConnectResponse {
        domain_name: "demo.tuna.am".into(),
        ..Default::default()
    };
    assert_eq!(cr.public_url("http"), "https://demo.tuna.am");
    cr.domain_name = "ru.tuna.am".into();
    cr.endpoint_port = 40001;
    assert_eq!(cr.public_url("tcp"), "tcp://ru.tuna.am:40001");
    cr.public_url = "https://x.tuna.am".into();
    assert_eq!(cr.public_url("tcp"), "https://x.tuna.am");
}

#[test]
fn node_events() {
    assert!(matches!(
        parse_event(br#"{"type":"terminate","reason":"deleted"}"#),
        Some(Err(Error::Terminated { reason })) if reason == "deleted"
    ));
    assert!(matches!(
        parse_event(br#"{"type":"session_expiring","expires_in":300}"#),
        Some(Ok(Event::SessionExpiring { expires_in })) if expires_in == Duration::from_secs(300)
    ));
    assert!(parse_event(br#"{"type":"unknown","x":1}"#).is_none());
    assert!(parse_event(b"not json").is_none());
}

#[test]
fn server_urls() {
    assert!(check_server_url("https://api.tuna.am").is_ok());
    assert!(check_server_url("http://127.0.0.1:7070/").is_ok());
    assert!(check_server_url("ftp://api.tuna.am").is_err());
    assert!(check_server_url("api.tuna.am").is_err());
}

#[test]
fn connect_body() {
    let empty: Vec<String> = Vec::new();
    let allow = vec!["10.0.0.0/8".to_string()];
    let req = ConnectRequest {
        client_version: CLIENT_VERSION,
        client_name: "tuna-sdk-rust/0.1.0",
        sdk_version: VERSION,
        forwards_to: "",
        protocol: "tcp",
        location: "",
        subdomain: "",
        domain: "",
        token: "k",
        os: os(),
        arch: arch(),
        port_or_alias: "",
        tunnel_session_id: "",
        proxy_protocol: 0,
        cidr_allow_list: &allow,
        cidr_deny_list: &empty,
    };
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    assert_eq!(v["client_version"], 2);
    assert_eq!(v["tunnel_session_id"], "");
    assert_eq!(v["cidr_allow_list"][0], "10.0.0.0/8");
    assert!(v.get("cidr_deny_list").is_none());
}

#[tokio::test]
async fn options_validation() {
    let err = |o| async move { start(o, String::new()).await.err().unwrap() };
    let with_key = |f: fn(&mut Options)| {
        let mut o = Options {
            api_key: "k".into(),
            ..Default::default()
        };
        f(&mut o);
        o
    };
    assert!(matches!(
        err(with_key(|o| o.server_url = "ftp://x".into())).await,
        Error::InvalidOptions(_)
    ));
    assert!(matches!(
        err(with_key(|o| o.client_name = "a\nb".into())).await,
        Error::InvalidOptions(_)
    ));
}
