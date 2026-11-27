use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::signal::unix::{SignalKind, signal};
use tuna_sdk::{Error, Event, Options, Protocol};

const USAGE: &str = "Usage:
  runner http|tcp <addr> [-s SUBDOMAIN] [-d DOMAIN] [-p PORT] [--proxy-protocol N]
                         [--cidr-allow CIDR]... [--cidr-deny CIDR]... [--listen]
                         [--log-format text|json] [--api-key KEY]

addr: 8080, 10.0.0.1:8080, http://localhost:8080, unix:///path/to.sock
Environment: TUNA_API_KEY, TUNA_ADDR, TUNA_LOCATION";

struct Args {
    options: Options,
    addr: String,
    listen: bool,
    json: bool,
}

fn parse_args(mut argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let protocol = match argv.next().as_deref() {
        Some("http") => Protocol::Http,
        Some("tcp") => Protocol::Tcp,
        _ => return Err(USAGE.into()),
    };
    let mut options = Options {
        protocol,
        server_url: std::env::var("TUNA_ADDR").unwrap_or_default(),
        location: std::env::var("TUNA_LOCATION").unwrap_or_default(),
        ..Default::default()
    };
    let (mut addr, mut listen, mut json) = (None, false, false);
    while let Some(arg) = argv.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with('-') => (f.to_owned(), Some(v.to_owned())),
            _ => (arg.clone(), None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| argv.next())
                .ok_or(format!("flag {flag} needs a value"))
        };
        match flag.as_str() {
            "-s" => options.subdomain = value()?,
            "-d" => options.domain = value()?,
            "-p" => options.port = value()?,
            "-l" => options.location = value()?,
            "--api-key" => options.api_key = value()?,
            "--proxy-protocol" => {
                options.proxy_protocol = value()?
                    .parse()
                    .map_err(|_| "--proxy-protocol must be 1 or 2".to_string())?
            }
            "--cidr-allow" => options.cidr_allow.push(value()?),
            "--cidr-deny" => options.cidr_deny.push(value()?),
            "--listen" => listen = true,
            "--log-format" => match value()?.as_str() {
                "json" => json = true,
                "text" => json = false,
                f => return Err(format!("unknown log format {f:?}, use text or json")),
            },
            _ if flag.starts_with('-') => return Err(format!("unknown flag {flag}\n{USAGE}")),
            _ if addr.is_none() => addr = Some(local_addr(&arg)?),
            _ => return Err(USAGE.into()),
        }
    }
    Ok(Args {
        options,
        addr: addr.ok_or(USAGE)?,
        listen,
        json,
    })
}

fn local_addr(s: &str) -> Result<String, String> {
    if s.starts_with("unix://") {
        return Ok(s.into());
    }
    if let Some(rest) = s.strip_prefix("http://") {
        let host = rest.split('/').next().unwrap_or_default();
        return Ok(
            if host
                .rsplit_once(':')
                .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
            {
                host.into()
            } else {
                format!("{host}:80")
            },
        );
    }
    if s.contains("://") {
        return Err(format!(
            "address {s:?}: only http:// and unix:// URLs are supported"
        ));
    }
    if !s.contains(':') {
        let port: u16 = s.parse().map_err(|_| {
            format!("address {s:?} is not a port, host:port, http:// URL or unix:// path")
        })?;
        return Ok(format!("127.0.0.1:{port}"));
    }
    Ok(s.into())
}

fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn printer(json: bool, addr: String) -> impl Fn(&Event) + Send + Sync {
    move |e| {
        let mut line = serde_json::Map::new();
        line.insert("time".into(), rfc3339_now().into());
        line.insert("event".into(), e.name().into());
        let mut put = |k: &str, v: serde_json::Value| {
            line.insert(k.into(), v);
        };
        let secs = |d: &Duration| serde_json::Value::from(d.as_secs_f64());
        let text = match e {
            Event::Connected { url } | Event::Reconnected { url } => {
                put("url", url.as_str().into());
                format!("Forwarding {url} -> {addr}")
            }
            Event::Reconnecting { error, retry_in } => {
                put("error", error.to_string().into());
                put("retry_in", secs(retry_in));
                format!("Connection error ({error}), retry in {retry_in:.1?}")
            }
            Event::Banner { message } => {
                put("message", message.as_str().into());
                message.clone()
            }
            Event::SessionExpiring { expires_in } => {
                put("expires_in", secs(expires_in));
                format!("Session expires in {expires_in:?}")
            }
            Event::Terminated { reason, message } => {
                put("reason", reason.as_str().into());
                put("message", message.as_str().into());
                message.clone()
            }
            Event::LocalError { error } => {
                put("error", error.to_string().into());
                format!("Local service unavailable: {error}")
            }
            _ => String::new(),
        };
        if json {
            let mut out = std::io::stdout().lock();
            let _ = serde_json::to_writer(&mut out, &line);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        } else {
            eprintln!("{text}");
        }
    }
}

fn print_error(json: bool, err: &Error) {
    if json {
        let line =
            serde_json::json!({"time": rfc3339_now(), "event": "error", "error": err.to_string()});
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    } else {
        eprintln!("Error: {err}");
    }
}

async fn proxy(tunnel: Arc<tuna_sdk::Tunnel>, addr: String) {
    while let Ok(mut remote) = tunnel.accept().await {
        let addr = addr.clone();
        tokio::spawn(async move {
            if let Ok(mut local) = tokio::net::TcpStream::connect(&addr).await {
                let _ = tokio::io::copy_bidirectional(&mut remote, &mut local).await;
            }
        });
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    args.options.on_event = Some(Arc::new(printer(args.json, args.addr.clone())));

    let (mut term, mut int) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(t), Ok(i)) => (t, i),
        _ => return ExitCode::FAILURE,
    };
    let stop = async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    };
    tokio::pin!(stop);

    let result = if args.listen {
        let tunnel = tokio::select! {
            t = tuna_sdk::listen(args.options) => t.map(Arc::new),
            _ = &mut stop => return ExitCode::SUCCESS,
        };
        match tunnel {
            Ok(tunnel) => {
                tokio::spawn(proxy(tunnel.clone(), args.addr));
                tokio::select! {
                    r = tunnel.wait() => r,
                    _ = &mut stop => {
                        tunnel.close();
                        let _ = tunnel.wait().await;
                        Ok(())
                    }
                }
            }
            Err(e) => Err(e),
        }
    } else {
        tokio::select! {
            r = tuna_sdk::forward(args.options, &args.addr) => r,
            _ = &mut stop => Ok(()),
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::Terminated { .. }) => ExitCode::FAILURE,
        Err(e) => {
            print_error(args.json, &e);
            ExitCode::FAILURE
        }
    }
}

#[test]
fn local_addrs() {
    assert_eq!(local_addr("8080").unwrap(), "127.0.0.1:8080");
    assert_eq!(local_addr("10.0.0.1:8080").unwrap(), "10.0.0.1:8080");
    assert_eq!(local_addr("http://localhost").unwrap(), "localhost:80");
    assert_eq!(
        local_addr("http://localhost:3000/x").unwrap(),
        "localhost:3000"
    );
    assert_eq!(
        local_addr("unix:///tmp/a.sock").unwrap(),
        "unix:///tmp/a.sock"
    );
    assert!(local_addr("https://x").is_err());
    assert!(local_addr("99999").is_err());
}
