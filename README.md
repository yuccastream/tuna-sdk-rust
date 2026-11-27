# tuna-sdk-rust

Open [tuna.am](https://tuna.am) tunnels straight from Rust code: expose a
local HTTP or TCP service at a public address without installing the `tuna`
CLI.

- Two ways in: `listen` returns a `Tunnel` that accepts connections as byte
  streams (`AsyncRead + AsyncWrite`), `forward` proxies them to a local
  address.
- Survives network failures: reconnects with backoff and keeps the same
  public address.
- Runs on Tokio; SSH is [russh](https://crates.io/crates/russh), TLS is
  rustls, cryptography is `ring`.

The API is not stable yet: it may change before v1.

## Install

```shell
cargo add tuna-sdk
```

The library name is `tuna_sdk`. Requires Rust 1.89 or later and a C compiler
for `ring` (`gcc` or `clang`; no cmake or Go).

## Authentication

Create an API key with the `tunnels:connect` scope at
[my.tuna.am](https://my.tuna.am) and pass it in `Options::api_key` or the
`TUNA_API_KEY` environment variable.

## Accept connections

```rust
use tuna_sdk::{Options, Protocol};

let tunnel = tuna_sdk::listen(Options {
    protocol: Protocol::Http,
    ..Default::default()
})
.await?;
println!("public URL: {}", tunnel.url());

while let Ok(mut visitor) = tunnel.accept().await {
    tokio::spawn(async move {
        let mut local = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;
        tokio::io::copy_bidirectional(&mut visitor, &mut local).await?;
        Ok::<_, std::io::Error>(())
    });
}
```

`close` stops accepting and reconnecting, but the tunnel stays connected
until the last accepted stream is dropped; `wait` resolves after that.
`abort` cuts off every accepted stream at once. Dropping the `Tunnel` closes
it like `close`.

## Forward to a local service

```rust
use std::sync::Arc;
use tuna_sdk::{Event, Options, Protocol};

tuna_sdk::forward(
    Options {
        protocol: Protocol::Tcp,
        port: "my-db".into(),
        on_event: Some(Arc::new(|e: &Event| {
            if let Event::Connected { url } = e {
                eprintln!("forwarding {url} -> 127.0.0.1:5432");
            }
        })),
        ..Default::default()
    },
    "127.0.0.1:5432",
)
.await?;
```

The local address is `host:port` or `unix:///path/to.sock`. `forward` runs
until the tunnel ends for good; drop the future (for example in
`tokio::select!` with a shutdown signal) to stop it.

[`examples/runner.rs`](examples/runner.rs) is a complete command-line client
built on both calls.

## Options

| Field | Meaning |
|---|---|
| `protocol` | `Protocol::Http` (default) or `Protocol::Tcp` |
| `api_key` | API key, defaults to `$TUNA_API_KEY` |
| `subdomain`, `domain` | reserved subdomain or custom domain for HTTP |
| `port` | reserved TCP port or its alias |
| `proxy_protocol` | PROXY protocol header version for TCP: `1` or `2` |
| `cidr_allow`, `cidr_deny` | client CIDRs filtered by the tuna.am node, TCP only |
| `location` | only for names and ports reserved in the legacy `ru` or `nl` zones; empty lets the server pick |
| `on_event` | callback for tunnel events |
| `connect_timeout` | limit on the wait for the first connection; `None` means no limit |
| `server_url`, `client_name` | API address and client name reported to the server |

## Events and errors

`on_event` receives `Event::Connected`, `Reconnecting`, `Reconnected`,
`Banner`, `SessionExpiring`, `Terminated` and `LocalError`; `Event::name`
gives the snake_case name. Calls never overlap and run on the tunnel's tasks,
so keep the callback short.

Network failures and temporary server errors are retried: the pause grows
from 1 to 15 seconds with random jitter, and `Retry-After` is respected. The
tunnel ends with an error when retrying is pointless; check it with
`Error::is_permanent`:

- `Error::Server { status, code, message, request_id, .. }` — the API
  rejected the request: bad or revoked key, missing scope, unknown reserved
  name, unpaid plan;
- `Error::Terminated { reason }` — the server closed the tunnel: it was
  deleted, suspended or hit the session time limit.

`Error::KeepAliveTimeout` in a `Reconnecting` event means the node stopped
answering for 15 seconds; the tunnel reconnects.

## Behaviour worth knowing

- When the visitor closes its side of a forwarded connection, the connection
  is closed in both directions: a response sent after that is lost.
- The `Host` header and the PROXY protocol header reach your service as sent.
- The API client uses the system root certificates and does not use HTTP
  proxies. Connections to tuna.am nodes are plain SSH over TCP.

## Contributing

This repository is a read-only mirror of the SDK directory in the tuna.am
monorepo. Issues and pull requests are welcome here: accepted changes are
applied upstream and come back with the next release.

## License

[MIT](LICENSE)
