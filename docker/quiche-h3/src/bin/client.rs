//! quiche HTTP/3 client for GOAWAY interop testing.
//!
//! Fetches one URL. When the server's GOAWAY arrives it answers with its
//! own GOAWAY and keeps reading the response. Prints one line per event:
//! `status=N`, `GOAWAY id=N`, `GOAWAY sent`, `body=...`. Exits 0 once the
//! response is complete.
//!
//! Adapted from quiche/examples/http3-client.rs (Cloudflare, BSD-2-Clause).

#[macro_use]
extern crate log;

use quiche::h3::NameValue;
use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();
    let cmd = &args.next().unwrap();
    if args.len() != 1 {
        println!("Usage: {cmd} URL");
        std::process::exit(2);
    }
    let (host, port, path) = parse_url(&args.next().unwrap());

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let peer_addr: std::net::SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))
        .expect("resolve host")
        .next()
        .expect("no address for host");
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    let mut socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    config.set_max_idle_timeout(10000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let mut http3_conn = None;

    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);
    let local_addr = socket.local_addr().unwrap();

    let server_name = if host.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(host.as_str())
    };
    let mut conn =
        quiche::connect(server_name, &scid, local_addr, peer_addr, &mut config).unwrap();
    info!("connecting to {peer_addr} from {local_addr}");

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            continue;
        }
        panic!("send() failed: {e:?}");
    }

    let h3_config = quiche::h3::Config::new().unwrap();

    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", host.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
    ];

    let mut req_sent = false;
    let mut goaway_sent = false;
    let mut finished = false;
    let mut body = Vec::new();

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        'read: loop {
            if events.is_empty() {
                conn.on_timeout();
                break 'read;
            }
            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break 'read;
                    }
                    panic!("recv() failed: {e:?}");
                }
            };
            let recv_info = quiche::RecvInfo { to: local_addr, from };
            if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                error!("recv failed: {e:?}");
                continue 'read;
            }
        }

        if conn.is_closed() {
            break;
        }

        if conn.is_established() && http3_conn.is_none() {
            http3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .expect("unable to create HTTP/3 connection"),
            );
        }

        if let Some(h3_conn) = &mut http3_conn {
            if !req_sent {
                info!("sending request {req:?}");
                h3_conn.send_request(&mut conn, &req, true).unwrap();
                req_sent = true;
            }
        }

        if let Some(h3_conn) = &mut http3_conn {
            loop {
                match h3_conn.poll(&mut conn) {
                    Ok((_stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        for h in &list {
                            if h.name() == b":status" {
                                println!("status={}", String::from_utf8_lossy(h.value()));
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        while let Ok(read) = h3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                            println!("data={read}");
                            body.extend_from_slice(&buf[..read]);
                        }
                    }
                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        println!("body={}", String::from_utf8_lossy(&body));
                        finished = true;
                        conn.close(true, 0x100, b"done").ok();
                    }
                    Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                        println!("reset={e}");
                        conn.close(true, 0x100, b"reset").ok();
                    }
                    Ok((_, quiche::h3::Event::PriorityUpdate)) => (),
                    Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                        println!("GOAWAY id={goaway_id}");
                        if !goaway_sent {
                            // RFC 9114 Section 5.2: answer with our own GOAWAY.
                            match h3_conn.send_goaway(&mut conn, 0) {
                                Ok(()) => {
                                    println!("GOAWAY sent");
                                    goaway_sent = true;
                                }
                                Err(e) => println!("GOAWAY send failed: {e:?}"),
                            }
                        }
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        println!("h3 error={e:?}");
                        break;
                    }
                }
            }
        }

        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("send failed: {e:?}");
                    conn.close(false, 0x1, b"fail").ok();
                    break;
                }
            };
            if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                panic!("send() failed: {e:?}");
            }
        }

        if conn.is_closed() {
            break;
        }
    }

    std::process::exit(if finished { 0 } else { 1 });
}

/// Splits `https://host[:port]/path` into its parts; the port defaults to 443.
fn parse_url(url: &str) -> (String, u16, String) {
    let rest = url.strip_prefix("https://").expect("URL must start with https://");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => (h, p.parse().expect("port")),
        _ => (authority, 443),
    };
    (host.to_string(), port, path.to_string())
}
