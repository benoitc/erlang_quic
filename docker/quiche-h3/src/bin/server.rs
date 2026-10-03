//! quiche HTTP/3 server for GOAWAY interop testing.
//!
//! On the first request of a connection it sends GOAWAY naming the next
//! client request stream, then a 200 whose body ends only after a short
//! hold, so the client has the GOAWAY while its request is still in
//! flight. A GOAWAY from the client is logged and the connection goes on.
//!
//! Adapted from quiche/examples/http3-server.rs (Cloudflare, BSD-2-Clause).

#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use quiche::h3::NameValue;
use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;
/// How long the end of the body is held back after the GOAWAY.
const HOLD: Duration = Duration::from_millis(500);

struct Client {
    conn: quiche::Connection,
    http3_conn: Option<quiche::h3::Connection>,
    goaway_sent: bool,
    /// Streams whose body end is due at the given instant.
    pending: Vec<(u64, Instant)>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let mut listen_addr = "0.0.0.0:4441".to_string();
    let mut cert_path = "/certs/cert.pem".to_string();
    let mut key_path = "/certs/priv.key".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                listen_addr = args[i].clone();
            }
            "--cert" => {
                i += 1;
                cert_path = args[i].clone();
            }
            "--key" => {
                i += 1;
                key_path = args[i].clone();
            }
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut socket = mio::net::UdpSocket::bind(listen_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();
    info!("listening on {listen_addr}");

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.load_cert_chain_from_pem_file(&cert_path).unwrap();
    config.load_priv_key_from_pem_file(&key_path).unwrap();
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let h3_config = quiche::h3::Config::new().unwrap();

    let rng = SystemRandom::new();
    let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();
    let local_addr = socket.local_addr().unwrap();

    loop {
        let now = Instant::now();
        let timeout = clients
            .values()
            .flat_map(|c| {
                c.conn
                    .timeout()
                    .into_iter()
                    .chain(c.pending.iter().map(|(_, due)| due.saturating_duration_since(now)))
            })
            .min();
        poll.poll(&mut events, timeout).unwrap();

        finish_due_bodies(&mut clients);

        'read: loop {
            if events.is_empty() {
                clients.values_mut().for_each(|c| c.conn.on_timeout());
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

            let pkt_buf = &mut buf[..len];
            let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,
                Err(e) => {
                    error!("parsing packet header failed: {e:?}");
                    continue 'read;
                }
            };

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id: quiche::ConnectionId<'static> = conn_id.to_vec().into();

            let client = if !clients.contains_key(&hdr.dcid) && !clients.contains_key(&conn_id) {
                if hdr.ty != quiche::Type::Initial {
                    error!("packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();
                    if let Err(e) = socket.send_to(&out[..len], from) {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            panic!("send() failed: {e:?}");
                        }
                    }
                    continue 'read;
                }

                let scid = conn_id.clone();

                let conn = quiche::accept(&scid, None, local_addr, from, &mut config).unwrap();
                info!("{} new connection from {from}", conn.trace_id());

                clients.insert(
                    scid.clone(),
                    Client {
                        conn,
                        http3_conn: None,
                        goaway_sent: false,
                        pending: Vec::new(),
                    },
                );
                clients.get_mut(&scid).unwrap()
            } else {
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,
                    None => clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo { to: local_addr, from };
            if let Err(e) = client.conn.recv(pkt_buf, recv_info) {
                error!("{} recv failed: {e:?}", client.conn.trace_id());
                continue 'read;
            }

            if (client.conn.is_in_early_data() || client.conn.is_established())
                && client.http3_conn.is_none()
            {
                match quiche::h3::Connection::with_transport(&mut client.conn, &h3_config) {
                    Ok(v) => client.http3_conn = Some(v),
                    Err(e) => {
                        error!("failed to create HTTP/3 connection: {e}");
                        continue 'read;
                    }
                }
            }

            if let Some(http3_conn) = client.http3_conn.as_mut() {
                loop {
                    match http3_conn.poll(&mut client.conn) {
                        Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                            handle_request(
                                &mut client.conn,
                                http3_conn,
                                &mut client.goaway_sent,
                                &mut client.pending,
                                stream_id,
                                &list,
                            );
                        }
                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            while let Ok(_read) =
                                http3_conn.recv_body(&mut client.conn, stream_id, &mut buf)
                            {}
                        }
                        Ok((_stream_id, quiche::h3::Event::Finished)) => (),
                        Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),
                        Ok((_, quiche::h3::Event::PriorityUpdate)) => (),
                        Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                            info!("{} GOAWAY id={goaway_id}", client.conn.trace_id());
                            println!("GOAWAY id={goaway_id}");
                        }
                        Err(quiche::h3::Error::Done) => break,
                        Err(e) => {
                            error!("{} HTTP/3 error {e:?}", client.conn.trace_id());
                            break;
                        }
                    }
                }
            }
        }

        for client in clients.values_mut() {
            loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        error!("{} send failed: {e:?}", client.conn.trace_id());
                        client.conn.close(false, 0x1, b"fail").ok();
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
        }

        clients.retain(|_, c| {
            if c.conn.is_closed() {
                info!("{} connection closed", c.conn.trace_id());
            }
            !c.conn.is_closed()
        });
    }
}

/// Ends the bodies whose hold has expired.
fn finish_due_bodies(clients: &mut ClientMap) {
    let now = Instant::now();
    for client in clients.values_mut() {
        let Some(http3_conn) = client.http3_conn.as_mut() else {
            continue;
        };
        let (due, later): (Vec<_>, Vec<_>) =
            client.pending.drain(..).partition(|(_, at)| *at <= now);
        client.pending = later;
        for (stream_id, _) in due {
            if let Err(e) = http3_conn.send_body(&mut client.conn, stream_id, b" and done", true) {
                error!("{} send_body failed: {e:?}", client.conn.trace_id());
            }
        }
    }
}

fn handle_request(
    conn: &mut quiche::Connection,
    http3_conn: &mut quiche::h3::Connection,
    goaway_sent: &mut bool,
    pending: &mut Vec<(u64, Instant)>,
    stream_id: u64,
    headers: &[quiche::h3::Header],
) {
    let path = headers
        .iter()
        .find(|h| h.name() == b":path")
        .map(|h| String::from_utf8_lossy(h.value()).to_string())
        .unwrap_or_default();
    info!("{} request {path} on stream {stream_id}", conn.trace_id());

    if !*goaway_sent {
        // The GOAWAY names the first request stream we will not process.
        match http3_conn.send_goaway(conn, stream_id + 4) {
            Ok(()) => {
                *goaway_sent = true;
                println!("GOAWAY sent id={}", stream_id + 4);
            }
            Err(e) => error!("{} send_goaway failed: {e:?}", conn.trace_id()),
        }
    }

    let headers = vec![
        quiche::h3::Header::new(b":status", b"200"),
        quiche::h3::Header::new(b"server", b"quiche"),
        quiche::h3::Header::new(b"content-type", b"text/plain"),
    ];
    if let Err(e) = http3_conn.send_response(conn, stream_id, &headers, false) {
        error!("{} send_response failed: {e:?}", conn.trace_id());
        return;
    }
    if let Err(e) = http3_conn.send_body(conn, stream_id, b"partial", false) {
        error!("{} send_body failed: {e:?}", conn.trace_id());
        return;
    }
    pending.push((stream_id, Instant::now() + HOLD));
}
