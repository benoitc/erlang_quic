//! Quiche benchmark server for QUIC throughput comparison
//!
//! Supports two modes:
//! - Upload: Client sends data, server sinks it
//! - Download: Client sends 8-byte size, server sends that many bytes

use std::collections::HashMap;
use std::net::SocketAddr;

use log::{debug, error, info};
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use ring::rand::{SecureRandom, SystemRandom};

const MAX_DATAGRAM_SIZE: usize = 1350;
const SERVER: Token = Token(0);

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mut listen_addr = "0.0.0.0:4435".to_string();
    let mut cert_path = "/certs/cert.pem".to_string();
    let mut key_path = "/certs/priv.key".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" | "-l" => {
                i += 1;
                if i < args.len() {
                    listen_addr = args[i].clone();
                }
            }
            "--cert" | "-c" => {
                i += 1;
                if i < args.len() {
                    cert_path = args[i].clone();
                }
            }
            "--key" | "-k" => {
                i += 1;
                if i < args.len() {
                    key_path = args[i].clone();
                }
            }
            _ => {}
        }
        i += 1;
    }

    info!("Starting quiche benchmark server on {}", listen_addr);

    if let Err(e) = run_server(&listen_addr, &cert_path, &key_path) {
        error!("Server error: {:?}", e);
        std::process::exit(1);
    }
}

fn run_server(listen_addr: &str, cert_path: &str, key_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);

    let addr: SocketAddr = listen_addr.parse()?;
    let mut socket = UdpSocket::bind(addr)?;
    poll.registry().register(&mut socket, SERVER, Interest::READABLE)?;

    info!("Listening on {}", addr);

    // Configure QUIC
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file(cert_path)?;
    config.load_priv_key_from_pem_file(key_path)?;
    config.set_application_protos(&[b"bench"])?;
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(16 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(16 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(16 * 1024 * 1024);
    config.set_initial_max_stream_data_uni(16 * 1024 * 1024);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let rng = SystemRandom::new();
    let mut conn_id_seed = [0u8; 32];
    rng.fill(&mut conn_id_seed).unwrap();

    let mut connections: HashMap<quiche::ConnectionId<'static>, Connection> = HashMap::new();
    let mut buf = [0u8; 65535];
    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    loop {
        // Use short timeout to allow sending pending data
        let timeout = connections
            .values()
            .filter_map(|c| c.quic.timeout())
            .min()
            .unwrap_or_else(|| std::time::Duration::from_millis(10));

        poll.poll(&mut events, Some(timeout))?;

        // Read incoming packets
        'read: loop {
            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break 'read,
                Err(e) => return Err(e.into()),
            };

            let pkt_buf = &mut buf[..len];
            let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,
                Err(e) => {
                    debug!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                }
            };

            let conn_id = hdr.dcid.clone().into_owned();

            let conn = if !connections.contains_key(&conn_id) {
                if hdr.ty != quiche::Type::Initial {
                    debug!("Packet is not Initial");
                    continue 'read;
                }

                let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
                rng.fill(&mut scid).unwrap();
                let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                let conn = quiche::accept(&scid, None, addr, from, &mut config)?;

                connections.insert(scid.clone(), Connection::new(conn, from));
                connections.get_mut(&scid).unwrap()
            } else {
                connections.get_mut(&conn_id).unwrap()
            };

            let recv_info = quiche::RecvInfo {
                to: addr,
                from,
            };

            match conn.quic.recv(pkt_buf, recv_info) {
                Ok(_) => {}
                Err(e) => {
                    debug!("recv failed: {:?}", e);
                }
            }
        }

        // Process connections
        let mut closed_conns = Vec::new();

        for (conn_id, conn) in connections.iter_mut() {
            // Handle timeouts
            conn.quic.on_timeout();

            // Handle readable streams
            for stream_id in conn.quic.readable() {
                loop {
                    match conn.quic.stream_recv(stream_id, &mut buf) {
                        Ok((len, fin)) => {
                            let data = &buf[..len];
                            conn.bytes_recv += len;

                            // Check if this is a download request (8 bytes = size)
                            if conn.stream_state.get(&stream_id).is_none() && len == 8 && fin {
                                // Download mode: send requested bytes
                                let size = u64::from_be_bytes(data.try_into().unwrap()) as usize;
                                info!("Download request for {} bytes on stream {}", size, stream_id);
                                conn.stream_state.insert(stream_id, StreamState::Download { remaining: size });
                            } else if fin {
                                // Upload complete
                                info!("Upload received {} bytes on stream {}", conn.bytes_recv, stream_id);
                                // Send FIN to acknowledge
                                let _ = conn.quic.stream_send(stream_id, &[], true);
                                conn.bytes_recv = 0;
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            debug!("stream recv error: {:?}", e);
                            break;
                        }
                    }
                }
            }

            // Send download data on writable streams
            let stream_ids: Vec<_> = conn.stream_state.keys().cloned().collect();
            for stream_id in stream_ids {
                if let Some(StreamState::Download { remaining }) = conn.stream_state.get_mut(&stream_id) {
                    if *remaining > 0 {
                        // Check if stream is writable
                        let cap = conn.quic.stream_capacity(stream_id).unwrap_or(0);
                        if cap > 0 {
                            // Generate and send data
                            let chunk_size = (*remaining).min(cap).min(32768);
                            let chunk: Vec<u8> = vec![0x42; chunk_size];
                            let fin = chunk_size >= *remaining;

                            match conn.quic.stream_send(stream_id, &chunk, fin) {
                                Ok(written) => {
                                    *remaining = remaining.saturating_sub(written);
                                    if *remaining == 0 {
                                        info!("Download complete on stream {}", stream_id);
                                    }
                                }
                                Err(quiche::Error::Done) => {}
                                Err(e) => debug!("stream send error: {:?}", e),
                            }
                        }
                    }
                }
            }

            // Send outgoing packets
            loop {
                let (len, send_info) = match conn.quic.send(&mut out) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        debug!("send failed: {:?}", e);
                        conn.quic.close(false, 0x00, b"send error").ok();
                        break;
                    }
                };

                if let Err(e) = socket.send_to(&out[..len], send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    debug!("socket send error: {:?}", e);
                    break;
                }
            }

            if conn.quic.is_closed() {
                info!("Connection closed: {:?}", conn_id);
                closed_conns.push(conn_id.clone());
            }
        }

        for conn_id in closed_conns {
            connections.remove(&conn_id);
        }
    }
}

#[derive(Debug)]
enum StreamState {
    Download { remaining: usize },
}

struct Connection {
    quic: quiche::Connection,
    #[allow(dead_code)]
    peer: SocketAddr,
    bytes_recv: usize,
    stream_state: HashMap<u64, StreamState>,
}

impl Connection {
    fn new(quic: quiche::Connection, peer: SocketAddr) -> Self {
        Self {
            quic,
            peer,
            bytes_recv: 0,
            stream_state: HashMap::new(),
        }
    }
}
