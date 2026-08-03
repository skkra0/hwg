use std::{env, net::{IpAddr, Ipv4Addr, SocketAddr}, str::FromStr, sync::Arc};

use anyhow::Result;
use tokio::{net::UdpSocket, sync::Mutex};
use tun_rs::DeviceBuilder;

use crate::{handshake::{Session, build_initiator, build_responder}, ipv4::Ipv4Header};

mod handshake;
mod ipv4;

const MTU: u16 = 1420;

#[tokio::main]
async fn main() -> Result<()> {
    let self_addr = match env::var("SELF_ADDR") {
        Ok(addr) => Ipv4Addr::from_str(addr.as_str()).expect("Invalid SELF_ADDR"),
        Err(_) => Ipv4Addr::new(10, 0, 0, 1)
    };

    let peer_addr = match env::var("PEER_ADDR") {
        Ok(addr) => {
            let ip = Ipv4Addr::from_str(addr.as_str()).expect("Invalid PEER_ADDR");
            SocketAddr::new(IpAddr::V4(ip), 51820)
        },
        Err(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)), 51820)
    };
    println!("{} {}", self_addr, peer_addr);

    let dev = DeviceBuilder::new()
        .name("utun7")
        .ipv4(self_addr, 24, None)
        .mtu(MTU)
        .build_async()
        .unwrap();
    let sock = UdpSocket::bind("0.0.0.0:51820").await?;
    
    let dev = Arc::new(dev);
    let sock = Arc::new(sock);
    let state = Arc::new(Mutex::new(Session::Idle));

    // outbound: TUN → UDP
    let dev_out = dev.clone();
    let sock_out = sock.clone();
    let state_out = state.clone();


    tokio::spawn(async move {
        // layout: [plaintext/ciphertext | nonce | tag]
        let mut buf = [0u8; MTU as usize];
        let mut ct = [0u8; MTU as usize];
        loop {
            // read the IP packet in place
            let n = dev_out.recv(&mut buf).await.unwrap();
            match Ipv4Header::try_from(&buf[..n]) {
                Ok(h) => {
                    println!("{}", h);
                },
                Err(e) => {
                    eprintln!("{e}");
                    continue;
                }
            }
            let mut s = state_out.lock().await;
            println!("{}", match *s {
                Session::Idle => "idle",
                Session::Initiated(_) => "initiated",
                Session::Up(_) => "up",
            });
            match &mut *s {
                Session::Idle => {
                    let mut hs = build_initiator().unwrap();
                    let mut m = [0u8; 513];
                    m[0] = handshake::MSG_INIT;
                    let len = hs.write_message(&[], &mut m[1..]).unwrap();
                    sock_out.send_to(&m[..1 + len], peer_addr).await.unwrap();
                    *s = Session::Initiated(hs);
                },
                Session::Initiated(_) => {},
                Session::Up(ts) => {
                    println!("transport: encrypting {n} bytes");
                    let len = ts.write_message(&buf[..n], &mut ct[1..]).unwrap();
                    ct[0] = handshake::MSG_TRANSPORT;
                    sock_out.send_to(&ct[..1 + len], peer_addr).await.unwrap();
                }
            }
        }
    });

    // inbound: UDP → TUN
    tokio::spawn(async move {
        let mut buf = [0u8; MTU as usize];
        let mut pt = [0u8; MTU as usize];
        loop {
            let (n, _from) = sock.recv_from(&mut buf).await.unwrap();
            if n == 0 { continue; }
            let (t, msg) = (buf[0], &buf[1..n]);
            println!("received type {} message", match t {
                handshake::MSG_INIT => "init",
                handshake::MSG_RESP => "resp",
                handshake::MSG_TRANSPORT => "transport",
                other => "unknown",
            });
            let mut s= state.lock().await;
            match t {
                handshake::MSG_INIT => {
                    let mut hs = build_responder().unwrap();
                    match hs.read_message(msg, &mut []) {
                        Err(e) => {
                            eprintln!("failed to read init message: {e:?}");
                            continue;
                        },
                        default => {}
                    };
                    let mut m2 = [0u8; 513];
                    m2[0] = handshake::MSG_RESP;
                    let len = hs.write_message(&[], &mut m2[1..]).unwrap();
                    sock.send_to(&m2[..1+len], peer_addr).await.unwrap();
                    *s = Session::Up(hs.into_transport_mode().unwrap());
                },
                handshake::MSG_RESP => {
                    if let Session::Initiated(mut hs) =
                    std::mem::replace(&mut *s, Session::Idle) {
                        if hs.read_message(msg, &mut []).is_ok() {
                            *s = Session::Up(hs.into_transport_mode().unwrap());
                        }
                    }
                },
                handshake::MSG_TRANSPORT => {
                    if let Session::Up(ts) = &mut *s {
                        if let Ok(len) = ts.read_message(msg, &mut pt) {
                            dev.send(&pt[..len]).await.unwrap();
                            println!("transport: got {len} bytes");
                        }
                    }
                },
                other => eprintln!("unknown type {other}"),

            }
            // handle received from UDP
        }
    })
    .await?;

  Ok(())
}

