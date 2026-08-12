use std::{env, net::{Ipv4Addr, SocketAddrV4}, str::FromStr, sync::Arc};

use anyhow::Result;
use tokio::{net::UdpSocket};
use tun_rs::DeviceBuilder;

use crate::{handshake::{Session, Destination, TRANSPORT_OVERHEAD}};

mod handshake;
mod ipv4;
mod conf;

// Largest plaintext accepted by the tun
const MTU: u16 = 1420;
// Largest datagram sent or received from the UDP socket
const MAX_DATAGRAM_LEN: usize = MTU as usize + TRANSPORT_OVERHEAD;

#[tokio::main]
async fn main() -> Result<()> {
    let conf_file = match env::var("CONFIG_FILE") {
        Ok(file) => file,
        Err(_) => String::from_str("/etc/wireguard/wg0.conf").unwrap(),
    };

    let conf = conf::read_from_file(conf_file.as_str())?;
    let peers = conf.peers;
    let interface = conf.interface;
    println!("addr: {}", interface.addr);

    let session = Session::new(interface.priv_key, peers);

    let dev = DeviceBuilder::new()
        .name("utun7")
        .ipv4(interface.addr, 24, None)
        .mtu(MTU)
        .build_async()
        .unwrap();
    let listen_port = interface.listen_port;
    let listen_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), listen_port);
    let sock = UdpSocket::bind(listen_addr).await?;
    
    let dev = Arc::new(dev);
    let sock = Arc::new(sock);

    let dev_out = dev.clone();
    let sock_out = sock.clone();

    let session_out = session.clone();

    // TUN to UDP: initiator
    tokio::spawn(async move {
        // plaintext in, [type | ciphertext | tag] out
        let mut buf = [0u8; MTU as usize];
        let mut ct = [0u8; MAX_DATAGRAM_LEN];
        loop {
            // read the IP packet in place
            let n = dev_out.recv(&mut buf).await.unwrap();
            match session_out.handle_outbound_msg(&buf[..n], &mut ct).await {
                Ok((out, addr)) => {
                    if out.len() > 0 && let Some(addr) = addr {
                        sock_out.send_to(out, addr).await.unwrap();
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    continue;
                }
            };
        }
    });

    // UDP to TUN: responder
    tokio::spawn(async move {
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        let mut out= [0u8; MTU as usize];
        loop {
            let (n, src_addr) = sock.recv_from(&mut buf).await.unwrap();
            if n == 0 { continue; }

            match session.handle_inbound_msg(&buf[..n], &mut out, src_addr).await {
                Ok((out, dst)) => {
                    if out.len() == 0 {
                        continue;
                    }

                    match dst {
                        Destination::Socket => {
                            sock.send_to(out, src_addr).await.unwrap();
                        },
                        Destination::Tun => {
                            dev.send(out).await.unwrap();
                        },
                        Destination::Null => {},
                    };
                },
                Err(e) => eprintln!("{e}"),
            }
        }
    })
    .await?;

  Ok(())
}

