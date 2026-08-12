use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Result};
use snow::{Builder, HandshakeState, params::NoiseParams, TransportState};
use tokio::sync::Mutex;

use crate::{conf::Peer, ipv4::Ipv4Header};

pub enum SessionState {
    Idle,
    Initiated{ hs: HandshakeState, peer: SocketAddr },
    Up{ ts: TransportState, peer: SocketAddr },
}

#[derive(Clone)]
pub struct Session {
    pub state: Arc<Mutex<SessionState>>,
    pub priv_key: [u8;32],
    pub peers: HashMap<[u8;32],Peer>,
    pub ip_to_key: HashMap<u32, [u8;32]>,
}

#[derive(PartialEq)]
pub enum Destination {
    Socket,
    Tun,
    Null,
}

pub const MSG_INIT: u8 = 254;
pub const MSG_RESP: u8 = 253;
pub const MSG_TRANSPORT: u8 = 252;

fn params() -> NoiseParams {
    "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
}

pub fn build_initiator(local_private_key: &[u8], remote_public_key: &[u8]) -> Result<HandshakeState> {
    let init = Builder::new(params())
        .local_private_key(&local_private_key)?
        .remote_public_key(&remote_public_key)?
        .build_initiator()?;
    Ok(init)
}

pub fn build_responder(local_private_key: &[u8]) -> Result<HandshakeState> {
    let resp = Builder::new(params())
        .local_private_key(&local_private_key)?
        .build_responder()?;
    Ok(resp) 
}

impl Session {
    pub fn new(priv_key: [u8;32], peers: HashMap<[u8;32],Peer>) -> Session {
        let mut ip_to_key = HashMap::new();
        for (key, peer) in &peers {
            let addr = u32::from(peer.addr);
            ip_to_key.insert(addr, *key);
        }

        return Session {
            state: Arc::new(Mutex::new(SessionState::Idle)),
            priv_key,
            peers,
            ip_to_key,
        }
    }

    pub fn peer_by_ip(&self, ip: u32) -> Option<&Peer> {
        let key = self.ip_to_key.get(&ip)?;
        self.peers.get(key)
    }

    pub async fn handle_outbound_msg<'a> (&self, buf: &[u8], out: &'a mut [u8]) -> Result<(&'a [u8], Option<SocketAddr>)> {
        let dst_addr = match Ipv4Header::try_from(buf) {
            Ok(h) => {
                println!("{h}");
                h.dst_addr
            },
            Err(e) => {
                return Err(anyhow!(e))
            }
        };
       let mut s = self.state.lock().await; 
       match &mut *s {
        SessionState::Idle => {
            let peer = self.peer_by_ip(dst_addr).ok_or_else(|| anyhow!("unreachable dst: not a peer"))?;
            let endpoint = peer.endpoint.ok_or_else(|| anyhow!("unreachable dst: endpoint unknown"))?;

            let remote_pubkey = peer.pub_key;
            let mut hs = build_initiator(&self.priv_key, &remote_pubkey[..]).unwrap();
            out[0] = MSG_INIT;
            let len = hs.write_message(&[], &mut out[1..]).unwrap();
            *s = SessionState::Initiated { hs: hs, peer: endpoint };
            return Ok((&out[..len + 1], Some(endpoint)))
        },
        SessionState::Initiated { hs: _, peer: _ } => {
            return Ok((&out[0..0], None))
        },
        SessionState::Up{ ts, peer } => {
            let len = ts.write_message(buf, &mut out[1..]).unwrap();
            out[0] = MSG_TRANSPORT;
            return Ok((&out[..len + 1], Some(peer.to_owned())))
        }
       }
    }

    pub async fn handle_inbound_msg<'a> (&self, buf: &[u8], out: &'a mut [u8], src_addr: SocketAddr) -> Result<(&'a [u8], Destination)> {
        let (t, msg) = (buf[0], &buf[1..]);
        let mut s = self.state.lock().await;
        match t {
            MSG_INIT => {
                let mut hs = build_responder(&self.priv_key[..])?;
                match hs.read_message(msg, &mut []) {
                    Err(e) => {
                        return Err(anyhow!("failed to read init message: {e:?}"));
                    },
                    Ok(_) => {
                        if !self.peers.contains_key(hs.get_remote_static().ok_or_else(|| anyhow!("missing remote public key"))?) {
                            return Err(anyhow!("unknown peer"));
                        }
                    }
                };

                out[0] = MSG_RESP;
                let len = hs.write_message(&[], &mut out[1..])?;
                *s = SessionState::Up { ts: hs.into_transport_mode()?, peer: src_addr };
                return Ok((&out[..len + 1], Destination::Socket));
            },
            MSG_RESP => {
                if let SessionState::Initiated{ mut hs, peer } =
                    std::mem::replace(&mut *s, SessionState::Idle) {
                        hs.read_message(msg, &mut [])?;
                        *s = SessionState::Up{ ts: hs.into_transport_mode().unwrap(), peer };
                }
                return Ok((&[], Destination::Null));
            },
            MSG_TRANSPORT => {
                if let SessionState::Up{ ts, peer: _ } = &mut *s {
                        let len = ts.read_message(msg, out)?;
                        return Ok((&out[..len],Destination::Tun));
                    }
                return Ok((&[], Destination::Null));
            },
            _ => Err(anyhow!("unknown message type")),
        }
    }
}