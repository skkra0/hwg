use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Result};
use snow::{Builder, HandshakeState, params::NoiseParams, TransportState};
use tokio::sync::Mutex;

use crate::{conf::Peer, ipv4::Ipv4Header};

#[derive(Default)]
pub enum SessionState {
    #[default]
    Idle,
    Initiated{ hs: HandshakeState, peer: SocketAddr },
    Up{ ts: TransportState, peer: SocketAddr },
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]

/// Which variant a [`SessionState`] currently holds. Used for testing
/// because HandshakeState, TransportState are not comparable.
pub enum StateKind {
    Idle,
    Initiated,
    Up,
}

impl SessionState {
    fn kind(&self) -> StateKind {
        match self {
            SessionState::Idle => StateKind::Idle,
            SessionState::Initiated { .. } => StateKind::Initiated,
            SessionState::Up { .. } => StateKind::Up,
        }
    }
}

#[derive(Clone)]
pub struct Session {
    pub state: Arc<Mutex<SessionState>>,
    pub priv_key: [u8;32],
    pub peers: HashMap<[u8;32],Peer>,
    pub ip_to_key: HashMap<u32, [u8;32]>,
}

#[derive(Debug, PartialEq)]
pub enum Destination {
    Socket,
    Tun,
    Null,
}

pub const MSG_INIT: u8 = 254;
pub const MSG_RESP: u8 = 253;
pub const MSG_TRANSPORT: u8 = 252;

pub const TYPE_LEN: usize = 1;
pub const TAG_LEN: usize = 16;

/// Output buffer passed to [`Session::handle_outbound_msg`] must be at least this much larger than the MTU.
pub const TRANSPORT_OVERHEAD: usize = TYPE_LEN + TAG_LEN;

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

    /// Returns the current state. Used for tests.
    pub async fn state_kind(&self) -> StateKind {
        self.state.lock().await.kind()
    }

    pub async fn handle_outbound_msg<'a> (&self, buf: &[u8], out: &'a mut [u8]) -> Result<(&'a [u8], Option<SocketAddr>)> {
        let dst_addr = Ipv4Header::try_from(buf).map_err(|e| anyhow!(e))?.dst_addr;

        if out.is_empty() {
            return Err(anyhow!("output buffer is empty"));
        }

       let mut s = self.state.lock().await;
       match &mut *s {
        SessionState::Idle => {
            let peer = self.peer_by_ip(dst_addr).ok_or_else(|| anyhow!("unreachable dst: not a peer"))?;
            let endpoint = peer.endpoint.ok_or_else(|| anyhow!("unreachable dst: endpoint unknown"))?;

            let remote_pubkey = peer.pub_key;
            let mut hs = build_initiator(&self.priv_key, &remote_pubkey[..])?;
            out[0] = MSG_INIT;
            let len = hs.write_message(&[], &mut out[TYPE_LEN..])?;
            println!("{len}");
            *s = SessionState::Initiated { hs: hs, peer: endpoint };
            return Ok((&out[..len + TYPE_LEN], Some(endpoint)))
        },
        SessionState::Initiated { hs: _, peer: _ } => {
            return Ok((&out[0..0], None))
        },
        SessionState::Up{ ts, peer } => {
            if out.len() < buf.len() + TRANSPORT_OVERHEAD {
                return Err(anyhow!(
                    "output buffer too small: {} bytes for a {} byte packet, need {}",
                    out.len(),
                    buf.len(),
                    buf.len() + TRANSPORT_OVERHEAD,
                ));
            }
            let len = ts.write_message(buf, &mut out[TYPE_LEN..])?;
            out[0] = MSG_TRANSPORT;
            return Ok((&out[..len + TYPE_LEN], Some(peer.to_owned())))
        }
       }
    }

    pub async fn handle_inbound_msg<'a> (&self, buf: &[u8], out: &'a mut [u8], src_addr: SocketAddr) -> Result<(&'a [u8], Destination)> {
        let Some((&t, msg)) = buf.split_first() else {
            return Err(anyhow!("empty datagram"));
        };
        let mut s = self.state.lock().await;
        match t {
            MSG_INIT => {
                if let SessionState::Up { ts: _, peer: _ } = *s {
                    return Ok((&[], Destination::Null));
                }

                if out.is_empty() {
                    return Err(anyhow!("output buffer is empty"));
                }
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
                let len = hs.write_message(&[], &mut out[TYPE_LEN..])?;
                *s = SessionState::Up { ts: hs.into_transport_mode()?, peer: src_addr };
                return Ok((&out[..len + TYPE_LEN], Destination::Socket));
            },
            MSG_RESP => {
                let SessionState::Initiated { hs, .. } = &mut *s else {
                    return Ok((&[], Destination::Null));
                };
                hs.read_message(msg, &mut [])?;

                // take is needed to gain ownership over hs: swaps the value to default Idle
                let SessionState::Initiated { hs, peer } =
                    std::mem::take(&mut *s)
                else {
                    unreachable!("state matched above and the lock is held throughout")
                };
                *s = SessionState::Up { ts: hs.into_transport_mode()?, peer };
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