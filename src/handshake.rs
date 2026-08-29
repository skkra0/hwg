use std::{collections::HashMap, net::{SocketAddr}, sync::{Arc, Mutex, RwLock}};

use anyhow::{anyhow, Result};
use blake2::{Blake2s256, Blake2sMac, Digest, digest::{KeyInit, Mac}};
use chacha20poly1305::consts::U16;
use ip_network::Ipv4Network;
use ip_network_table::IpNetworkTable;
use snow::{Builder, HandshakeState, params::NoiseParams, TransportState};
use tai64::Tai64N;

use crate::{conf::PeerConfig, ipv4::Ipv4Header};

#[derive(Default)]
pub enum SessionState {
    #[default]
    Idle,
    Initiated{ hs: HandshakeState },
    Up{ ts: TransportState, remote_index: u32 },
}

pub struct Session {
    pub priv_key: [u8;32],
    pub pubkey_table: HashMap<[u8;32],Arc<Peer>>,
    pub index_table: RwLock<HashMap<u32, Arc<Peer>>>,
    pub network_table: IpNetworkTable<Arc<Peer>>,
}

pub struct Peer {
    pub pub_key: [u8;32],
    pub allowed_ips: Vec<Ipv4Network>,
    pub endpoint: RwLock<Option<SocketAddr>>,
    state: Mutex<SessionState>,
}

#[derive(Debug, PartialEq)]
pub enum Destination {
    Socket,
    Tun,
    Null,
}

pub const MSG_INIT: u8 = 1;
pub const MSG_RESP: u8 = 2;
pub const MSG_TRANSPORT: u8 = 4;
const HANDSHAKE_INIT_LEN: usize = 148;
const HANDSHAKE_RESP_LEN: usize = 92;
const TRANSPORT_HEADER_LEN: usize = 16;

pub const TAG_LEN: usize = 16;

/// Output buffer passed to [`Session::handle_outbound_msg`] must be at least this much larger than the MTU
pub const TRANSPORT_OVERHEAD: usize = TRANSPORT_HEADER_LEN + TAG_LEN;

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

fn write_handshake_init(hs: &mut HandshakeState, out: &mut [u8]) -> Result<(u32, usize)> {
    if out.len() < HANDSHAKE_INIT_LEN {
        return Err(anyhow!("buffer is too small for handshake init"));
    }

    let sender_index: u32 = rand::random();
    out[0] = MSG_INIT;

    // out[1..4] is reserved
    out[1..4].fill(0);

    out[4..8].copy_from_slice(&sender_index.to_le_bytes());

    let mut offset = 8;

    let timestamp = Tai64N::now().to_bytes();
    // writes ephemeral, static, timestamp
    let len = hs.write_message(&timestamp, &mut out[8..HANDSHAKE_INIT_LEN - 32])?;
    offset += len;

    let mut hasher = Blake2s256::new();
    hasher.update(b"mac1----");
    hasher.update(hs.get_remote_static().expect("should have remote static key")); 
    let res = hasher.finalize();
    let mut mac = <Blake2sMac<U16> as KeyInit>::new(&res);
    mac.update(&out[..offset]);

    // write mac1
    out[offset..offset+16].copy_from_slice(&mac.finalize().into_bytes());

    offset += 16;
    // skipping mac2: cookie not implemented yet
    out[offset..offset+16].fill(0);

    Ok((sender_index, offset+16))
}

fn write_handshake_resp(init_index: u32, hs: &mut HandshakeState, out: &mut [u8]) -> Result<(u32, usize)> {
    if out.len() < HANDSHAKE_RESP_LEN {
        return Err(anyhow!("buffer is too small for handshake resp"));
    }

    let resp_index: u32 = rand::random();
    out[0] = MSG_RESP;
    out[1..4].fill(0);
    out[4..8].copy_from_slice(&resp_index.to_le_bytes());
    out[8..12].copy_from_slice(&init_index.to_le_bytes());

    let mut offset = 12;
    // writes ephemeral
    let enc_len = hs.write_message(&[],&mut out[12..])?;
    offset += enc_len;

    let mut hasher = Blake2s256::new();
    hasher.update(b"mac1----");
    hasher.update(hs.get_remote_static().expect("should have remote static key")); 
    let res = hasher.finalize();
    let mut mac = <Blake2sMac<U16> as KeyInit>::new(&res);
    mac.update(&out[..offset]);

    // write mac1
    out[offset..offset+16].copy_from_slice(&mac.finalize().into_bytes());
    offset += 16;

    // skipping mac2: cookie not implemented yet
    out[offset..offset+16].fill(0);
    
    Ok((resp_index, offset+16))
}

fn write_transport_msg(ts: &mut TransportState, buf: &[u8], index: u32, out: &mut [u8]) -> Result<usize> {
    if out.len() < TRANSPORT_HEADER_LEN + buf.len() {
        return Err(anyhow!("buffer is too small"));
    }

    out[0] = MSG_TRANSPORT;
    out[1..4].fill(0);
    out[4..8].copy_from_slice(&index.to_le_bytes());
    out[8..16].copy_from_slice(&ts.sending_nonce().to_le_bytes());
    let len = ts.write_message(buf, &mut out[16..])?;
    Ok(TRANSPORT_HEADER_LEN + len)
}

impl Session {
    pub fn new(priv_key: [u8;32], peers: Vec<PeerConfig>) -> Session {
        let mut pubkey_table: HashMap<[u8; 32], Arc<Peer>> = HashMap::new();
        let mut network_table = IpNetworkTable::new();
        for peer in peers {
            let peer: Arc<Peer> = Arc::new(peer.into());
            pubkey_table.insert(peer.pub_key, peer.clone());
            for allowed_ip in &peer.allowed_ips {
                network_table.insert(*allowed_ip, peer.clone()); 
            }
        }

        return Session {
            priv_key,
            pubkey_table,
            index_table: HashMap::new().into(),
            network_table,
        }
    }

    fn peer_by_ip(&self, ip: u32) -> Option<&Arc<Peer>> {
        let (_, peer) = self.network_table.longest_match_ipv4(ip.into())?;
        Some(peer)
    }

    pub fn write_outbound_msg (&self, buf: &[u8], out: &mut [u8]) -> Result<(usize, Option<SocketAddr>)> {
        let dst_addr = Ipv4Header::try_from(buf).map_err(|e| anyhow!(e))?.dst_addr;

        if out.is_empty() {
            return Err(anyhow!("output buffer is empty"));
        }
        let peer = self.peer_by_ip(dst_addr).ok_or_else(|| anyhow!("unreachable dst: not a peer"))?;
        let endpoint = (*peer.endpoint.read().unwrap()).ok_or_else(|| anyhow!("unreachable dst: endpoint unknown"))?;
        let mut s = peer.state.lock().map_err(|_| anyhow!("cannot obtain lock"))?;
        match &mut *s {
            SessionState::Idle => {
                let remote_pubkey = peer.pub_key;
                let mut hs = build_initiator(&self.priv_key, &remote_pubkey[..])?;
                let (index, len) = write_handshake_init(&mut hs, out)?;
                self.index_table.write().unwrap().insert(index, peer.clone());
                *s = SessionState::Initiated { hs: hs };
                return Ok((len, Some(endpoint)))
            },
            SessionState::Initiated { hs: _ } => {
                return Ok((0, None))
            },
            SessionState::Up{ ts, remote_index } => {
                if out.len() < buf.len() + TRANSPORT_OVERHEAD {
                    return Err(anyhow!(
                        "output buffer too small: {} bytes for a {} byte packet, need {}",
                        out.len(),
                        buf.len(),
                        buf.len() + TRANSPORT_OVERHEAD,
                    ));
                }
                let len = write_transport_msg(ts, buf, *remote_index, out)?;
                return Ok((len, Some(endpoint.to_owned())))
            }
       }
    }

    pub fn write_inbound_msg(&self, buf: &[u8], out: &mut [u8], src_endpoint: SocketAddr) -> Result<(usize, Destination)> {
        if buf.len() < 8 {
            return Err(anyhow!("buf is empty"));
        }
        if out.is_empty() {
            return Err(anyhow!("msg buffer is empty"));
        }
        let t = buf[0];
        let index = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        match t {
            MSG_INIT => {
                if buf.len() < HANDSHAKE_INIT_LEN {
                    return Err(anyhow!("invalid init"));
                }
                let mut hs = build_responder(&self.priv_key)?;
                let peer: Arc<Peer>;
                let mut timestamp = [0u8; 12];
                match hs.read_message(&buf[8..HANDSHAKE_INIT_LEN - 32], &mut timestamp) {
                    Err(e) => {
                        return Err(anyhow!("failed to read init message: {e:?}"));
                    },
                    Ok(_) => {
                        peer = self.pubkey_table[hs.get_remote_static().ok_or_else(|| anyhow!("missing remote public key"))?].clone();
                    }
                };

                let remote_index = index;
                let (local_index, len) = write_handshake_resp(remote_index, &mut hs, out)?;
                let mut index_table = self.index_table.write().unwrap();
                index_table.insert(local_index, peer.clone());
                let mut s = peer.state.lock().map_err(|e| anyhow!("cannot obtain lock: {e}"))?;
                *s = SessionState::Up { ts: hs.into_transport_mode()?, remote_index };
                let mut endpoint = peer.endpoint.write().unwrap();
                *endpoint = Some(src_endpoint);
                return Ok((len, Destination::Socket));
            },
            MSG_RESP => {
                if buf.len() < HANDSHAKE_RESP_LEN {
                    return Err(anyhow!("invalid resp"));
                }

                let remote_index = index;
                let local_index = u32::from_le_bytes(buf[8..12].try_into().unwrap());
                let index_table = self.index_table.read().unwrap();
                let peer = index_table.get(&local_index).ok_or_else(|| anyhow!("invalid index"))?;
                let mut s = peer.state.lock().map_err(|e| anyhow!("cannot obtain lock: {e}"))?;
                let SessionState::Initiated { hs} = &mut *s else {
                    return Ok((0, Destination::Null));
                };

                hs.read_message(&buf[12..HANDSHAKE_RESP_LEN - 32], &mut [])?;

                // take is needed to gain ownership over hs: swaps the value to default Idle
                let SessionState::Initiated { hs, ..} =
                    std::mem::take(&mut *s)
                else {
                    unreachable!("state matched above and the lock is held throughout")
                };
                *s = SessionState::Up { ts: hs.into_transport_mode()?, remote_index };

                let cur_endpoint = peer.endpoint.read().unwrap();
                if *cur_endpoint != Some(src_endpoint) {
                    let mut endpoint = peer.endpoint.write().unwrap();
                    *endpoint = Some(src_endpoint);
                } 
                return Ok((0, Destination::Null));
            },
            MSG_TRANSPORT => {
                if buf.len() < TRANSPORT_OVERHEAD {
                    return Err(anyhow!("invalid msg"));
                }
                let (nonce, msg) = buf[8..].split_at(8);
                let nonce = u64::from_le_bytes(nonce.try_into().unwrap());
                let index_table = self.index_table.read().unwrap();
                let local_index = index;
                let peer = index_table.get(&local_index).ok_or_else(|| anyhow!("invalid index"))?;
                let mut s = peer.state.lock().map_err(|_| anyhow!("cannot obtain lock"))?;
                if let SessionState::Up{ ts, remote_index: _} = &mut *s { 
                    ts.set_receiving_nonce(nonce);
                    let len = ts.read_message(msg, out)?;

                    let src_addr = Ipv4Header::try_from(&out[..len]).map_err(|e| anyhow!(e))?.src_addr;
                    let mut matches = false;
                    for net in &peer.allowed_ips {
                        if net.contains(src_addr.into()) {
                            matches = true;
                            break;
                        }
                    }

                    if !matches {
                        return Err(anyhow!("source ip does not match"));
                    }

                    let cur_endpoint = peer.endpoint.read().unwrap();
                    if *cur_endpoint != Some(src_endpoint) {
                        let mut endpoint = peer.endpoint.write().unwrap();
                        *endpoint = Some(src_endpoint);
                    } 
                        return Ok((len, Destination::Tun));
                    }
                
                return Ok((0, Destination::Null));
            },
            _ => Err(anyhow!("unknown message type")),
        }
    }
}

impl From<PeerConfig> for Peer {
    fn from(peer: PeerConfig) -> Self {
        Peer {
            pub_key: peer.pub_key,
            allowed_ips: peer.allowed_ips,
            endpoint: peer.endpoint.into(),
            state: Mutex::new(SessionState::Idle),
        }
    }
}


#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};
    use ip_network::Ipv4Network;

use super::*;
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]

    /// Which variant a [`SessionState`] currently holds
    /// Used for testing because [`HandshakeState`], [`TransportState`] are not comparable
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

    fn init_session_with_peer(addr: Ipv4Network, endpoint: Option<SocketAddr>) -> Session {
        let mut peers = Vec::new();
        let mut addrs = Vec::new();
        addrs.push(addr);
        peers.push(PeerConfig {
            pub_key: [1; 32],
            allowed_ips: addrs,
            endpoint,
        });
        Session::new([0; 32], peers)
    }

    fn write_valid_ip_packet(out: &mut [u8], dst_addr: Ipv4Addr) {
        let header = Ipv4Header::new(
            6,
            64, 
            u32::from(Ipv4Addr::new(127, 0, 0, 1)),
            u32::from(dst_addr),
            0
        );

        header.write_to(out).unwrap();
    }

    
    #[test]
    pub fn idle_first_packet_emits_init() {
        let to = Ipv4Network::from_str("10.0.0.1/32").unwrap();
        let to_endpoint = SocketAddr::from_str("172.16.0.1:51820").unwrap();
        
        let session = init_session_with_peer(to.clone(), Some(to_endpoint));
        let peer = session.peer_by_ip(to.network_address().into()).unwrap();
        assert!(peer.state.lock().unwrap().kind().eq(&StateKind::Idle));

        let mut first_packet = [0u8; 1420];
        write_valid_ip_packet(&mut first_packet, to.network_address());

        let mut out = [0u8; 1420 + TRANSPORT_OVERHEAD];
        let (_, addr) = session.write_outbound_msg(&first_packet, &mut out).unwrap();
        let addr = addr.unwrap();
        assert!(addr.eq(&to_endpoint));
        assert!(out[0] == MSG_INIT);
        
        assert!(peer.state.lock().unwrap().kind().eq(&StateKind::Initiated));
    }

    #[test]
    pub fn outbound_rejects_non_ip_packet() {
        let packet = [0u8; 1420];
        let mut out = [0u8; 1437];
        let session = init_session_with_peer(Ipv4Network::from_str("10.0.0.1/32").unwrap(), Some(SocketAddr::from_str("172.16.0.1:51820").unwrap()));
        let err = session.write_outbound_msg(&packet, &mut out).unwrap_err();
        assert!(err.to_string().contains("ipv4:"));
    }

    #[test]
    pub fn outbound_unknown_destination_errors() {
        let session = init_session_with_peer(Ipv4Network::from_str("10.0.0.1/32").unwrap(), None);
        let mut packet = [0u8; 1420];
        write_valid_ip_packet(&mut packet, Ipv4Addr::new(10, 0, 0, 2));
        let mut out = [0u8; 1437];
        let err = session.write_outbound_msg(&packet, &mut out).unwrap_err();
        assert!(err.to_string().contains("unreachable"));
    }

    #[test]
    pub fn outbound_peer_without_endpoint_errors() {
        let dst = Ipv4Network::from_str("10.0.0.1/32").unwrap();
        let session = init_session_with_peer(dst.clone(), None);
        let mut packet = [0u8; 1420];
        write_valid_ip_packet(&mut packet, dst.network_address());
        let mut out = [0u8; 1420 + TRANSPORT_OVERHEAD];
        let err = session.write_outbound_msg(&packet, &mut out).unwrap_err();
        assert!(err.to_string().contains("unreachable"));
    }
}