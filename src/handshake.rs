use std::{collections::HashMap, net::{Ipv4Addr, SocketAddr}, sync::{Arc, Mutex}};

use anyhow::{anyhow, Result};
use ip_network_table::IpNetworkTable;
use snow::{Builder, HandshakeState, params::NoiseParams, TransportState};

use crate::{conf::Peer, ipv4::Ipv4Header};

#[derive(Default)]
pub enum SessionState {
    #[default]
    Idle,
    Initiated{ hs: HandshakeState, peer: SocketAddr },
    Up{ ts: TransportState, peer: SocketAddr },
}

pub struct Session {
    pub state: Arc<Mutex<SessionState>>,
    pub priv_key: [u8;32],
    pub peers: HashMap<[u8;32],Peer>,
    pub network_table: IpNetworkTable<[u8;32]>,
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

/// Output buffer passed to [`Session::handle_outbound_msg`] must be at least this much larger than the MTU
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
    pub fn new(priv_key: [u8;32], peers: HashMap<[u8; 32], Peer>, network_table: IpNetworkTable<[u8; 32]>) -> Session {
        return Session {
            state: Arc::new(Mutex::new(SessionState::Idle)),
            priv_key,
            peers,
            network_table,
        }
    }

    pub fn peer_by_ip(&self, ip: u32) -> Option<&Peer> {
        let (_, key ) = self.network_table.longest_match_ipv4(ip.into())?;
        self.peers.get(key)
    }

    pub fn handle_outbound_msg<'a> (&self, buf: &[u8], out: &'a mut [u8]) -> Result<(&'a [u8], Option<SocketAddr>)> {
        let dst_addr = Ipv4Header::try_from(buf).map_err(|e| anyhow!(e))?.dst_addr;

        if out.is_empty() {
            return Err(anyhow!("output buffer is empty"));
        }

       let mut s = self.state.lock().map_err(|_| anyhow!("cannot obtain lock"))?;
       match &mut *s {
        SessionState::Idle => {
            let peer = self.peer_by_ip(dst_addr).ok_or_else(|| anyhow!("unreachable dst: not a peer"))?;
            let endpoint = peer.endpoint.ok_or_else(|| anyhow!("unreachable dst: endpoint unknown"))?;

            let remote_pubkey = peer.pub_key;
            let mut hs = build_initiator(&self.priv_key, &remote_pubkey[..])?;
            out[0] = MSG_INIT;
            let len = hs.write_message(&[], &mut out[TYPE_LEN..])?;
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

    pub fn handle_inbound_msg<'a> (&self, buf: &[u8], out: &'a mut [u8], src_addr: SocketAddr) -> Result<(&'a [u8], Destination)> {
        let Some((&t, msg)) = buf.split_first() else {
            return Err(anyhow!("empty datagram"));
        };
        let mut s = self.state.lock().map_err(|e| anyhow!("cannot obtain lock: {e}"))?;
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

                        let src_addr: Ipv4Addr = Ipv4Header::try_from(&out[..len]).map_err(|e| anyhow!(e))?.src_addr.into();
                        let mut matches = false;
                        let allowed_ips: &Vec<ip_network::Ipv4Network> = &self.peers[ts.get_remote_static().expect("handshake should have completed")].allowed_ips;
                        for net in allowed_ips {
                            if net.contains(src_addr) {
                                matches = true;
                                break;
                            }
                        }

                        if !matches {
                            return Err(anyhow!("source ip does not match"));
                        }


                        return Ok((&out[..len],Destination::Tun));
                    }
                return Ok((&[], Destination::Null));
            },
            _ => Err(anyhow!("unknown message type")),
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

    impl Session {
        pub fn state_kind(&self) -> Result<StateKind> {
            Ok(self.state.lock().map_err(|e| anyhow!("cannot obtain lock: {e}"))?.kind())
        }
    }

    fn init_session_with_peer(addr: Ipv4Network, endpoint: Option<SocketAddr>) -> Session {
        let mut peers = HashMap::new();
        let mut addrs = Vec::new();
        addrs.push(addr);
        peers.insert([1; 32], Peer {
            pub_key: [1; 32],
            allowed_ips: addrs,
            endpoint,
        });
        let mut network_table = IpNetworkTable::new();
        network_table.insert(addr, [1; 32]);
        Session::new([0; 32], peers, network_table)
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
        assert!(session.state_kind().unwrap().eq(&StateKind::Idle));

        let mut first_packet = [0u8; 1420];
        write_valid_ip_packet(&mut first_packet, to.network_address());

        let mut out = [0u8; 1437];
        let (out, addr) = session.handle_outbound_msg(&first_packet, &mut out).unwrap();
        let addr = addr.unwrap();
        assert!(addr.eq(&to_endpoint));
        assert!(out[0] == MSG_INIT);
        assert!(session.state_kind().unwrap().eq(&StateKind::Initiated));
    }

    #[test]
    pub fn outbound_rejects_non_ip_packet() {
        let packet = [0u8; 1420];
        let mut out = [0u8; 1437];
        let session = init_session_with_peer(Ipv4Network::from_str("10.0.0.1/32").unwrap(), Some(SocketAddr::from_str("172.16.0.1:51820").unwrap()));
        let err = session.handle_outbound_msg(&packet, &mut out).unwrap_err();
        assert!(err.to_string().contains("ipv4:"));
    }

    #[test]
    pub fn outbound_unknown_destination_errors() {
        let session = init_session_with_peer(Ipv4Network::from_str("10.0.0.1/32").unwrap(), None);
        let mut packet = [0u8; 1420];
        write_valid_ip_packet(&mut packet, Ipv4Addr::new(10, 0, 0, 2));
        let mut out = [0u8; 1437];
        let err = session.handle_outbound_msg(&packet, &mut out).unwrap_err();
        assert!(err.to_string().contains("unreachable"));
    }

    #[test]
    pub fn outbound_peer_without_endpoint_errors() {
        let dst = Ipv4Network::from_str("10.0.0.1/32").unwrap();
        let session = init_session_with_peer(dst.clone(), None);
        let mut packet = [0u8; 1420];
        write_valid_ip_packet(&mut packet, dst.network_address());
        let mut out = [0u8; 1437];
        let err = session.handle_outbound_msg(&packet, &mut out).unwrap_err();
        assert!(err.to_string().contains("unreachable"));
    }
}