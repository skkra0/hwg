use anyhow::{anyhow, Result};
use snow::{Builder, HandshakeState, params::NoiseParams, TransportState};
use std::env;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub enum Session {
    Idle,
    Initiated(HandshakeState),
    Up(TransportState),
}

pub const MSG_INIT: u8 = 254;
pub const MSG_RESP: u8 = 253;
pub const MSG_TRANSPORT: u8 = 252;

pub fn load_key_from_env(name: &str) -> Result<[u8; 32]> {
    let b64 = env::var(name)?;

    let bytes = STANDARD.decode(b64.trim())?;

    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("{name} is {} bytes, expected 32", v.len()))?;

    Ok(key)
}

fn params() -> NoiseParams {
    "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
}

pub fn build_initiator() -> Result<HandshakeState> {
    let local_private_key = load_key_from_env("LOCAL_PRIVATE_KEY")?;
    let remote_public_key = load_key_from_env("REMOTE_PUBLIC_KEY")?;

    let init = Builder::new(params())
        .local_private_key(&local_private_key)?
        .remote_public_key(&remote_public_key)?
        .build_initiator()?;
    Ok(init)
}

pub fn build_responder() -> Result<HandshakeState> {
    let local_private_key = load_key_from_env("LOCAL_PRIVATE_KEY")?;
    let resp = Builder::new(params())
        .local_private_key(&local_private_key)?
        .build_responder()?;
    Ok(resp) 
}
