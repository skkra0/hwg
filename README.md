# hwg

A hand-rolled WireGuard VPN. Uses [`snow`](https://crates.io/crates/snow)
for the crypto(Noise IK handshake), ([`tun-rs`](https://crates.io/crates/tun-rs))
for TUN device management, and [`tokio`](https://github.com/tokio-rs/tokio) for async I/O.

## Building

```sh
cargo build --release
```

## Unit tests

```sh
cargo test
```

## Trying it out

The binary reads a WireGuard-style config file (path from `CONFIG_FILE`,
default `/etc/wireguard/wg0.conf`) and opens a TUN device, so it needs
root/`CAP_NET_ADMIN`. We will create two "hosts" that can reach each other
over UDP.

1. Set up two network namespaces to mimic two hosts on a LAN

   ```sh
   ./setup-ns.sh
   ```

   This creates `ns1` (172.16.0.1) and `ns2` (172.16.0.2).

2. Generate a keypair for each peer

   ```sh
   wg genkey | tee priv-1.pem | wg pubkey > pub-1.pem
   wg genkey | tee priv-2.pem | wg pubkey > pub-2.pem
   ```

3. **Write a config for each peer**, e.g. `wg-1.conf`:

   ```ini
   [Interface]
   Address = 10.0.0.1
   ListenPort = 51820
   PrivateKey = <contents of priv-1.pem>

   [Peer]
   PublicKey = <contents of pub-2.pem>
   AllowedIPs = 10.0.0.2
   Endpoint = 172.16.0.2:51820
   ```

   and `wg-2.conf`:

   ```ini
   [Interface]
   Address = 10.0.0.2
   ListenPort = 51820
   PrivateKey = <contents of priv-2.pem>

   [Peer]
   PublicKey = <contents of pub-1.pem>
   AllowedIPs = 10.0.0.1
   ```

4. Run the binary in each namespace

   ```sh
   sudo ip netns exec ns1 env CONFIG_FILE=./wg-1.conf ./target/release/hwg
   sudo ip netns exec ns2 env CONFIG_FILE=./wg-2.conf ./target/release/hwg
   ```

5. Ping across the tunnel from a third shell

   ```sh
   sudo ip netns exec ns1 ping 10.0.0.2
   ```

   The first packet triggers the Noise IK handshake and gets dropped.
   Later traffic is encrypted transport data.
