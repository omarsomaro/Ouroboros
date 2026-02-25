# Discovery DHT Status

Current state:

- deterministic rendezvous, LAN broadcast, STUN, assist relay, and Tor fallback are implemented
- a real DHT backend is now implemented behind feature flag `dht`

## Discovery architecture

`src/discovery.rs` provides the backend-agnostic layer:

- `DiscoveryProvider` trait (`announce`, `discover`)
- `DiscoveryRecord` data model
- `InMemoryDiscovery` local/reference backend
- `FederatedDiscovery` fanout backend
- `DiscoveryService` high-level API (announce/discover + bootstrap fallback)
- `space_hash_from_rendezvous(...)` deterministic namespace derivation

## Kademlia provider (implemented)

`src/discovery/kad.rs` adds `KadDiscoveryProvider` using `libp2p-kad`:

- feature-gated via Cargo feature `dht`
- real `put_record`/`get_record` query flow
- bootstrap peer wiring (`add_peer`, `bootstrap`)
- endpoint record encoding via `DiscoveryRecord` serialization
- TTL freshness filter on decoded discovery records
- local store write before network replication to tolerate early quorum gaps

## Runtime knobs

- `HANDSHACKE_DISCOVERY_ENABLED=1|0`
- `HANDSHACKE_DISCOVERY_BOOTSTRAP_PEERS=host1:port,host2:port,...`

Config parsing is already wired in `src/config.rs`.

## Validation

- baseline discovery tests: `cargo test discovery::`
- DHT path: `cargo test --features dht discovery::`
- dedicated 3-node DHT roundtrip test:
  - `discovery::kad::tests::kad_discovery_multinode_roundtrip`

## Remaining hardening work

- signed endpoint envelopes (authenticity)
- explicit rate limiting around announce/discover API
- full transport fallback wiring to prioritize/merge DHT with existing strategies
