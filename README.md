# Zero Chain

The core node implementation for the **Zero Network** — a permissionless stablecoin microtransaction network.

**1 Z = $0.01 USD** | 136-byte transactions | <500ms finality | 0.01 Z flat fee

## Architecture

```
zero-chain/
├── zero-types       Core types: accounts, blocks, transfers, parameters
├── zero-crypto      Ed25519 signing + BLAKE3 hashing
├── zero-storage     Account state, staking, rate limiting, snapshots
├── zero-consensus   DAG-based aBFT consensus, trust scoring, finalization
├── zero-network     gRPC gossip layer + JSON-RPC API
├── zero-bridge      EVM bridge guardian (Base USDC, Arbitrum USDT)
└── zero-node        Binary entry point, config loading, faucet
```

### Design Choices

- **Block-lattice account model** — each account has its own chain of blocks, no global block ordering bottleneck
- **Leaderless DAG aBFT consensus** — events reference parents from other validators, finalized when 2/3+ weight achieved
- **Ed25519 + BLAKE3** — fast, small signatures (64 bytes) and hashes (32 bytes)
- **136-byte wire format** — from (32) + to (32) + amount (4 u32) + nonce (4 u32) + signature (64 Ed25519) = 136 bytes
- **Trinity Validators** — 3 trusted parties with 2-of-3 multisig for bridge operations

### Consensus

The consensus engine uses a DAG (Directed Acyclic Graph) where each validator produces events that reference the latest events from other validators. Finalization occurs when an event is seen by 2/3+ of committee stake weight.

- Trust scoring: validators earn/lose reputation (500 initial, 1000 max, ejected below 100)
- Slashing: equivocation = 100% stake, downtime = 10%, invalid attestation = 100%
- Committee rotation at epoch boundaries (every 10,000 finalized events)
- Late event detection (>5s threshold)

### Bridge

Two-chain bridge with ECDSA guardian attestation:

| Chain    | Asset | Confirmations |
|----------|-------|---------------|
| Base     | USDC  | 20            |
| Arbitrum | USDT  | 20            |

Circuit breaker: max 20% of reserves releasable per 24h with 2-of-3 sigs, up to 50% with 3-of-3.

Bridge-in is free (user pays L1/L2 gas only). Bridge-out costs 0.50 Z flat fee.

## Quick Start

### Install

```bash
curl -sSf https://install.zzero.net/install.sh | sh
```

Or build from source:

```bash
git clone https://github.com/Zzero-net/zero-chain.git
cd zero-chain
cargo build --release
```

The binary is at `target/release/zero-node`.

### Run a Local Testnet

```bash
cd devnet
./launch.sh
```

This starts 3 validator nodes locally on ports 50051-50053 with a JSON-RPC API on port 9070.

### Configuration

```toml
validator_index = 0
key_file = "validator.key"
listen = "0.0.0.0:50051"
peers = ["http://peer1:50051", "http://peer2:50051"]
data_dir = "/opt/zero/data"
event_interval_ms = 200
log_capacity = 100000
max_batch_size = 500
```

### Run Tests

```bash
cargo test
```

202 tests covering crypto, storage, consensus, and bridge logic.

## Network Parameters

| Parameter              | Value           |
|------------------------|-----------------|
| Units per Z            | 100             |
| Transfer fee           | 1 unit (0.01 Z) |
| Max transfer amount    | 2,500 units (25 Z) |
| Account creation fee   | 500 units (5 Z) |
| Bridge-out fee         | 50 units (0.50 Z) |
| Rate limit             | 100 tx/s per account |
| Dust pruning           | <10 units (<0.10 Z) inactive 30 days |
| Max validators         | 1,024           |
| Min validator stake    | 10,000 Z        |
| Unbonding period       | 7 days          |
| Epoch length           | 10,000 events   |

## Fee Distribution

| Recipient | Share |
|-----------|-------|
| Validators | 70% |
| Bridge reserve | 15% |
| Protocol reserve | 15% |

## SDKs & Tools

| Resource | Link |
|----------|------|
| Python SDK | [zero-sdk-python](https://github.com/Zzero-net/zero-sdk-python) |
| JavaScript SDK | [zero-sdk-js](https://github.com/Zzero-net/zero-sdk-js) |
| MCP Server | [mcp-server](https://github.com/Zzero-net/mcp-server) |
| Bridge Contracts | [zero-contracts](https://github.com/Zzero-net/zero-contracts) |
| Payment Widget | [pay.zzero.net](https://pay.zzero.net) |
| Documentation | [docs.zzero.net](https://docs.zzero.net) |
| Explorer | [explorer.zzero.net](https://explorer.zzero.net) |

## License

Apache-2.0
