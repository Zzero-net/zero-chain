#!/usr/bin/env bash
# Launch a 3-validator Zero devnet locally.
# Usage: ./devnet/launch.sh
#
# This script:
#   1. Builds the zero-node binary
#   2. Generates 3 validator keypairs (if not already present)
#   3. Writes genesis.toml with the 3 validators + a funded test account
#   4. Writes per-node zero.toml configs
#   5. Starts all 3 nodes in the background
#   6. Waits for ctrl-c, then shuts them all down

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAIN_DIR="$(dirname "$SCRIPT_DIR")"
DEVNET_DIR="$SCRIPT_DIR"

CARGO="${CARGO:-cargo}"
BASE_PORT=50051

echo "=== Zero Devnet Launcher ==="

# 1. Build
echo "[1/5] Building zero-node..."
cd "$CHAIN_DIR"
$CARGO build --release --bin zero-node 2>&1 | tail -1
BINARY="$CHAIN_DIR/target/release/zero-node"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed, binary not found at $BINARY"
    exit 1
fi

# 2. Generate keypairs
echo "[2/5] Generating validator keys..."
PUBKEYS=()
for i in 0 1 2; do
    KEY_DIR="$DEVNET_DIR/node$i"
    mkdir -p "$KEY_DIR"
    KEY_FILE="$KEY_DIR/validator.key"

    if [ -f "$KEY_FILE" ]; then
        echo "  Node $i: key already exists"
    else
        # Generate a random 32-byte Ed25519 secret key (hex)
        SECRET=$(openssl rand -hex 32)
        echo -n "$SECRET" > "$KEY_FILE"
        echo "  Node $i: generated new key"
    fi

    # Derive public key: we'll use a small helper
    # For now, store the secret and let the node derive the pubkey on startup
    # We need pubkeys for genesis though — use ed25519 key derivation
    PUBKEYS+=("PENDING")
done

# We need to derive public keys from secrets for genesis.
# Write a tiny Rust program to do this, or use the binary itself.
# Simpler: write a key-derive helper inline.
echo "[3/5] Deriving public keys..."

# Create a small Rust script to derive pubkeys
DERIVE_SRC="$DEVNET_DIR/.derive_keys.rs"
cat > "$DERIVE_SRC" << 'RUSTEOF'
use std::fs;
fn main() {
    for i in 0..3 {
        let path = format!("devnet/node{}/validator.key", i);
        let hex_str = fs::read_to_string(&path).unwrap();
        let secret_bytes: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|j| u8::from_str_radix(&hex_str[j..j+2], 16).unwrap())
            .collect();
        let secret: [u8; 32] = secret_bytes.try_into().unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key();
        let pk_hex: String = public_key.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        println!("{}", pk_hex);
    }
}
RUSTEOF

# Actually, easier to just use Python or openssl for ed25519 key derivation.
# Let's use Python with PyNaCl since it's installed.
PUBKEYS_RAW=$(python3 -c "
import nacl.signing
import os

for i in range(3):
    path = f'$DEVNET_DIR/node{i}/validator.key'
    with open(path) as f:
        secret_hex = f.read().strip()
    secret = bytes.fromhex(secret_hex)
    signing_key = nacl.signing.SigningKey(secret)
    pub_hex = signing_key.verify_key.encode().hex()
    print(pub_hex)
")

rm -f "$DERIVE_SRC"

# Parse pubkeys
readarray -t PUBKEYS <<< "$PUBKEYS_RAW"
echo "  Validator 0: ${PUBKEYS[0]:0:16}..."
echo "  Validator 1: ${PUBKEYS[1]:0:16}..."
echo "  Validator 2: ${PUBKEYS[2]:0:16}..."

# Also generate a test account keypair
TEST_KEY_FILE="$DEVNET_DIR/test_account.key"
if [ ! -f "$TEST_KEY_FILE" ]; then
    TEST_SECRET=$(openssl rand -hex 32)
    echo -n "$TEST_SECRET" > "$TEST_KEY_FILE"
fi

TEST_PUBKEY=$(python3 -c "
import nacl.signing
with open('$TEST_KEY_FILE') as f:
    secret = bytes.fromhex(f.read().strip())
sk = nacl.signing.SigningKey(secret)
print(sk.verify_key.encode().hex())
")
echo "  Test account: ${TEST_PUBKEY:0:16}... (funded with 1,000,000 Z)"

# 3. Write genesis.toml
echo "[4/5] Writing configs..."
GENESIS_FILE="$DEVNET_DIR/genesis.toml"
cat > "$GENESIS_FILE" << EOF
network = "zero-devnet"

[[validators]]
public_key = "${PUBKEYS[0]}"
stake = 100

[[validators]]
public_key = "${PUBKEYS[1]}"
stake = 100

[[validators]]
public_key = "${PUBKEYS[2]}"
stake = 100

[[accounts]]
public_key = "$TEST_PUBKEY"
balance = 1000000
EOF

# 4. Write per-node configs
for i in 0 1 2; do
    NODE_DIR="$DEVNET_DIR/node$i"
    mkdir -p "$NODE_DIR"

    PORT=$((BASE_PORT + i))
    PEERS=""
    for j in 0 1 2; do
        if [ "$j" -ne "$i" ]; then
            PEER_PORT=$((BASE_PORT + j))
            if [ -n "$PEERS" ]; then
                PEERS="$PEERS, "
            fi
            PEERS="${PEERS}\"http://127.0.0.1:${PEER_PORT}\""
        fi
    done

    cat > "$NODE_DIR/zero.toml" << EOF
validator_index = $i
key_file = "$NODE_DIR/validator.key"
listen = "127.0.0.1:$PORT"
peers = [$PEERS]
data_dir = "$NODE_DIR"
event_interval_ms = 200
log_capacity = 100000
max_batch_size = 500
EOF

    # Symlink genesis into each node's data dir
    ln -sf "$GENESIS_FILE" "$NODE_DIR/genesis.toml"
done

echo "  Configs written for 3 nodes (ports $BASE_PORT-$((BASE_PORT + 2)))"

# 5. Launch nodes
echo "[5/5] Starting nodes..."
PIDS=()

cleanup() {
    echo ""
    echo "Shutting down devnet..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait
    echo "All nodes stopped."
}
trap cleanup INT TERM

for i in 0 1 2; do
    NODE_DIR="$DEVNET_DIR/node$i"
    LOG_FILE="$NODE_DIR/node.log"
    "$BINARY" "$NODE_DIR/zero.toml" > "$LOG_FILE" 2>&1 &
    PIDS+=($!)
    echo "  Node $i started (PID ${PIDS[$i]}, log: $LOG_FILE)"
done

echo ""
echo "=== Devnet running ==="
echo "  Node 0: 127.0.0.1:$BASE_PORT"
echo "  Node 1: 127.0.0.1:$((BASE_PORT + 1))"
echo "  Node 2: 127.0.0.1:$((BASE_PORT + 2))"
echo "  Test account key: $DEVNET_DIR/test_account.key"
echo ""
echo "Press Ctrl+C to stop all nodes."
echo ""

# Tail logs from all nodes
tail -f "$DEVNET_DIR"/node*/node.log &
TAIL_PID=$!
PIDS+=($TAIL_PID)

wait
