#!/bin/bash

# Simple test script for the Double Ratchet console interface
# This demonstrates the Alice -> Bob message flow

echo "=== Cryptic Double Ratchet Console Demo ==="
echo

# Create temporary files for Alice and Bob sessions
ALICE_SCRIPT=$(mktemp)
BOB_SCRIPT=$(mktemp)
ROOT_KEY_FILE=$(mktemp)
ALICE_KEYS_FILE=$(mktemp)
BOB_KEYS_FILE=$(mktemp)

# Cleanup function
cleanup() {
    rm -f "$ALICE_SCRIPT" "$BOB_SCRIPT" "$ROOT_KEY_FILE" "$ALICE_KEYS_FILE" "$BOB_KEYS_FILE"
}
trap cleanup EXIT

# Generate shared root key
echo "Generating shared root key..."
cat << 'EOF' > "$ROOT_KEY_FILE"
generate_root_key
quit
EOF

ROOT_KEY=$(cd /Users/ttornkvi/git/cryptic && cat "$ROOT_KEY_FILE" | erl -pa _build/default/lib/cryptic/ebin -s cryptic_console_simple start -noshell 2>/dev/null | grep "ROOT_KEY:" | cut -d' ' -f2)
echo "Root key: $ROOT_KEY"

# Generate Alice's keys
echo "Generating Alice's keys..."
cat << 'EOF' > "$ALICE_KEYS_FILE"
generate_keys
quit
EOF

ALICE_OUTPUT=$(cd /Users/ttornkvi/git/cryptic && cat "$ALICE_KEYS_FILE" | erl -pa _build/default/lib/cryptic/ebin -s cryptic_console_simple start -noshell 2>/dev/null)
ALICE_PUB=$(echo "$ALICE_OUTPUT" | grep "PUBLIC_KEY:" | cut -d' ' -f2)
ALICE_PRIV=$(echo "$ALICE_OUTPUT" | grep "PRIVATE_KEY:" | cut -d' ' -f2)
echo "Alice pub: ${ALICE_PUB:0:20}..."
echo "Alice priv: ${ALICE_PRIV:0:20}..."

# Generate Bob's keys
echo "Generating Bob's keys..."
cat << 'EOF' > "$BOB_KEYS_FILE"
generate_keys
quit
EOF

BOB_OUTPUT=$(cd /Users/ttornkvi/git/cryptic && cat "$BOB_KEYS_FILE" | erl -pa _build/default/lib/cryptic/ebin -s cryptic_console_simple start -noshell 2>/dev/null)
BOB_PUB=$(echo "$BOB_OUTPUT" | grep "PUBLIC_KEY:" | cut -d' ' -f2)
BOB_PRIV=$(echo "$BOB_OUTPUT" | grep "PRIVATE_KEY:" | cut -d' ' -f2)
echo "Bob pub: ${BOB_PUB:0:20}..."
echo "Bob priv: ${BOB_PRIV:0:20}..."

echo

# Create Alice's session script
cat << EOF > "$ALICE_SCRIPT"
start_alice $ROOT_KEY $ALICE_PUB $ALICE_PRIV
status
encrypt Hello Bob from Alice!
status
quit
EOF

# Create Bob's session script for receiving
cat << EOF > "$BOB_SCRIPT"
start_bob $ROOT_KEY $BOB_PUB $BOB_PRIV
status
quit
EOF

echo "=== Alice initializes and sends message ==="
ALICE_RESULT=$(cd /Users/ttornkvi/git/cryptic && cat "$ALICE_SCRIPT" | erl -pa _build/default/lib/cryptic/ebin -s cryptic_console_simple start -noshell 2>/dev/null)
echo "$ALICE_RESULT"

# Extract encrypted message
ENCRYPTED_MSG=$(echo "$ALICE_RESULT" | grep "SUCCESS:" | grep -v "initialized" | cut -d' ' -f2)
echo
echo "Encrypted message: ${ENCRYPTED_MSG:0:40}..."

if [ -n "$ENCRYPTED_MSG" ]; then
    # Create Bob's decryption script
    cat << EOF > "$BOB_SCRIPT"
start_bob $ROOT_KEY $BOB_PUB $BOB_PRIV
status
decrypt $ENCRYPTED_MSG
status
quit
EOF

    echo
    echo "=== Bob receives and decrypts message ==="
    BOB_RESULT=$(cd /Users/ttornkvi/git/cryptic && cat "$BOB_SCRIPT" | erl -pa _build/default/lib/cryptic/ebin -s cryptic_console_simple start -noshell 2>/dev/null)
    echo "$BOB_RESULT"
else
    echo "ERROR: Could not extract encrypted message from Alice"
fi

echo
echo "=== Demo completed ==="