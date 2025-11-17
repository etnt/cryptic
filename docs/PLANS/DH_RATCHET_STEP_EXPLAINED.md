# DH Ratchet Step Counter Behavior

## Overview

The `dh_ratchet_step` counter in the Double Ratchet protocol tracks the number of **DH ratchet operations**, not individual messages. This document explains why the step counter can increment by 2 during a single message exchange cycle.

## Key Insight

**Direction changes trigger TWO DH ratchet operations:**

1. **On Receive (with new DH key):** Step increments when receiving a message with a NEW DH public key
2. **On First Send (after receiving):** Step increments when sending the FIRST reply after receiving

## Example Scenario

```
Alice's Perspective (starting at Step 4):

Step 4: Alice has sent messages, waiting for Bob's reply
   ↓
   [Receives message from Bob with NEW DH public key]
   ↓
Step 5: perform_dh_ratchet_step/2 executes
        - Extracts Bob's new DH public key
        - Computes new DH shared secret
        - Derives new receiving chain key
        - Generates NEW DH keypair for future sending
   ↓
   [Alice decides to send reply]
   ↓
Step 6: perform_dh_ratchet_on_send/1 executes
        - Uses Alice's NEW DH keypair (generated in Step 5)
        - Computes DH shared secret with Bob's key
        - Derives new sending chain key
        - Activates sending chain with fresh DH entropy

Result: Step 4 → Step 6 after one receive + one send
```

## Why This is Correct

This double increment is **standard Double Ratchet protocol behavior** and provides:

### 1. Forward Secrecy in Both Directions
- Receiving messages: Fresh DH key protects incoming message decryption
- Sending messages: Fresh DH key protects outgoing message encryption

### 2. Break-in Recovery
- If keys are compromised, the next direction change restores security
- Both parties inject fresh entropy via new DH operations

### 3. Symmetric Ratcheting
- Both Alice and Bob perform the same DH operations
- Ensures synchronized state across bidirectional communication

## Implementation Details

### Two Functions Handle DH Ratchet Steps:

#### 1. `perform_dh_ratchet_step/2` (Line 997)
Called by `decrypt_message_impl/2` when:
- Incoming message has NEW DH public key
- Different from currently stored `dh_remote`

**Actions:**
- Extract new remote DH public key from message
- Compute shared secret: `scalarmult(OwnDHPriv, NewRemoteDHPub)`
- Derive new root key and receiving chain key via `kdf_rk/2`
- Generate NEW DH keypair for future sending
- **Increment dh_ratchet_step**

#### 2. `perform_dh_ratchet_on_send/1` (Line 1286)
Called by `encrypt_message_impl/2` when:
- `should_perform_dh_ratchet_on_send/1` returns `true`
- Conditions:
  - `recv_msg_number > 0` (received at least one message)
  - `send_msg_number == 0` (first send after receiving)
  - `dh_remote =/= undefined` (have peer's DH key)

**Actions:**
- Use NEW DH keypair (generated during receive step)
- Compute shared secret: `scalarmult(NewDHPriv, RemoteDHPub)`
- Derive new root key and sending chain key via `kdf_rk/2`
- **Increment dh_ratchet_step**

### Guard Function: `should_perform_dh_ratchet_on_send/1` (Line 1270)

Ensures DH ratchet on send happens only ONCE per direction change:

```erlang
should_perform_dh_ratchet_on_send(State) ->
    HasReceivedMessages = State#ratchet_state.recv_msg_number > 0,
    FirstSendInDirection = State#ratchet_state.send_msg_number == 0,
    HasRemoteDH = State#ratchet_state.dh_remote =/= undefined,
    
    HasReceivedMessages andalso FirstSendInDirection andalso HasRemoteDH.
```

## Visual Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Alice State: Step 4, send_msg_number=2, recv_msg_number=0 │
└─────────────────────────────────────────────────────────────┘
                            ↓
                    [Receive Bob's message]
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  decrypt_message_impl checks: Is DH key new?                │
│  YES → Call perform_dh_ratchet_step/2                       │
│        - DH shared secret computed                          │
│        - New receiving chain derived                        │
│        - NEW DH keypair generated for sending               │
│        - Step: 4 → 5                                        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Alice State: Step 5, send_msg_number=2, recv_msg_number=1 │
└─────────────────────────────────────────────────────────────┘
                            ↓
                    [Alice sends reply]
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  encrypt_message_impl checks:                               │
│  should_perform_dh_ratchet_on_send?                         │
│  - recv_msg_number > 0? YES (1)                             │
│  - send_msg_number == 0? NO (2) — Wait, this should be 0!   │
│                                                             │
│  CORRECTION: After DH ratchet on receive,                   │
│  send_msg_number is RESET to 0 for new sending chain!       │
│                                                             │
│  - recv_msg_number > 0? YES (1)                             │
│  - send_msg_number == 0? YES (0)                            │
│  - dh_remote != undefined? YES                              │
│                                                             │
│  ALL CONDITIONS TRUE → Call perform_dh_ratchet_on_send/1    │
│        - Use NEW DH keypair from receive step               │
│        - DH shared secret computed                          │
│        - New sending chain derived                          │
│        - Step: 5 → 6                                        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Alice State: Step 6, send_msg_number=1, recv_msg_number=1 │
│  Both chains now use fresh DH entropy                       │
└─────────────────────────────────────────────────────────────┘
```

## Counter States Through Message Exchange

| Event | Step | send_msg_number | recv_msg_number | Notes |
|-------|------|-----------------|-----------------|-------|
| Initial (Alice sent 2 msgs) | 4 | 2 | 0 | Waiting for reply |
| Receive Bob's msg | 5 | 0 | 1 | DH ratchet: send counter RESET |
| Send reply to Bob | 6 | 1 | 1 | DH ratchet on send |
| Send another msg | 6 | 2 | 1 | Same chain, no DH ratchet |
| Receive Bob's reply | 7 | 0 | 2 | DH ratchet: direction change |

## Common Misconceptions

### ❌ Misconception 1: "Step should increment by 1 per message"
**Reality:** Step increments per DH operation, not per message. Multiple messages can use the same DH step (same chain).

### ❌ Misconception 2: "Step 4 → 6 indicates a bug"
**Reality:** This is correct! Direction change = 2 DH operations = 2 step increments.

### ❌ Misconception 3: "Receiving and sending should share one step increment"
**Reality:** Each direction needs its own DH operation for independent forward secrecy.

## Monitoring and Debugging

When observing `dh_ratchet_step` in logs or status output:

### Normal Patterns:
- Step increments by 2 on direction changes: **EXPECTED** ✓
- Step stays constant across multiple messages in same direction: **EXPECTED** ✓
- Both parties' steps converge after message exchange: **EXPECTED** ✓

### Potential Issues:
- Step increments on EVERY message (even in same direction): **BUG** ✗
- Steps diverge significantly between parties: **SYNC ISSUE** ✗
- Step decreases: **CRITICAL BUG** ✗

## References

- **Source Code:** `src/cryptic_double_ratchet.erl`
  - Line 997: `perform_dh_ratchet_step/2`
  - Line 1286: `perform_dh_ratchet_on_send/1`
  - Line 1270: `should_perform_dh_ratchet_on_send/1`

- **Documentation:** Module documentation (lines 1-200)
- **Protocol Spec:** Signal's Double Ratchet specification

## Summary

The DH ratchet step counter incrementing by 2 during a receive→send cycle is **correct Double Ratchet protocol behavior**. It ensures:

1. Fresh DH entropy in BOTH directions
2. Forward secrecy for incoming AND outgoing messages
3. Break-in recovery on bidirectional communication
4. Symmetric ratcheting between communication parties

**When debugging, remember:** `dh_ratchet_step` counts DH operations, not messages!
