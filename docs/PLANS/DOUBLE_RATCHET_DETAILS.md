# Double-Ratchet details

**Question**: In messaging systems, like Signal, where they are using X3DH
and Double-Ratchet. After having exchanged some messages. One part, bob,
goes off-line. During that time alice is sending several messages to bob.
Where are those messages stored while pending to be delivered? When bob comes
online again at a later time, how can he decrypt messages from alice, which
may be encrypted by keys derrived somewhere along the double-ratchet flow?

## **Setup (before Bob goes offline)**

* Alice and Bob already have a session set up from X3DH.
* They share a common **root key** `RK0`.
* They also have:

  * Alice’s **sending chain key** `CK_A0` → for Alice → Bob messages.
  * Bob’s **sending chain key** `CK_B0` → for Bob → Alice messages.

Each **chain key** produces **message keys** deterministically by applying a KDF:

```
MK = KDF(CK)
CK' = KDF'(CK)
```

(where MK is the one-time message key, CK' is the next chain key).

---

## **Step 1: Bob goes offline**

* Alice continues to send messages.
* Bob is not receiving them in real-time.

---

## **Step 2: Alice sends 3 messages**

Let’s follow what happens.

### **Message 1 (Alice → Bob)**

* Alice derives from `CK_A0`:

  * `MK1`, `CK_A1`.
* She encrypts **M1** with `MK1`.
* Sends `{header, ciphertext(M1)}` to the Signal server.

---

### **Message 2 (Alice → Bob)**

* Alice derives from `CK_A1`:

  * `MK2`, `CK_A2`.
* Encrypts **M2** with `MK2`.
* Sends to server.

---

### **Message 3 (Alice → Bob, new DH ratchet)**

At some point, Alice decides to "ratchet" (advance to new Diffie–Hellman step):

1. She generates a fresh DH public key `A_pub1`.
2. Includes it in the message header.
3. Computes:

   * New root key `RK1 = KDF(RK0, DH(A_priv1, B_pub0))`
   * New sending chain key `CK_A'` from `RK1`.
4. From this new `CK_A'`, she derives `MK3`.

So Message 3 is encrypted with `MK3` from the new ratchet.

---

## **Step 3: Messages stored**

* All 3 ciphertexts (with headers) are sitting encrypted on the Signal server.
* Server knows nothing about keys, only metadata.

---

## **Step 4: Bob comes back online**

* Bob downloads the 3 pending messages.

### **Processing Message 1**

* Header says: same ratchet public key as before.
* Bob uses his receiving chain key `CK_A0` to derive `MK1`.
* Decrypts **M1**.
* Advances to `CK_A1`.

### **Processing Message 2**

* Again, same ratchet public key.
* From `CK_A1`, he derives `MK2`.
* Decrypts **M2**.
* Advances to `CK_A2`.

### **Processing Message 3**

* Header shows **new Alice ratchet key `A_pub1`**.
* Bob notices this, so he:

  * Computes `RK1 = KDF(RK0, DH(B_priv0, A_pub1))`.
  * Derives a fresh receiving chain `CK_A'`.
  * From `CK_A'`, he gets `MK3`.
* Decrypts **M3**.

---

## ✅ **Summary of Catch-up**

* Even though Bob was offline, the headers gave him enough context:

  * Message numbers told him how many times to advance a chain.
  * A new ratchet public key told him to perform a DH ratchet.
  * By replaying the exact same key derivation steps, he catches up perfectly
    with Alice’s Double Ratchet flow.

---

👉 This also explains why **out-of-order delivery works**: Bob may cache
skipped message keys so he can decrypt if messages arrive late.



Perfect — let’s extend the earlier **3-message example** with Bob’s first reply.
This will show both **Alice’s sending chain advancing** while Bob is offline,
and then **Bob’s new sending chain** when he comes back.

---

# 🔹 Recap of where we left off

* Session is initialized (via X3DH).
* They share a root key `RK0`.
* At time of Bob going offline:

  * Alice has sending chain `CK_A0`.
  * Bob has sending chain `CK_B0`.

### While Bob is offline:

1. **M1**: Alice derives `MK1` from `CK_A0 → CK_A1`.
2. **M2**: Alice derives `MK2` from `CK_A1 → CK_A2`.
3. **M3**: Alice performs a **DH ratchet step**:

   * Generates new `A_pub1`.
   * Computes new root key `RK1`.
   * Creates new sending chain `CK_A'`.
   * Encrypts M3 with `MK3`.

All three messages (M1, M2, M3) are stored on the **server**.

---

# 🔹 Bob comes back online

He downloads M1, M2, M3.

### Decrypting

* **M1**: Uses `CK_A0` → derives `MK1`, advances to `CK_A1`.
* **M2**: Uses `CK_A1` → derives `MK2`, advances to `CK_A2`.
* **M3**: Sees new Alice ratchet key `A_pub1`.

  * Performs DH ratchet with `A_pub1`.
  * Updates root key `RK1`.
  * Creates a new receiving chain (`CK_A'`).
  * Derives `MK3`, decrypts M3.
  * **At this point:** Bob also creates his *next sending chain* as part of
    the DH ratchet.
  * Generates fresh `B_priv1`, `B_pub1`.
  * From `RK1`, derives `CK_B'` (Bob’s new sending chain).

---

# 🔹 Bob’s first reply (M4)

* Bob now uses his brand-new sending chain `CK_B'`.
* From it, he derives `MK4`.
* Encrypts his reply **M4** with `MK4`.
* Includes in the message header:
  * His new ratchet public key `B_pub1`.

---

# 🔹 Alice receives M4

* Alice sees `B_pub1` in the header.
* She performs the **corresponding DH ratchet step**:
  * Computes new root key from `A_priv1` and `B_pub1`.
  * Updates her root key and creates a new receiving chain for Bob’s messages.
* From that chain, she derives `MK4`.
* Decrypts Bob’s reply.

---

# ✅ Summary of the extended example

1. **While Bob is offline**:

   * Alice advances her sending chain multiple times, then eventually ratchets
     to a new public key.
   * Messages are queued on the server.

2. **When Bob comes back**:

   * He replays the ratchet state evolution by processing Alice’s headers.
   * At the ratchet step, he not only updates his *receiving* chain but also
     generates a fresh *sending* chain for his next reply.

3. **When Bob replies**:

   * His message carries his new ratchet public key.
   * Alice ratchets accordingly, updating her receiving chain.
   * Both are now back in sync with new sending/receiving chains for both directions.

---

So the **ratchet has this ping-pong rhythm**:

* One side introduces a new ratchet key (via a message).
* The other side processes it, derives a new receiving chain *and* a new
  sending chain.
* When that side replies, their new ratchet key gets carried back, allowing
  the first side to advance again.


**what does Bob have to persist in order to decrypt later, and to send valid
messages when he comes back online?*

---

# 🔹 What is a “ratchet key” in this context?

In the **Double Ratchet**, each DH ratchet step involves:

* A **DH key pair** (private + public) from the sending side.
* The public key is sent in the message header.
* The private key must be stored locally, until it has been used to derive the next root key.

So **Bob’s DH ratchet key = his ephemeral Curve25519 key pair (priv, pub)**
that he generates at each new ratchet step.

---

# 🔹 Where and how does Bob store his DH ratchet keys?

Signal (and other Double Ratchet implementations) keeps them in the
**local session state** on the device, typically in an encrypted database
or secure storage area.

Concretely, Bob’s session state will contain:

### **1. Root Key**

* Current root key (RK), updated each time a new DH ratchet step occurs.

### **2. Chain Keys**

* Current sending chain key (for Bob → Alice).
* Current receiving chain key(s) (for Alice → Bob).
* Possibly a small cache of skipped message keys (for out-of-order messages).

### **3. DH Ratchet Keys**

* Bob’s **most recent DH private key** (the one he generated at his last ratchet step).
* Alice’s **last received DH public key** (to compute the next DH operation).
* Optionally, Bob may temporarily keep his **previous DH private key** until
  he has used it to derive all necessary chain keys — after that, it is deleted.

### **4. Other metadata**

* Message counters (to know how many times to advance a chain).
* Skipped key map (for messages that arrive late).

---

# 🔹 Lifecycle of Bob’s DH ratchet key

1. **Generate**: When Bob needs to ratchet (because Alice introduced a new
   DH public key), he generates a fresh DH key pair `(B_privX, B_pubX)`.
2. **Store**:
   * `B_privX` is stored in Bob’s session state.
   * `B_pubX` is sent to Alice in the header of his *next* outgoing message.
3. **Use**: Both Alice and Bob compute a shared secret from `(A_pubY, B_privX)`
   and update their root key and chains.
4. **Delete**: Once the shared secret is used to derive new keys, and all
   messages depending on this ratchet step have been decrypted, Bob deletes
   the old `B_privX` from memory.

This ensures **forward secrecy**: if someone later compromises Bob’s device,
they can’t go back and recompute past message keys.

---

# 🔹 Where physically on the device?

* On **Signal clients**, session state (including DH ratchet keys) is stored
  in an encrypted SQLite database on the phone.
* On iOS, the DB is protected by the OS’s Keychain hardware security.
* On Android, it uses SQLCipher (AES encryption of the DB).
* Keys are never uploaded to the server — only public parts travel in headers.

---

# ✅ Summary

* Bob stores his DH ratchet keys (private & public) **locally in his session state**.
* Each ratchet step introduces a new ephemeral Curve25519 key pair.
* His private ratchet key is kept just long enough to derive the new root and
  chain keys, then securely deleted.
* Session state includes: root key, chain keys, current DH private key,
  last remote DH public key, and skipped keys.


## Example **session state snapshot** for Bob.

We’ll show what his state might look like **after he came back online,
processed Alice’s 3 messages, and sent his first reply (M4).**

---

# 📦 Bob’s Session State (example, JSON-style)

```json
{
  "root_key": "RK1",
  "sending_chain": {
    "current_ck": "CK_B1",
    "dh_key_pair": {
      "public": "B_pub1",
      "private": "B_priv1"
    },
    "message_number": 1
  },
  "receiving_chain": {
    "current_ck": "CK_A3",
    "last_remote_dh_pub": "A_pub1",
    "message_number": 3
  },
  "skipped_message_keys": {
    "A_pub0:2": "MK2"
  },
  "previous_dh": {
    "public": "B_pub0",
    "private": null
  },
  "metadata": {
    "session_id": "Alice-Bob",
    "last_message_timestamp": "2025-10-01T12:34:56Z"
  }
}
```

---

# 🔹 Explanation of each part

### **root_key**

* Current root key after the most recent DH ratchet (Alice introduced
`A_pub1`, Bob ratcheted with it).

### **sending_chain**

* Bob’s current chain for sending to Alice.
* `dh_key_pair`: Bob’s **active ratchet key pair**.
  * The public half (`B_pub1`) will be included in headers of outgoing messages.
  * The private half (`B_priv1`) is stored locally until used in the next ratchet step.
* `current_ck`: the chain key Bob is advancing to generate per-message keys for outgoing messages.
* `message_number`: how many messages Bob has sent in this chain (he just sent M4, so it’s 1).

### **receiving_chain**

* Tracks Alice’s sending chain.
* `last_remote_dh_pub`: the last Alice DH public key Bob saw (`A_pub1`).
* `current_ck`: where Bob is in Alice’s receiving chain.
* `message_number`: how many messages from Alice have been processed (3 so far).

### **skipped_message_keys**

* Stores message keys for out-of-order delivery.
* Example: If Alice’s M2 arrived late, Bob would keep `MK2` here for later use.

### **previous_dh**

* Optionally, keeps the last DH public key (for reference / state management).
* Private part is deleted after use (for forward secrecy).

### **metadata**

* Session ID, timestamps, and housekeeping info.

---

# ✅ Takeaway

* Bob’s **session state** is a structured bundle of:

  * Current root key.
  * Active sending chain (with his DH key pair).
  * Active receiving chain (with Alice’s last public DH key).
  * Cached skipped message keys.
  * Metadata.
* His **DH ratchet private key** is only stored as long as it’s relevant — then deleted.
* This state is encrypted and persisted locally (so if the app restarts,
  Bob can still decrypt new messages or send replies).

