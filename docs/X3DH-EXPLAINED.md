# X3DH and Double-Ratchet

X3DH is not “just more Diffie–Hellman”—it is a protocol for asynchronous,
authenticated key exchange with strong forward secrecy, designed to work
in real-world messaging:

  * Alice can initiate a secure conversation when Bob is offline.
  *  The key is bound to both Alice’s and Bob’s identities.
  *  If long-term keys are later leaked, past sessions remain confidential.
  * No centralized PKI is needed beyond the server distributing prekeys.

Plain DH lacks these properties; X3DH layers multiple carefully chosen
DH computations plus key derivation to provide them.

Here’s a step-by-step technical breakdown of the mathematical computations
performed in the Extended Triple Diffie–Hellman (X3DH) key agreement protocol
when Alice initiates a session to send a message to Bob.

It will show:

  * Which key pairs are involved
  * The actual elliptic-curve Diffie–Hellman computations performed
  * What each party (Alice and Bob) calculates.

## Keys and Notation

| Symbol     | Owner                               | Type                                                    |
|------------|-------------------------------------|---------------------------------------------------------|
| **IK_A**   | Alice's identity key (long-term)    | static Curve25519 keypair: `(ik_A_priv, IK_A_pub)`      |
| **IK_B**   | Bob's identity key (long-term)      | static Curve25519 keypair: `(ik_B_priv, IK_B_pub)`      |
| **SPK_B**  | Bob's signed prekey (medium-term)   | static Curve25519 keypair: `(spk_B_priv, SPK_B_pub)`    |
| **OPK_B**  | Bob's one-time prekey (optional)    | static Curve25519 keypair: `(opk_B_priv, OPK_B_pub)`    |
| **EK_A**   | Alice's ephemeral key               | ephemeral Curve25519 keypair: `(ek_A_priv, EK_A_pub)`   |

All keys are **Curve25519 (Montgomery curve) public/private pairs**.

The Diffie–Hellman function is **ECDH(priv, pub) → 32-byte shared secret**.

*ECDH* stands for: *Elliptic-Curve Diffie–Hellman*

*ephemeral* simply means: *temporary and short-lived*.

### Mathematical meaning

Curve25519 is an elliptic curve over a finite field.
“Scalar multiplication” (a.k.a ECDH) means:
```
  a * G (mod p)
```
where:

  * a = a 32-byte random integer (your private key),
  * G = a point (x,y) on the curve
  * p = 2**255-19 (hence: Curve25519) used with `mod` to limit the numbers,
    i.e making a `finite field`
  * the result is another curve point A (your public key)

So basically, by adding two points on the curve together (G+G = 2*G) you
will get a new point on the curve. This is easy to do but hard to reverse
engineer (especially for large numbers of `a`).

X25519 is a specific, standardized algorithm for doing this on the Montgomery
form of Curve25519. It uses the Montgomery ladder algorithm to compute A
efficiently and securely.

A Montgomery curve is just a special shape of elliptic curve that lets our
cryptographic “secret-sharing dance” be:

  * **fast** (computers can race around it quickly),
  * **safe** (hard for spies to reverse),
  * **reliable** (resists tricky side attacks).

So, it’s not a different kind of cryptography, just a better track for
the same race.

Example: To find 2 × G (“double G”) where G = (x,y) = (9, 147816...) you:

  0. You don't just double the x and y numbers, instead do...
  1. Draw the tangent line to the curve right at point G.
  2. See where that line crosses the curve again.
  3. Reflect that crossing point across the x-axis.

That reflected point is called 2 G.

So “doubling” is a purely geometric recipe:
**tangent → second intersection → reflection**.

**Why you usually don’t do it by hand**

The arithmetic is done mod a very large prime (for Curve25519 it’s a
255-bit prime), so even the “9” you see is only the x-coordinate mod
that prime.

You must use the exact field operations (modular inverses, etc.),
which are large-integer calculations.

Because of that, software libraries implement a scalar-multiplication
routine that repeatedly applies this doubling-and-adding process for you.

## Computations Performed by Alice (Sender)

Alice fetches from Bob’s “prekey bundle”:
**IK_B_pub**, **SPK_B_pub**, (optional) **OPK_B_pub**,
and the signature on **SPK_B**.

She first verifies Bob’s signature on SPK_B.

Then she generates a fresh ephemeral (short lived) key pair:
```
  ek_A_priv ← random 32-byte scalar
  EK_A_pub = Curve25519BaseMult(ek_A_priv)
```

### Diffie–Hellman Computations

Alice computes the four (or three) X25519 operations:

1. **DH1**: Between her identity and Bob’s signed prekey
```
  # proves Bob’s identity to Alice.
  DH1 = ECDH(ik_A_priv, SPK_B_pub)
```

2. **DH2**: Between her ephemeral and Bob’s identity key
```
  # proves Alice’s identity to Bob.
  DH2 = ECDH(ek_A_priv, IK_B_pub)
```

3. **DH3**: Between her ephemeral and Bob’s signed prekey
 ```
  # gives forward secrecy.
  DH3 = ECDH(ek_A_priv, SPK_B_pub)
 ```

 4. **DH4 (optional)**: If Bob advertised a one-time prekey
```
  # strengthens forward secrecy further
  DH4 = ECDH(ek_A_priv, OPK_B_pub)
```

**Key derivation** is done by concatenating the DH calculations and
use that as input to the *HMAC-based Key Derivation Function* (**HKDF**)
together with some Salt and a info label string. This will produce the
Shared-Key (SK).

```
SK_input = DH1 || DH2 || DH3 || DH4
SK = HKDF( SK_input, Salt, Info)
```

Both clients are doing the same calculations and obtains exactly the
same SK, which then is used to decrypt the first message and start a
Double Ratchet session.

**Summary table**:

| Step     |	Alice computes            | Bob computes               |
|----------|----------------------------|----------------------------|
| DH1      | ECDH(ik_A_priv, SPK_B_pub) | ECDH(spk_B_priv, IK_A_pub) |
| DH2      | ECDH(ek_A_priv, IK_B_pub)	| ECDH(ik_B_priv, EK_A_pub)  |
| DH3	     | ECDH(ek_A_priv, SPK_B_pub) | ECDH(spk_B_priv, EK_A_pub) |
| DH4      | ECDH(ek_A_priv, OPK_B_pub) | ECDH(opk_B_priv, EK_A_pub) |
| SK_input | concat(DH1,DH2,DH3,DH4)    | concat(DH1,DH2,DH3,DH4)    |
| HKDF  	 | HKDF(SK_input, Salt, Info) | HKDF(SK_input, Salt, Info) |

## Double-Ratchet

The Double Ratchet algorithm takes that initial shared secret and turns it
into a continually evolving sequence of keys—one per message.

It’s called Double because there are two types of ratchets:
  1. **DH ratchet** – occasional fresh Diffie–Hellman steps when a new
     ephemeral key from the peer arrives,
  2. **Symmetric-key ratchet** – per-message key derivation using a hash chain.

These combine to produce new message keys continuously, even if the
original X3DH key was long ago compromised.

So, X3DH just gives you the first root key so you can start the Double Ratchet.
After that, the Double Ratchet itself keeps producing fresh message keys.

```
# CK0 is obtained from the initial X3DH calculations
(CK1, MK1) = HKDF(CK0, "label")
# Encrypt M1 with MK1
(CK2, MK2) = HKDF(CK1, "label")
# Encrypt M2 with MK2
...etc...
```

So a new **Symmetric-key** is generated for each message sent and, typically,
a new ephemeral DH-key is introduced when a response is received.

Example (MK is the Symmetric-Key, EpK is the ephemeral DH key):

```
Alice -> Bob: encrypt(Msg1, MK1, EpK1)
Alice -> Bob: encrypt(Msg2, MK2, EpK1)
Alice -> Bob: encrypt(Msg3, MK3, EpK1)
Alice <- Bob: ...getting a response...
Alice -> Bob: encrypt(Msg4, MK4, EpK2)
...etc...
```

In a Double Ratchet conversation it’s perfectly normal for some messages to
be dropped or arrive out of order. The protocol was designed to cope with that.

Each party keeps two independent hash chains of keys:

| Chain           |	Purpose                                         |
|-----------------|-------------------------------------------------|
| Sending chain	  | Derives one-time keys for messages you send.    |
| Receiving chain	| Derives one-time keys for messages you receive. |

Only the receiving chain is affected if messages get lost.

If you expect message #7 but only #9 arrives, you don’t know which message
keys #7 and #8 would have used yet.

To avoid losing the ability to decrypt late messages, the receiver:
  1. Derives the intermediate message keys (#7, #8) in order as soon as
     it notices a gap.
  2. Stores those keys (encrypted in memory) in a “skipped-message-key” cache.
  3. When the missing messages eventually show up, it looks up their key in
     the cache and decrypts.

These saved keys are discarded as soon as they are used, or if they get too old.



## Step-by-step breakdown

* **X3DH** is a *one-time setup* that creates an initial shared **Root Key (RK₀)**.
  It also defines Alice’s and Bob’s *initial DH key pairs* — so the very first message can be sent asynchronously.
* **Double Ratchet** takes over *after* that.
  It continuously updates keys through two intertwined mechanisms:

  * **DH Ratchet:** new ephemeral DH keys exchanged when the “speaker” changes.
  * **Symmetric Ratchet:** per-message keys derived from a chain key.

### **1️⃣ Alice begins by sending a message to Bob**

Right — they use **X3DH** to compute a shared secret **Session Key**, usually called **Root Key (RK₀)**.
That root key becomes the *starting point* for the Double Ratchet.

**State after X3DH:**

* Alice and Bob both have:

  * `RK₀` (the initial root key)
  * Alice’s initial ephemeral DH key pair `(A_DH_priv, A_DH_pub)`
  * Bob’s initial DH key pair `(B_DH_priv, B_DH_pub)` (often the signed prekey)
* They both derive:

  * `CKs₀` (Alice’s sending chain key)
  * `CKr₀` (Bob’s receiving chain key)

Alice encrypts her first message (M₁) with a message key derived from her `CKs₀`.

Bob will decrypt it with his `CKr₀`.
No DH ratchet yet — they’re still on the same pair from X3DH.


### **2a️⃣ Alice sends a second message**

She’s *still the speaker* — Bob hasn’t replied yet — so:

* No new DH key pair is generated.
* She continues along her **sending chain**:

  ```
  CKs₀ → HKDF → (CKs₁, MK₁)
  CKs₁ → HKDF → (CKs₂, MK₂)
  ```
* Each message gets a fresh message key `MK_i`, giving forward secrecy.

So: Alice does **not** produce a new DH key pair yet.
The initial pair from X3DH is still in use.
The **symmetric ratchet** (chain key → message key) advances for each message.


### **2b️⃣ Bob replies**

Now the “speaker” changes — Bob is sending after receiving a message from Alice.
This triggers a **DH ratchet step**.

Bob does:

1. Generate a **new ephemeral DH key pair**: `(B1_priv, B1_pub)`.
2. Compute:

   ```
   DH_out = ECDH(B1_priv, A_DH_pub)
   (RK₁, CKs₁, CKr₁) = HKDF(RK₀, DH_out)
   ```

   * `RK₁` = new root key
   * `CKs₁` = Bob’s sending chain key
   * `CKr₁` = Bob’s receiving chain key
3. He uses `CKs₁` to derive the message key for his reply.
4. Sends `(B1_pub, ciphertext)` to Alice.

So yes — Bob is **producing a new ephemeral DH key**, but *not* using the session key directly.
He mixes the new DH output into the root key via HKDF.

### **3a️⃣ Alice receives Bob’s reply**

Alice now sees that Bob’s message includes a **new DH public key (B1_pub)**.
This signals that a **DH ratchet step** must occur on her side too.

She does:

1. Compute the same ECDH:

   ```
   DH_out = ECDH(A_DH_priv, B1_pub)
   (RK₁, CKr₁, CKs₁) = HKDF(RK₀, DH_out)
   ```

   (note: her order of send/receive chains is swapped)
2. Replace her old `RK₀` with `RK₁`.
3. Set her new receiving chain to `CKr₁` and sending chain to `CKs₁`.
4. Delete her old DH key pair `(A_DH_priv, A_DH_pub)` — it will never be used again.
5. Generate her *own* new ephemeral DH pair `(A1_priv, A1_pub)` for the *next time she sends*.

Now the conversation continues:

* Alice’s next message will use `(A1_pub)`, triggering the next DH ratchet when Bob replies again.

## Summary of who generates what, when

| Step                     | Who acts | Generates new DH key?  | Uses which ratchet?    | Description                                                 |
| ------------------------ | -------- | ---------------------- | ---------------------- | ----------------------------------------------------------- |
| 1. X3DH                  | Both     | Yes (initial setup)    | Initial state          | Establish initial root key (RK₀)                            |
| 2a. Alice sends 2nd msg  | Alice    | ❌ No                   | Symmetric ratchet      | Just chain-key advance                                      |
| 2b. Bob replies          | Bob      | ✅ Yes                  | DH ratchet + symmetric | New DH pair (B1), derive RK₁                                |
| 3a. Alice receives reply | Alice    | ✅ Yes (after deriving) | DH ratchet + symmetric | Mix Bob’s DH, update RK₁, then create her next DH pair (A1) |


###  Intuition

* **X3DH**: "Let’s agree on our *first* secret."
* **Double Ratchet (DH part)**: "Every time the *speaker* changes, we each make a *new* DH key pair and mix it in."
* **Double Ratchet (Symmetric part)**: "Between those speaker changes, derive per-message keys so every message is unique."

Perfect 👍 — this is one of those cases where a **picture makes the protocol “click.”**
Here’s a clean, text-based **timeline diagram** showing how X3DH hands over to the Double Ratchet.


## Step 0 – X3DH: Initial Shared Secret (Root Key RK₀)

```
Alice                               Bob
  |                                   |
  |  X3DH Handshake (DH1–DH4)         |
  |---------------------------------->|
  |                                   |
  |-- derive Root Key (RK₀) --------->|  (same RK₀)
  |                                   |
  | Initial DH keypair: A₀            | Initial DH keypair: B₀
```

After X3DH:

* Both have `RK₀`
* Alice has `(A₀_priv, A₀_pub)`
* Bob has `(B₀_priv, B₀_pub)`
* Alice → Bob messages use chain derived from `RK₀`


## Step 1 – Alice Sends First Message(s)

```
Alice                               Bob
  |                                   |
  |  (A₀_pub, ciphertext₁)            |
  |---------------------------------->|
  |                                   |
  | [uses CKs₀ → MK₁]                 | [uses CKr₀ → MK₁]
  |                                   |
  | (A₀ still current DH key)         | (B₀ still current DH key)
  |                                   |
  |  (A₀_pub, ciphertext₂)            |
  |---------------------------------->|
```

➡️ No new DH key yet.
Each new message just advances the **symmetric ratchet** (`CK → MK → CK'`).


## Step 2 – Bob Replies (Triggers DH Ratchet)

```
Alice                               Bob
  |                                   |
  |            <--- receives msg 1,2  |
  |                                   |
  |                                   | (Bob generates new DH keypair)
  |                                   |   B₁ = (B₁_priv, B₁_pub)
  |                                   |
  |                                   | Compute:
  |                                   |   DH_out = ECDH(B₁_priv, A₀_pub)
  |                                   |   (RK₁, CKs₁, CKr₁) = HKDF(RK₀, DH_out)
  |                                   |
  |          (B₁_pub, ciphertext₃)    |
  |<----------------------------------|
  |                                   |
```

Bob’s first reply **rotates the DH ratchet**:

* New DH keypair **B₁**
* Mixes with Alice’s old public key **A₀_pub**
* Derives a new **root key (RK₁)** and **chain keys**


## Step 3 – Alice Receives Bob’s Reply

```
Alice                               Bob
  |                                   |
  | Receives (B₁_pub, ciphertext₃)    |
  |                                   |
  | Compute:                          |
  |   DH_out = ECDH(A₀_priv, B₁_pub)  |
  |   (RK₁, CKr₁, CKs₁) = HKDF(RK₀, DH_out)
  |                                   |
  | Deletes old A₀ keypair            |
  | Generates new DH keypair A₁       |
  |                                   |
  |  (A₁_pub, ciphertext₄)            |
  |---------------------------------->|
```

Now the ratchet has *flipped sides*:

* Alice advances to a new DH key `A₁`.
* Her next message will again trigger a new DH ratchet when Bob replies.


### Summary Table

| Event                          | Who Sends | New DH Key Pair? | What Changes?           |
| ------------------------------ | --------- | ---------------- | ----------------------- |
| X3DH handshake                 | both      | ✅ (A₀, B₀)       | Establish `RK₀`         |
| Alice → Bob (first N messages) | Alice     | ❌                | Symmetric ratchet only  |
| Bob → Alice (reply)            | Bob       | ✅ (B₁)           | New DH ratchet → `RK₁`  |
| Alice → Bob (after reply)      | Alice     | ✅ (A₁)           | Next DH ratchet → `RK₂` |


### Visual Intuition

Think of it as a **zig-zag ladder**:

```
Alice’s DH keys:   A₀ ------- A₁ ------- A₂ ...
                     \         \         \
Bob’s DH keys:        B₀ ------- B₁ ------- B₂ ...
```

Each time the “speaker” changes, a new DH pair is made → new rung on the ladder → new root key.

Between those ladder steps, the **symmetric ratchet** handles per-message keys.


## Loss of local Ratchet State

1. **Alice and Bob have an established secure session** (via X3DH → Double Ratchet).
2. **Bob goes offline.**
3. **Alice keeps sending messages** (e.g., M₆, M₇, M₈...).
   * Each new message advances Alice’s **sending chain** (symmetric ratchet).
   * These ciphertexts get **stored on the server** (the Signal service stores them encrypted).
4. **Bob’s phone is offline**, so he can’t receive or advance his **receiving chain** yet.
5. **Bob deletes his local state** (perhaps due to reinstall, data loss, etc.).

Now… what happens when Bob comes back online?

### If Bob *still had* his old ratchet state

Normally, if Bob’s ratchet state were intact:

* He would download the stored messages (M₆, M₇, …).
* For each message:

  * Use his current `CKrₙ` to derive message keys `MKₙ`.
  * Decrypt sequentially.
* The **symmetric ratchet** would let him skip over up to some number of missed
  messages (via a “message key cache”), because each chain key can be iteratively
  derived forward.

* Everything decrypts fine.
* Forward secrecy preserved.
* Out-of-order and missed messages handled correctly.

### If Bob **deleted** his local state (catastrophic loss)

If Bob deletes his local ratchet state — all the following information is lost:

* His last **root key (RKₙ)**
* His last **receiving chain key (CKrₙ)**
* His last **sending chain key (CKsₙ)**
* His most recent **DH private key**
* All cached message keys for out-of-order messages.

Without those, Bob **cannot** decrypt Alice’s queued messages.

### Why recovery is impossible

Each of Alice’s messages depends on:

```
MKᵢ = HKDF(CKsᵢ₋₁, "MessageKeys")
```

and `CKsᵢ₋₁` was derived from the *previous* chain key (which itself came from
the previous chain key, etc.), *anchored* in the last root key after the last DH ratchet.

If Bob doesn’t have that `CKr` or the previous DH state, he has no cryptographic
path to recompute any of those keys.

**Forward secrecy** ensures this irreversibility — even *Bob himself* can’t
reconstruct old keys once they’re gone.

So:

> The encryption is so strong that without the saved ratchet state,
> even the legitimate participant can’t decrypt the messages.

## What happens in practice (Signal’s solution)

Signal’s servers don’t help you recover these — they only hold ciphertexts.
So when Bob comes back online **without state**, the protocol effectively has to start over.

### Signal’s real-world behavior:

1. When Bob reinstalls or resets, he **creates a new identity key** and **uploads new prekeys** to the server.
2. The next time Alice tries to send a message, her client detects:
   * “This is a new identity for Bob (identity key changed)”
3. The client either:
   * Alerts the user (“Bob’s safety number has changed”), or
   * (If the app policy allows) automatically re-establishes a **new X3DH session**.
4. Future messages are encrypted under the **new session**, not the old one.

All old messages that were encrypted under the *lost* state are unrecoverable.

### Summary — message fate matrix

| Bob’s state                                  | What happens when he comes back              | Can decrypt old messages? | Next step                                       |
| -------------------------------------------- | -------------------------------------------- | ------------------------- | ----------------------------------------------- |
| 🔹 Still has ratchet state                   | Downloads stored ciphertexts, uses CKr chain | ✅ Yes                     | Continue ratchet normally                       |
| 🔸 State lost (reinstall/reset)              | No CKr or DH keys left                       | ❌ No                      | Start new X3DH session                          |
| 🔹 Partially lost (some message keys cached) | Can decrypt some but not all                 | ⚠️ Maybe                  | Decrypt what’s possible, re-ratchet when needed |


### Why the design *intentionally allows this loss*

It may seem inconvenient, but this “forgetfulness” is actually a **security feature**:

* If an attacker compromises Bob’s device *after* he’s lost his state, they
  can’t retroactively decrypt Alice’s old messages — even if they steal everything else.
* It enforces **forward secrecy** (past messages safe) and **post-compromise security** (new session can heal).




