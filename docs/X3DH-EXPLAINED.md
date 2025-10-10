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
