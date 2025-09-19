# X3DH Mathematical Calculations# X3DH Mathematical C## 1. Keys and Notation



This document provides a **step-by-step technical breakdown** of the mathematical computations performed in the **Extended Triple Diffie–Hellman (X3DH)** key agreement protocol when **Alice initiates a session to send a message to Bob**.|## 2. Computations Performed by Alice (Sender)



## OverviewAlice fetches Bob's "prekey bundle" containing:

- `IK_B_pub` (Bob's identity public key)

This document shows:- `SPK_B_pub` (Bob's signed prekey public key) 

- `OPK_B_pub` (Bob's one-time prekey public key, optional)

- Which key pairs are involved- Signature on `SPK_B`

- The actual elliptic-curve Diffie–Hellman computations performed

- What each party (Alice and Bob) calculates### 2.1 Initial Setup



---1. **Verify Bob's signature** on `SPK_B`

2. **Generate ephemeral keypair:**

## 1. Keys and Notation

```

| Symbol       | Owner                               | Type                                                     |ek_A_priv ← random 32-byte scalar

|--------------|-------------------------------------|----------------------------------------------------------|EK_A_pub = Curve25519BaseMult(ek_A_priv)

| **IK_A**     | Alice's identity key (long-term)    | static Curve25519 keypair: `(ik_A_priv, IK_A_pub)`      |``` Owner                               | Type                                                     |

| **IK_B**     | Bob's identity key (long-term)      | static Curve25519 keypair: `(ik_B_priv, IK_B_pub)`      ||--------------|-------------------------------------|----------------------------------------------------------|

| **SPK_B**    | Bob's signed prekey (medium-term)   | static Curve25519 keypair: `(spk_B_priv, SPK_B_pub)`    || **IK_A**     | Alice's identity key (long-term)    | static Curve25519 keypair: `(ik_A_priv, IK_A_pub)`      |

| **OPK_B**    | Bob's one-time prekey (optional)    | static Curve25519 keypair: `(opk_B_priv, OPK_B_pub)`    || **IK_B**     | Bob's identity key (long-term)      | static Curve25519 keypair: `(ik_B_priv, IK_B_pub)`      |

| **EK_A**     | Alice's ephemeral key               | ephemeral Curve25519 keypair: `(ek_A_priv, EK_A_pub)`   || **SPK_B**    | Bob's signed prekey (medium-term)   | static Curve25519 keypair: `(spk_B_priv, SPK_B_pub)`    |

| **OPK_B**    | Bob's one-time prekey (optional)    | static Curve25519 keypair: `(opk_B_priv, OPK_B_pub)`    |

**Key Properties:**| **EK_A**     | Alice's ephemeral key               | ephemeral Curve25519 keypair: `(ek_A_priv, EK_A_pub)`   |

- All keys are Curve25519 (Montgomery curve) public/private pairs

- The Diffie–Hellman function is `ECDH(priv, pub) → 32-byte shared secret`**Key Properties:**

- All keys are Curve25519 (Montgomery curve) public/private pairs

---- The Diffie–Hellman function is `ECDH(priv, pub) → 32-byte shared secret`

This document provides a **step-by-step technical breakdown** of the mathematical computations performed in the **Extended Triple Diffie–Hellman (X3DH)** key agreement protocol when **Alice initiates a session to send a message to Bob**.

## 2. Computations Performed by Alice (Sender)

## Overview

Alice fetches Bob's "prekey bundle" containing:

- `IK_B_pub` (Bob's identity public key)This document shows:

- `SPK_B_pub` (Bob's signed prekey public key) 

- `OPK_B_pub` (Bob's one-time prekey public key, optional)- Which key pairs are involved

- Signature on `SPK_B`- The actual elliptic-curve Diffie–Hellman computations performed

- What each party (Alice and Bob) calculates

### 2.1 Initial Setup

--- **step-by-step technical breakdown** of the *mathematical computations* performed in the **Extended Triple Diffie–Hellman (X3DH)** key agreement protocol when **Alice initiates a session to send a message to Bob**.

1. **Verify Bob's signature** on `SPK_B`I will show:

2. **Generate ephemeral keypair:**

* Which key pairs are involved

```* The *actual elliptic-curve Diffie–Hellman* computations performed

ek_A_priv ← random 32-byte scalar* What each party (Alice and Bob) calculates.

EK_A_pub = Curve25519BaseMult(ek_A_priv)

```---



### 2.2 Diffie–Hellman Computations## 1. Keys and Notation



Alice computes four (or three) X25519 operations:| Symbol     | Who owns it                         | Type                                                    |

| ---------- | ----------------------------------- | ------------------------------------------------------- |

1. **DH1**: Alice's identity × Bob's signed prekey| **IK\_A**  | Alice’s *identity key* (long-term)  | static Curve25519 keypair: (ik\_A\_priv, IK\_A\_pub)    |

   ```| **IK\_B**  | Bob’s *identity key* (long-term)    | static Curve25519 keypair: (ik\_B\_priv, IK\_B\_pub)    |

   DH1 = ECDH(ik_A_priv, SPK_B_pub)| **SPK\_B** | Bob’s *signed prekey* (medium-term) | static Curve25519 keypair: (spk\_B\_priv, SPK\_B\_pub)  |

   ```| **OPK\_B** | Bob’s *one-time prekey* (optional)  | static Curve25519 keypair: (opk\_B\_priv, OPK\_B\_pub)  |

| **EK\_A**  | Alice’s *ephemeral key*             | ephemeral Curve25519 keypair: (ek\_A\_priv, EK\_A\_pub) |

2. **DH2**: Alice's ephemeral × Bob's identity

   ```All keys are Curve25519 (Montgomery curve) public/private pairs.

   DH2 = ECDH(ek_A_priv, IK_B_pub)The Diffie–Hellman function is **ECDH(priv, pub) → 32-byte shared secret**.

   ```

---

3. **DH3**: Alice's ephemeral × Bob's signed prekey

   ```## 2. Computations Performed by Alice (Sender)

   DH3 = ECDH(ek_A_priv, SPK_B_pub)

   ```Alice fetches from Bob’s “prekey bundle”:

**IK\_B\_pub**, **SPK\_B\_pub**, (optional) **OPK\_B\_pub**, and the signature on SPK\_B.

4. **DH4 (optional)**: Alice's ephemeral × Bob's one-time prekey

   ```She first verifies Bob’s signature on SPK\_B.

   DH4 = ECDH(ek_A_priv, OPK_B_pub)

   ```Then she generates a fresh ephemeral key pair:

   *(Only if Bob provided a one-time prekey)*

$$

### 2.3 Key Derivation\begin{aligned}

\text{ek\_A\_priv} &\leftarrow \text{random 32-byte scalar} \\

1. **Concatenate DH outputs** in the prescribed order:\text{EK\_A\_pub} &= \text{Curve25519BaseMult(ek\_A\_priv)}

   ```\end{aligned}

   SK_input = DH1 || DH2 || DH3 [|| DH4]$$

   ```

---

2. **Derive session key** using HKDF:

   ```### 2.1 Diffie–Hellman Computations

   SK = HKDF(SK_input, salt, info)

   ```Alice computes the four (or three) X25519 operations:



`SK` is the shared secret (root key) that will be used to encrypt Alice's initial message.1. **DH1**: Between her *identity* and Bob’s *signed prekey*



### 2.4 Message to Bob$$

\boxed{DH1 = ECDH(ik\_A\_priv, SPK\_B\_pub)}

Alice sends to Bob:$$

- `IK_A_pub` (her identity public key)

- `EK_A_pub` (her ephemeral public key)2. **DH2**: Between her *ephemeral* and Bob’s *identity* key

- Identifier for which one-time prekey was used (if any)

- Ciphertext of her first message (encrypted using a key derived from `SK`)$$

\boxed{DH2 = ECDH(ek\_A\_priv, IK\_B\_pub)}

---$$



## 3. Computations Performed by Bob (Receiver)3. **DH3**: Between her *ephemeral* and Bob’s *signed prekey*



Bob receives Alice's bundle and already knows his own private keys:$$

- `ik_B_priv`\boxed{DH3 = ECDH(ek\_A\_priv, SPK\_B\_pub)}

- `spk_B_priv`$$

- `opk_B_priv` (if used)

4. **DH4 (optional)**: If Bob advertised a one-time prekey

### 3.1 Diffie–Hellman Computations

$$

Bob recomputes the same four DH values using his private keys:\boxed{DH4 = ECDH(ek\_A\_priv, OPK\_B\_pub)}

$$

1. **DH1**: Bob's signed prekey × Alice's identity

   ```(if no one-time prekey, this step is omitted).

   DH1 = ECDH(spk_B_priv, IK_A_pub)

   ```---



2. **DH2**: Bob's identity × Alice's ephemeral### 2.2 Key Derivation

   ```

   DH2 = ECDH(ik_B_priv, EK_A_pub)Concatenate the DH outputs in the prescribed order:

   ```

$$

3. **DH3**: Bob's signed prekey × Alice's ephemeral\text{SK\_input} =

   ```   DH1 \,\|\, DH2 \,\|\, DH3 \,[\|\, DH4]

   DH3 = ECDH(spk_B_priv, EK_A_pub)$$

   ```

Run through a KDF (usually **HKDF** with protocol-specific salt and info):

4. **DH4 (optional)**: Bob's one-time prekey × Alice's ephemeral

   ```$$

   DH4 = ECDH(opk_B_priv, EK_A_pub)\boxed{SK = HKDF(SK\_input, salt, info)}

   ```$$

   *(Only if the indicated one-time prekey was used)*

`SK` is the shared secret (root key) that will be used to encrypt Alice’s initial message.

**Note:** Each computation is the same scalar multiplication as Alice's but with private/public roles swapped. Because ECDH is symmetric: `ECDH(a,b) = ECDH(b,a)`.

Alice sends to Bob:

### 3.2 Key Derivation

* `IK_A_pub` (her identity key)

Bob concatenates in the **exact same order**:* `EK_A_pub` (her ephemeral public key)

* identifiers for which one-time prekey was used (if any)

1. **Concatenate DH outputs:*** the ciphertext of her first message (encrypted using a key derived from `SK`).

   ```

   SK_input = DH1 || DH2 || DH3 [|| DH4]---

   ```

## 3. Computations Performed by Bob (Receiver)

2. **Derive session key:**

   ```Bob receives Alice’s bundle.

   SK = HKDF(SK_input, salt, info)He already knows his own:

   ```

* `ik_B_priv`

Bob obtains **exactly the same shared secret SK** as Alice.* `spk_B_priv`

* `opk_B_priv` (if used).

Bob then uses `SK` to decrypt the first message and start a Double Ratchet session.

---

---

### 3.1 Diffie–Hellman Computations

## 4. Summary Table

Bob recomputes the same four values:

| Step           | Alice computes                    | Bob computes                      |

|----------------|-----------------------------------|-----------------------------------|1. **DH1**:

| **DH1**        | `ECDH(ik_A_priv, SPK_B_pub)`      | `ECDH(spk_B_priv, IK_A_pub)`      |

| **DH2**        | `ECDH(ek_A_priv, IK_B_pub)`       | `ECDH(ik_B_priv, EK_A_pub)`       |$$

| **DH3**        | `ECDH(ek_A_priv, SPK_B_pub)`      | `ECDH(spk_B_priv, EK_A_pub)`      |\boxed{DH1 = ECDH(spk\_B\_priv, IK\_A\_pub)}

| **DH4**        | `ECDH(ek_A_priv, OPK_B_pub)`      | `ECDH(opk_B_priv, EK_A_pub)`      |$$

| **HKDF**       | `HKDF(DH1||DH2||DH3[||DH4])`      | `HKDF(DH1||DH2||DH3[||DH4])`      |

2. **DH2**:

The concatenated output of the Diffie–Hellman operations is the **input to HKDF** to derive the session root key.

$$

---\boxed{DH2 = ECDH(ik\_B\_priv, EK\_A\_pub)}

$$

## Important Notes

3. **DH3**:

- The protocol relies on Curve25519's X25519 function, which performs scalar multiplication of the private scalar with the peer's public curve point

- The HKDF salt and "info" values are specified by the Signal/X3DH spec to ensure domain separation$$

- This is the exact set of calculations both sides carry out when Alice sends the initial message to Bob in the X3DH protocol\boxed{DH3 = ECDH(spk\_B\_priv, EK\_A\_pub)}

$$

---

4. **DH4 (optional)**:

## Mathematical Properties

$$

### ECDH Symmetry\boxed{DH4 = ECDH(opk\_B\_priv, EK\_A\_pub)}

The key property that makes X3DH work is the symmetry of elliptic curve Diffie-Hellman:$$



```(if the indicated one-time prekey was used).

ECDH(private_key_A, public_key_B) = ECDH(private_key_B, public_key_A)

```Note that each is the same scalar multiplication as Alice’s but with private/public roles swapped; because ECDH is symmetric,



This ensures that Alice computing `ECDH(ik_A_priv, SPK_B_pub)` produces the same result as Bob computing `ECDH(spk_B_priv, IK_A_pub)`.$$

ECDH(a,b)=ECDH(b,a).

### Security Properties$$



The X3DH protocol provides:---



1. **Perfect Forward Secrecy**: Compromise of long-term keys doesn't compromise past sessions due to ephemeral keys### 3.2 Key Derivation

2. **Mutual Authentication**: Both parties can verify each other's identity through the signed prekeys

3. **Resistance to Key-Compromise Impersonation**: An attacker who compromises one party's keys cannot impersonate others to that partyBob concatenates in the *exact same order*:

4. **Resistance to Replay Attacks**: One-time prekeys prevent replay of initial messages
$$
\text{SK\_input} =
   DH1 \,\|\, DH2 \,\|\, DH3 \,[\|\, DH4]
$$

$$
\boxed{SK = HKDF(SK\_input, salt, info)}
$$

He obtains **exactly the same shared secret SK** as Alice.

Bob then uses SK to decrypt the first message and start a Double Ratchet session.

---

## 4. Summary Table

| Step           | Alice computes                 | Bob computes                   |     |   |       |   |       |          |   |     |   |       |   |       |
| -------------- | ------------------------------ | ------------------------------ | --- | - | ----- | - | ----- | -------- | - | --- | - | ----- | - | ----- |
| DH1            | ECDH(ik\_A\_priv, SPK\_B\_pub) | ECDH(spk\_B\_priv, IK\_A\_pub) |     |   |       |   |       |          |   |     |   |       |   |       |
| DH2            | ECDH(ek\_A\_priv, IK\_B\_pub)  | ECDH(ik\_B\_priv, EK\_A\_pub)  |     |   |       |   |       |          |   |     |   |       |   |       |
| DH3            | ECDH(ek\_A\_priv, SPK\_B\_pub) | ECDH(spk\_B\_priv, EK\_A\_pub) |     |   |       |   |       |          |   |     |   |       |   |       |
| DH4 (optional) | ECDH(ek\_A\_priv, OPK\_B\_pub) | ECDH(opk\_B\_priv, EK\_A\_pub) |     |   |       |   |       |          |   |     |   |       |   |       |
| HKDF           | HKDF(DH1                       |                                | DH2 |   | DH3\[ |   | DH4]) | HKDF(DH1 |   | DH2 |   | DH3\[ |   | DH4]) |

The concatenated output of the Diffie–Hellman operations is the **input to HKDF** to derive the session root key.

---

### Important Notes

* The protocol relies on Curve25519’s X25519 function, which performs scalar multiplication of the private scalar with the peer’s public curve point.
* The HKDF salt and “info” values are specified by the Signal/X3DH spec to ensure domain separation.

This is the exact set of calculations both sides carry out when Alice sends the initial message to Bob in the X3DH protocol.

