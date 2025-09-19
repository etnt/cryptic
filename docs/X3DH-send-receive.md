# X3DH send and receive flow

X3DH uses the following elliptic curve public keys:

| Name | Definition            |
|------|-----------------------|
| IKA  | Alice's identity key  |
| EKA  | Alice's ephemeral key |
| IKB  | Bob's identity key    |
| SPKB | Bob's signed prekey   |
| OPKB | Bob's one-time prekey |

All public keys have a corresponding private key, but to simplify description
we will focus on the public keys.

The public keys used within an X3DH protocol run must either all be in
X25519 form, or they must all be in X448 form, depending on the curve parameter.

Each party has a long-term identity public key (IKA for Alice, IKB for Bob).

Bob also has a signed prekey SPKB, which he will change periodically,
and a set of one-time prekeys OPKB, which are each used in a single
X3DH protocol run. ("Prekeys" are so named because they are essentially
protocol messages which Bob publishes to the server prior to Alice beginning
the protocol run).

During each protocol run, Alice generates a new ephemeral key pair with
public key EKA.

After a successful protocol run Alice and Bob will share a 32-byte
secret key SK. This key may be used within some post-X3DH secure
communication protocol

## Sending the initial message

To perform an X3DH key agreement with Bob, Alice contacts the server and
fetches a "prekey bundle" containing the following values:

  * Bob's identity key IKB
  * Bob's signed prekey SPKB
  * Bob's prekey signature Sig(IKB, Encode(SPKB))
  * Bob's one-time prekey OPKB

The server should provide one of Bob's one-time prekeys, and then delete it.
If all of Bob's one-time prekeys on the server have been deleted,
the bundle will not contain a one-time prekey.

Alice verifies the prekey signature and aborts the protocol if verification
fails. Alice then generates an ephemeral key pair with public key EKA.

Alice calculates:

    DH1 = DH(IKA, SPKB)
    DH2 = DH(EKA, IKB)
    DH3 = DH(EKA, SPKB)
    DH4 = DH(EKA, OPKB)
    SK = KDF(DH1 || DH2 || DH3 || DH4)

After calculating SK, Alice deletes her ephemeral private key and the DH outputs.

Alice then calculates an "associated data" byte sequence AD that contains
identity information for both parties:

    AD = Encode(IKA) || Encode(IKB)

Alice may optionally append additional information to AD, such as Alice
and Bob's usernames, certificates, or other identifying information.

Alice then sends Bob an initial message containing:

  * Alice's identity key IKA
  * Alice's ephemeral key EKA
  * Identifiers stating which of Bob's prekeys Alice used
  * An initial ciphertext encrypted with some AEAD encryption scheme using
    AD as associated data and using an encryption key which is either SK or
    the output from some cryptographic PRF keyed by SK.
    
The initial ciphertext is typically the first message in some post-X3DH
communication protocol. In other words, this ciphertext typically has two
roles, serving as the first message within some post-X3DH protocol, and as
part of Alice's X3DH initial message.

After sending this, Alice may continue using SK or keys derived from SK
within the post-X3DH protocol for communication with Bob.

## Receiving the initial message

Upon receiving Alice's initial message, Bob retrieves Alice's identity key
and ephemeral key from the message. Bob also loads his identity private key,
and the private key(s) corresponding to whichever signed prekey and
one-time prekey (if any) Alice used.

Using these keys, Bob repeats the DH and KDF calculations from the previous
section to derive SK, and then deletes the DH values.

Bob then constructs the AD byte sequence using IKA and IKB, as described in
the previous section. Finally, Bob attempts to decrypt the initial ciphertext
using SK and AD. If the initial ciphertext fails to decrypt, then Bob aborts
the protocol and deletes SK.

If the initial ciphertext decrypts successfully the protocol is complete
for Bob. Bob deletes any one-time prekey private key that was used,
for forward secrecy. Bob may then continue using SK or keys derived from
SK within the post-X3DH protocol for communication with Alice.


