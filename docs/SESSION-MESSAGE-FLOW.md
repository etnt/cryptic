Here's the detailed protocol flow for the Triple Diffie-Hellman (3DH) handshake, including the error case where the One-Time Prekey (OTPK) is stale.

### Setup Phase

This is the one-time preparation phase.

1.  **Key Generation**: User B (Bob) generates his long-term cryptographic keys: an **identity key pair**, a **signed prekey pair**, and a bundle of temporary **one-time prekeys (OTPKs)**.
2.  **Key Upload**: Bob uploads the public parts of all these keys to the central server. The server stores this "pre-key bundle" for Bob.

***

### Session Establishment Phase (Success Case)

This is the standard flow for a new session.

1.  **Alice's Request**: User A (Alice) requests Bob's pre-key bundle from the server.
2.  **Server's Response**: The server sends the requested bundle to Alice. Crucially, the server **removes the used OTPK** from its storage, ensuring it can't be used again.
3.  **Alice's Key Exchange**: Alice's device uses her own keys and the keys from Bob's bundle to perform three separate Diffie-Hellman key exchanges. The results are combined to create a shared **session key**.
4.  **Message Sending**: Alice encrypts her message with the new session key. She sends this encrypted message to the server, and the message's header includes her ephemeral public key and the identifier of the specific OTPK she used.
5.  **Bob's Key Derivation**: Bob's device receives the message, reads the OTPK identifier from the header, and uses his corresponding private key to perform the same key exchange, deriving the exact same session key.
6.  **Decryption**: Bob's device uses this shared session key to successfully decrypt Alice's message. A secure session is now established.

***

### Session Establishment Phase (Error Case)

This flow occurs if Bob has rotated his keys, making the OTPK stale.

1.  **Alice's Request**: Alice's device requests Bob's pre-key bundle. Let's say it gets an old bundle just before Bob uploads a new one.
2.  **Server's Response**: The server provides Alice with one of the old, soon-to-be-stale OTPKs and removes it from its storage.
3.  **Bob's Key Rotation**: Shortly after, Bob's device rotates its keys. It uploads a new key bundle to the server and **deletes the old private keys**, including the private key for the OTPK that Alice just received.
4.  **Alice's Key Exchange & Message Sending**: Alice's device, unaware of the key rotation, performs the 3DH key exchange using the now-stale OTPK. She encrypts her message and sends it to the server with the OTPK's identifier.
5.  **Bob's Failed Decryption**: When the message arrives at Bob's device, it attempts to find the private key corresponding to the OTPK identifier in the message header. It fails because that key has been deleted during the rotation. Bob's device **drops the message** as it cannot be decrypted.
6.  **Protocol Recovery**: Bob's device, upon receiving an undecryptable message, can signal a failure to the server. The server, in turn, can notify Alice's device that the message was not delivered. Alice's app then automatically requests a **fresh key bundle** from the server, re-encrypts the original message with the new keys, and resends it. This process is transparent to the user, who only experiences a minor delay.

Yes, that's a correct assumption. For the protocol to work, Alice's device must be able to match the delivery failure notification to the specific message that needs to be resent. This is handled by including a unique **message identifier** in the message header.

Here's how that works in the context of the protocol flow:

1.  **Unique Message ID**: When Alice's device encrypts a message, it assigns a unique identifier (a `message_id`) to it. This ID is included in the message header along with the OTPK identifier.
2.  **Server Delivery**: The server receives the message and attempts to deliver it to Bob. The server logs the `message_id` associated with the delivery attempt.
3.  **Failure Notification**: When Bob's device fails to decrypt the message, it signals an error back to the server. The server then uses the `message_id` from its logs to send a "delivery failure" notification back to Alice's device.
4.  **Local Message Matching**: Alice's device receives this notification and checks its own local log of sent messages for the corresponding `message_id`. Once a match is found, her device knows exactly which message needs to be re-encrypted and resent.

This ensures that the correct message is re-sent, preventing any confusion and making the process seamless and reliable.
