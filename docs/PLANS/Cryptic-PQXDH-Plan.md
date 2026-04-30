Cool\! **Cryptic** looks like a solid implementation of the Signal stack. Upgrading it from **X3DH** to **PQXDH** is absolutely doable, but it requires changes at three specific levels.

Since you already have the logic for X3DH in place, here are the technical steps to reach PQXDH:

## **1\. Update of "Prekey Bundles"**

In cryptic, you need to extend the data that is generated and published for a user.

* **Key Generation:** You need to add an ML-KEM key (e.g. mlkem768) as part of the user's "bundle".  
* **Storage:** A Kyber (ML-KEM) public key is significantly larger than an X25519 key (\~1184 bytes vs 32 bytes). This may affect how you serialize your bundle.  
* **Signing:** The ML-KEM key should be signed with the identity key (Ed25519) you already have in cryptic to guarantee authenticity.

## **2\. Change of Key Agreement (From X3DH to PQXDH)**

This is the biggest change in your code. Instead of 3-4 Diffie-Hellman operations, you now perform a hybrid:

* **Input:** You keep the existing DH operations (DH1, DH2, DH3).  
* **New step:** Perform a crypto:encapsulate\_key/2 against the recipient's ML-KEM key.  
* **KDF mixing:** In your current KDF (where you combine the DH results) you must now also inject the 32-byte SharedSecret from the ML-KEM operation.  
* **Payload:** The resulting Ciphertext from the ML-KEM encapsulation must be sent with the initial message to the recipient.

## **3\. Adaptation of Double Ratchet**

The good news is that **the Double Ratchet algorithm itself does not need to be changed**.

* Once the initial Root Key is established via PQXDH (instead of X3DH), the "ratcheting" process continues as usual.  
* *Extra credit:* Some choose to also make the Diffie-Hellman ratchet itself post-quantum secure, but that is significantly more complex and is not a requirement for standard PQXDH.

## **How difficult is it in practice?**

Considering that you already have a working Erlang application for this:

1. **Simplicity:** Erlang/OTP 28 makes the mathematics itself (ML-KEM) extremely simple via the crypto module.  
2. **Challenge:** The difficult part is the protocol layout (binary packing). You must ensure that your message structure can carry the new ML-KEM ciphertext.

## **Recommendation for Cryptic:**

Since you already have a stable base, I would recommend implementing it as a **"Version 2"** of your protocol.

1. Let the client check if a pq\_prekey is available in the fetched bundle.  
2. If yes: Run the PQXDH flow.  
3. If no: Fall back to your existing X3DH code.

Would you like to look at how you would need to change your **KDF function** in cryptic to accommodate the ML-KEM secret?