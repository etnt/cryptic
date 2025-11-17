# Pairwise Double-Ratchet Fan-Out
> Each sender encrypts each message to every participant using their pairwise ratchet.

Let’s design a *virtual room* built on the pairwise fan-out model.

## High level idea

A **room** in fan-out land is just a logical container (an ID and a signed
membership list) that every member uses as the target for messages.
When someone sends to the room, they encrypt the same plaintext separately
to each *other* participant using the pairwise Double-Ratchet session for
that recipient (or X3DH if initializing), then submit the per-recipient
ciphertexts to the server. The server only handles routing/storage — it does
**not** hold room keys.

## Room canonicalization (how members agree on “the same room”)

Pick one of these two simple, robust approaches:

1. **Server-issued room ID (recommended)**

   * Client A requests server to create room with `members = [A,B,C]` and
     optional metadata.
   * Server returns `room_id = uuidv4()` and stores a signed creation event
     (creator’s signature over `{room_id, members, created_at, version}`)
     so clients can verify authenticity.
   * The creator (or server) distributes the room_id and signed creation
     event to all members.

2. **Deterministic room ID (serverless/dedup)**

   * Compute `room_id = H("room-v1" || sorted(member_ids) || creation_nonce)`
     where `creation_nonce` is a random value chosen by the creator and
     included in the creation event.
   * Creator signs `{room_id, members, creation_nonce, created_at}` and shares
     that signed creation event with members.
   * This avoids collisions but requires passing the creation event around.

Either way, the canonical truth about the room is the signed
*room creation event* which lists members and a version/epoch.
Clients verify the creator’s signature on the creation event to ensure
everyone refers to the same room.

## Minimal canonical room data model

A canonical room object (what clients store) — JSON example:

```json
{
  "room_id": "uuid-1234",
  "creator": "alice@example",
  "members": ["alice@example","bob@example","carol@example"],
  "created_at": "2025-11-06T11:02:00Z",
  "version": 1,
  "signature": "BASE64(sig_of_creator_over_the_object)"
}
```

Store this locally, and optionally upload the signed creation event to the
server so other clients can fetch it.

## Message sending model (fan-out)

When Alice sends a message to the room:

1. For each recipient R in room.members except Alice:

   * Ensure there is a Double-Ratchet session with R.
   * If no session exists and R is offline, perform X3DH using R’s prekey
     bundle to establish session (one-time).
    
2. Use the recipient’s DR state to produce one ciphertext and attach the
   DR header (public ratchet key, pn, n) for that recipient.
  
3. Build a **room envelope** that contains:
   * `room_id`, `sender_id`, `sender_client_id`, `client_msg_id`, `timestamp`
   * For each recipient: `{recipient_id, dr_header, ciphertext}`
  
4. Upload the envelope to the server. The server stores/forwards the
   envelope and routes each per-recipient blob to the correct device(s)
   of that recipient.

You can either:

* Upload a single envelope that contains all recipient payloads (efficient server API), or
* Upload N separate outgoing messages (one per recipient) — easier but more HTTP calls.

## Example message envelope (schema)

```json
{
  "room_id": "uuid-1234",
  "sender_id": "alice@example",
  "client_msg_id": "msg-0001",
  "timestamp": "2025-11-06T11:12:00Z",
  "attachments": [
    {
      "recipient_id": "bob@example",
      "dr_header": {
        "rk_public": "BASE64(pk)",
        "pn": 0,
        "n": 5
      },
      "ciphertext": "BASE64(...)"
    },
    {
      "recipient_id": "carol@example",
      "dr_header": { ... },
      "ciphertext": "BASE64(...)"
    }
  ],
  "signature": "BASE64(sig_of_sender_over_room_id + client_msg_id + hash_of_ciphertexts)"
}
```

Signing the envelope protects against server substitution or mixing.

## Pseudocode (sender)

```python
def send_room_message(room, plaintext):
    envelope = {
      "room_id": room.room_id,
      "sender_id": me.id,
      "client_msg_id": random_id(),
      "timestamp": now_iso(),
      "attachments": []
    }

    for recipient in room.members:
        if recipient == me.id: continue
        session = get_dr_session(recipient)
        if not session:
            prekey_bundle = fetch_prekey_bundle(recipient)
            session = x3dh_and_init_dr(prekey_bundle)
            store_dr_session(recipient, session)
        header, ciphertext = dr_encrypt(session, plaintext, associated_data=room.room_id)
        envelope["attachments"].append({
            "recipient_id": recipient,
            "dr_header": header,
            "ciphertext": ciphertext
        })

    envelope["signature"] = sign(my_signing_key, canonicalize(envelope_without_signature))
    upload_envelope_to_server(envelope)
    locally_display_message_as_sent(envelope)
```

Important: include `room_id` as associated data (AAD) when encrypting so
ciphertexts are bound to the room.

## Pseudocode (recipient)

```python
def on_receive_envelope(envelope):
    for att in envelope["attachments"]:
        if att["recipient_id"] != me.id: continue
        header = att["dr_header"]
        ciphertext = att["ciphertext"]
        session = get_dr_session(envelope["sender_id"])
        # If session missing but header contains X25519 public key, initialize ratchet state as needed
        plaintext = dr_decrypt(session, header, ciphertext, associated_data=envelope["room_id"])
        deliver_plaintext_to_room_ui(envelope["room_id"], envelope["sender_id"], plaintext, envelope["client_msg_id"])
```

## Server responsibilities

* Maintain room metadata (signed creation events) and membership lists
  (ditch membership list if you want privacy — but signing is helpful).
* Route delivery: when a sender uploads an envelope, the server looks at
  attachments and deposits each attachment into recipient’s inbox or pushes
  it to online devices.
* Provide an API to fetch prekey bundles for X3DH.
* Optionally keep a copy of the signed room creation event and message
  envelopes (encrypted) for sync/history storage.

**Do not** let the server hold any symmetric room keys because we are in a
pure fan-out design.

## Membership changes (join / leave / invite)

* Membership is an ordered list expressed in a signed *room membership event* (versioned).
* When a member is **added**:

  * Creator or moderator issues a signed membership event (new version) that
    includes the new member.
  * Existing members fetch the membership event and accept it (verify signature).
  * The initial policy: existing messages are not automatically re-encrypted.
    New member will only get messages encrypted for them after they’re added.
  * If you want new members to read history, you must re-encrypt that history
    for them (server could store encrypted history, but to avoid breaking E2E
    you'd need each member to re-share/reencrypt history to the new member via
    pairwise sessions).
    
* When a member **leaves / is removed**:

  * Issue a new signed membership event marking that member removed.
  * From that point on, senders stop encrypting to the leaver (so they can't
    read future messages).
  * If the leaver had any cached messages or devices, you cannot force delete
    those client-side; consider issuing a room epoch bump (see below) if you
    need stronger guarantees.

## Room epochs and stronger forward secrecy

With fan-out, you automatically get forward secrecy per pair. However,
to express a clear boundary (i.e., “messages after this time are not
readable by previous member”), implement *room epochs*:

* On membership change, increment `room.version` or `room.epoch`.
* Include `room.epoch` as AD in DR encryption.
* Optionally require senders to **not** send to previously removed members
  on epoch ≥ new value.

Epochs are just metadata that help clients coordinate.

## History & sync decisions

You must choose a policy:

* **No history to new members** (simple, secure).
* **Provide history on invite**: require each existing member to re-encrypt
  selected historical messages to the new member (expensive).
* **Server-mediated history**: server keeps encrypted history; when adding
  a user, members re-share symmetric keys (not recommended without strong protocols).

## Offline recipients & prekey usage

* Use X3DH prekey bundles to bootstrap when recipient is offline. After
  the initial X3DH exchange, you’ll have a DR session for subsequent messages.
* You must ensure idempotent X3DH computes same shared state if multiple
  devices exist — track device IDs and per-device prekeys.

## Delivery receipts, read markers, message ordering

* Use per-recipient per-device receipts. Encrypted receipts are preferred
  (signed or encrypted with the sender’s DR session).
* Ordering: server can assign a monotonic `server_seq` to envelopes to
  provide a canonical order. Clients should accept server_seq but still
  handle reordering because of sync delays.
* Use `client_msg_id` + `timestamp` + `server_seq` to dedupe and reconcile.

## Security considerations / pitfalls

* **Binding**: always bind ciphertexts to `room_id` via associated data
  (AAD) to prevent cross-room replay.
* **Sign creation and membership events**: prevents server from injecting
  fake members or replaying older member lists.
* **Protect against replay**: include `client_msg_id` and per-recipient
  ratchet counters; reject duplicates.
* **Device management**: treat each device as independent identity for
  ratchet sessions. Membership lists should reference device lists (or you
  can rely on server to map user→devices).
* **Do not store ratchet state on server** — store locally on client devices only.

## When this approach is OK and when to move on

* OK for small groups (few participants) or when you prefer simplicity and
  reusing your DR + X3DH code.
* Inefficient as N grows (sender CPU + bandwidth ∝ N). If groups exceed
  ~10–20 active members regularly, consider moving to Signal Sender Keys or MLS later.

## Optimizations

* Parallelize per-recipient encryption to use all CPU cores.
* Cache prekey bundles and DR sessions.
* If many devices per user, send a single copy to server and let server
  fan-out to a user’s devices (but those device inboxes still hold per-device
  ciphertexts).
* Add optional compression before encryption to reduce size.

## Example timeline for adding this to your system

1. Implement room creation API + signed creation events.
2. Implement per-recipient envelope structure and server API to upload single
   envelope containing many attachments.
3. Implement client send loop to fan-out with DR sessions + prekeys.
4. Implement recipient decryption path and UI hooks for messages in rooms.
5. Add membership events and epoch handling.
6. Add receipts and message ordering.

