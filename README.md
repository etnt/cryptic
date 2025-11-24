# Cryptic - End-to-End Encrypted Chat System

> **⚠️ DISCLAIMER**
>
> This is an **educational implementation** of cryptographic protocols, created
> for learning purposes. It has **not been audited** and may contain security
> vulnerabilities.
>
> Cryptographic software is extremely difficult to implement correctly.
> Even small mistakes can completely undermine security.
>
> **NO WARRANTIES** of any kind. Use at your own risk. For production needs,
> use professionally audited solutions like Signal or Matrix.

**Cryptic** is an implementation of an end-to-end encrypted chat system built
in Erlang/OTP, featuring WebSocket mTLS communication, real-time messaging, and
demonstrating modern cryptographic protocols for secure message exchange.

**Cryptic** implements a secure messaging system:

* Uses Client Certificate to authenticate Users.
* Uses WebSocket TLS communication.
* Implements the [X3DH](https://signal.org/docs/specifications/x3dh/) and
  the [Double-Ratchet](https://signal.org/docs/specifications/doubleratchet/)
  cryptographic protocols.
* Admin-mediated GPG-based onboarding where users prove ownership with
  GPG-signed CSRs to get certificates.

**Cryptic** consists of:

* A server that route messages between users, and holds on to encrypted messages
  until they can be delivered to the receiver.
* A terminal console client.
* Local Sqlite3 database that stores historic messages (encrypted).
* A wizard script to facilitate onboarding of new users.
* Modular structure to make the core engines (X3DH & Double-Ratchet) available
  to be used in other contexts/applications.
* Docker images for both the server and the client exists for
  [containerized deployment](docs/DOCKER.md).
  
An ****external TUI**** (Terminal User Interface) exist, written in Rust, that
connects via the Erlang distribution protocol as a hidden node.
See: [cryptic-tui](https://github.com/etnt/cryptic-tui)

[Demo](https://youtu.be/R2lM5GLypc0?si=2Ux8TrRuQXZTkZFN)

## Documentation

📚 **[Complete API Documentation](https://etnt.github.io/cryptic/)** - Comprehensive EDoc-generated documentation

For local documentation generation:
```bash
rebar3 ex_doc
# Open doc/index.html in your browser
```

## Overview

Cryptic implements a secure messaging system using:
- **WebSocket mTLS** communication for real-time, certificate-authenticated messaging
- **Double Ratchet Protocol** for advanced forward secrecy and break-in recovery
- **X3DH Key Agreement** for secure session establishment
- **X25519** key agreement for establishing shared secrets
- **ChaCha20-Poly1305** AEAD encryption for message confidentiality and authenticity
- **Blake2b KDF** (39x faster than Erlang) for high-performance key derivation
- **Out-of-order message handling** with skipped message key store
- **Automatic ratchet session management** with seamless X3DH-to-ratchet transitions
- **Terminal UI** with real-time chat capabilities and ratchet status display
- **SQLite3** database to hold the encrypted messages.


## Quick build

``` bash
> git clone https://github.com/etnt/cryptic.git

> cd cryptic

> rebar3 compile
```


## Client Quick Start (when onboarded)

```bash
# Start the console client
> ./bin/cryptic -u alice --enable-db

# Specify the server and port to be used
> ./bin/cryptic -u alice --enable-db -s cryptic.example.com -p 9443

# Start with TUI mode (detached backend + external UI)
# Make sure to have the `cryptic-tui` binary in your PATH!
# See: https://github.com/etnt/cryptic-tui
> ./bin/cryptic -u alice --tui

# Connect to TUI backend via remote shell
> erl -sname admin -remsh alice@localhost
```

## Server Quick Start (when setup)

``` bash
# Start the server
> ./scripts/start-server.sh

# Start the server on another port with a custom Erlang node name
> ./scripts/start-server.sh -p 9000 --sname demo@localhost
```

## Onboard new users

A new User has to be approved by an _admin user_. This is done by sending
the User's GPG Public key and the corresponding GPG fingerprint to the 
admin user. This process is taken care of by the `cryptic --onboard` script.

### ./bin/cryptic --onboard

This is the Wizard menu system of the `./bin/cryptic --onboard` script.

```
   ╔═══════════════════════════════════════════════════════════════╗
   ║           Welcome to Cryptic Onboarding Wizard                ║
   ║                                                               ║
   ║  This wizard will guide you through the complete process      ║
   ║  of setting up your Cryptic secure messaging account.         ║
   ╚═══════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

What would you like to do?

  1) Generate a new GPG key pair
  2) Export GPG public key for admin registration
  3) Request a TLS certificate from server
  4) Check certificate status and expiration
  5) Complete onboarding walkthrough (steps 1-3)
  6) Show help and documentation
  0) Exit

Enter your choice [0-6]:
```

A new User follows the steps 1-3 and can then login to via the
`./bin/cryptic` client.

### Bootstrap the very first user

To bootstrap the very first user, read [here](docs/GPG-BOOTSTRAP.md) .

## The Client

So when you start the Client Console, you are immediately prompted for a
passphrase; this passphrase is used for encrypting your keys stored on your
local disk in your `$HOME/.cryptic` directory. The layout of this directory
looks like this:
```bash
❯ tree ~/.cryptic
/Users/tobbe/.cryptic
├── alice
│   ├── localhost_8443
│   │   ├── certificates
│   │   │   ├── alice.crt
│   │   │   ├── alice.key
│   │   │   ├── alice.pem
│   │   │   └── ca.crt
│   │   ├── keys.encrypted
│   │   └── sessions
│   │       ├── bob.session
│   │       └── gunnar.session
│   ├── cryptic.example.org_9997
│   │   ├── certificates
│   │   │   ├── alice.crt
│   │   │   ├── alice.key
│   │   │   ├── alice.pem
│   │   │   └── ca.crt
│   │   ├── keys.encrypted
│   │   └── sessions
│   │       └── bob.session
│   ├── messages.db
│   ├── messages.db-shm
│   └── messages.db-wal
...
```

So in the example above, the user `alice` are using two different cryptic
servers, one running on _localhost_ with the port: 8443 and one running
at _cryptic.example.org_ with the port: 9997. Under the
`certificates` directory we find the certificate and key used for the client
authentication over TLS. The file: `keys.encrypted` is an encrypted file
(using your passphrase) containing the Identity keys used for the X3DH protocol.
Under the `sessions` directory we find encrypted files ending in `.session`
which contains the Double-Ratchet keys used for the communication with
another User. It is important to have the `.cryptic` directory protected
since (currently) the private key used for client authentication
(e.g `alice.key`) is unprotected. Finally we have a couple of `messages.db*`
files which are the SQLite3 database holding the encrypted messages. 


### Aliases - Group Messaging

Aliases is a Poor man's chat room functionality.

The console supports aliases for group messaging. Create named
aliases containing multiple usernames, then send messages to all members
at once using the `@alias` syntax. For example, create a work group with
`:an work bob alice dave`, then broadcast messages with
`:s @work Coffee break?`. Aliases support full management operations
including adding/removing members (`:aa`, `:ar`), deletion (`:ad`), and
listing (`:a`). Each message sent to an alias shows individual deliver
confirmations for all members. See `help alias` in the console for complete
documentation and examples.

### Encrypted Message Storage

Cryptic includes optional SQLite-based message persistence with
ChaCha20-Poly1305 encryption. All received messages can be automatically
saved to an encrypted local database, allowing you to query your message
history using flexible commands like `:hi last 20`, `:hi from alice yesterday`,
or `:hi with bob`.

The storage feature can be enabled/disabled at runtime via the 
`db enable/db disable` commands, giving you control over when messages are
persisted. Messages are encrypted with your passphrase before being stored,
and history displays are grouped by federated server for clarity.
Enable at startup by using the `--enable-db` switch.

### Engine Status 

The **engine_status** command will show details of the Double-Ratchet engine:
```
=== Double Ratchet Sessions ===
Active sessions: 2
  alice: Step 2, Chain[3 init, 5 resp], Prev[2 msgs], Skipped[0 keys]
  bob: Step 1, Chain[5 init, 3 resp], Prev[2 msgs], Skipped[2 keys]
       │        │                      │             └─ Network health indicator
       │        │                      └─ Previous chain history  
       │        └─ Current chain activity (init/resp contexts)
       └─ DH ratchet steps (forward secrecy rotations)
```

**Status Line Explanation:**
- **Step X**: Number of DH ratchet steps (key rotations for forward secrecy)
- **Chain[X init, Y resp]**: Current message counters for initiator/responder chains
- **Prev[X msgs]**: Messages processed in previous receiving chain before rotation
- **Skipped[X keys]**: Out-of-order messages cached (network health indicator)

### Get Notified

Cryptic provides two notification mechanisms to alert you when messages arrive:

#### Script-Based Notification (`--notifier`)

By using the option `--notifier <file-path>` you can specify a script
that will be invoked whenever a message arrives. The script will be
invoked with the Username of the sender as argument. So on Linux this
script can for example call `notify-send` and on Mac it can call
`terminal-notifier`. This will produce a Desktop alert to pop-up.

Example (Mac):
```bash
> ./bin/cryptic -u alice --notifier /home/alice/.cryptic/notify.sh

> cat /home/alice/.cryptic/notify.sh
#!/bin/bash
terminal-notifier -title "Cryptic" -message "Cryptic message from: $1" -sound default

# On Linux we could use:
# notify-send "Cryptic message from: $1"
```

#### File-Based Notification (`--file-notify`)

For Docker-compatible deployments or when script execution isn't suitable, use
`--file-notify <filename>` to write the sender's username to a file. The file
is created in `~/.cryptic/<username>/<server>_<port>/` and can be monitored by
external file watchers.

**Mac (using fswatch):**
```bash
# Start the client with file notification
> ./bin/cryptic -u alice --file-notify sender.msg

# In another terminal, watch the file
> brew install fswatch
> fswatch -0 ~/.cryptic/alice/cryptic-server_8443/sender.msg | xargs -0 -n1 -I{} /full/path/to/your-script.sh {}
```

**Linux (using inotify-tools):**
```bash
# Start the client with file notification
> ./bin/cryptic -u alice --file-notify sender.msg

# In another terminal, watch the file
> sudo apt install inotify-tools
> while inotifywait -e modify ~/.cryptic/alice/cryptic-server_8443/sender.msg; do /full/path/to/your-script.sh; done
```

**Docker Example:**
```bash
# Mount the cryptic directory and use file notification
> docker run -v ~/.cryptic:/root/.cryptic cryptic --file-notify sender.msg

# On the host, watch the file
> fswatch -0 ~/.cryptic/alice/cryptic-server_8443/sender.msg | xargs -0 -n1 -I{} terminal-notifier -title "Cryptic" -message "Message from $(cat ~/.cryptic/alice/cryptic-server_8443/sender.msg)"
```

**Note:** Both notification methods can be used simultaneously if desired.

Here is another example script for Mac: if your script is quick, handle rapid
successive events (debounce) to avoid duplicate runs.

```bash
#!/bin/bash

debounce_ms=200
last=0
while read -r f; do
  now=$(python3 -c 'import time; print(int(time.time()*1000))')
  if (( now - last > debounce_ms )); then
    /Users/alice/.cryptic/alice/cryptic-server_8443/my_notify.sh "$f"
    last=$now
  fi
done < <(fswatch -0 /Users/alice/.cryptic/alice/cryptic-server_8443/inbox_sender | xargs -0 -n1 -I{} printf '%s\n' {})
```

## The Server

The main functions of the Cryptic Server are to:

1. Relay messages routed between the Clients.
2. Hold uploaded Client (Public) keys.
3. Hold pending (encrypted) messages to be delivered when receiving Client comes online.
4. Handle onboarding of new Clients (via GPG signed CSR's).
5. Issue new certificates (upon requests) to Clients.

Client keys and messages are not stored on disk, hence if the Server goes
down while holding pending messages, they are lost. Only the users (Public)
GPG keys are stored on disk (they are used to verify user Certificate Signing
Requests, CSR's).

The Server can be run either via the `scripts/start-server.sh` script,
or via a tailor made [docker container](docs/DOCKER.md) .

### Setup the server

``` bash
# After cloning and compiling cryptic:
# 1. Create the server certificates
./scripts//generate-mtls-certs.sh
🔐 Generating mTLS Server Certificates for Cryptic...
Enter DNS Subject Alternative Name (SAN) (unless localhost only) - press Enter to skip:
DNS names (comma-separated):
# If you just runs it on localhost (for testing) then just press enter above!
# But if you run it with a proper DNS name, e.g acme.duckdns.org ,then type
# in that DNS name.
...

# 2. Generate GPG key(s) for your admin user(s)
./scripts/bootstrap_gpg.sh
# These GPG keys will be put in the priv/ca/bootstrap directory
# and will be read by the server when starting. They are the trusted
# admin users that can add GPG keys from new users to be onboarded-

# 3. start the server
./scripts/start-server.sh

# 4. For each admin user, run the onboard script to generate the corresponding
# client certificates.
./bin/cryptic --onboard
```


## References

- The [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- The [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- The Messaging Layer Security (MLS) Protocol - [RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)

## License

Mozilla Public License Version 2.0
