# GPG Bootstrap Registration

This document explains how to bootstrap GPG registration using the
filesystem-based approach.

## Use Cases

The bootstrap mechanism is used for:

### 1. Initial System Setup

When first deploying the system, you need to register the first user(s) who
can then authenticate and use the system.

**Solution**: Bootstrap the initial user(s) via the filesystem. These users
can then connect and use the system normally.

## How It Works

Instead of exposing a network endpoint for bootstrapping (which would be a
security risk), the system uses a filesystem-based approach:

1. Users export their GPG public key to a designated directory
2. The server loads these keys on startup
3. GPG fingerprints are registered in the CA database
4. Users can then request certificates (CSR) via the Cryptic onboarding process

## How to Bootstrap a User

### Step 1: Export GPG Public Key

Use the provided script to export a user's GPG public key:

```bash
./scripts/bootstrap_gpg.sh admin
```

This will:
- Verify the GPG key exists for `admin@cryptic.local`
- Export the armored public key to `priv/ca/bootstrap/admin.gpg`

### Step 2: (Re-)Start Server or Reload

The server automatically loads bootstrap registrations on startup.
If the server is already running, you can reload without restart:

```erlang
%% From the Erlang shell:
{ok, DbRef} = cryptic_ca_init:get_db_ref().
cryptic_ca_bootstrap:load_bootstrap_registrations(DbRef).
```

### Step 3: Request certificates

Request new certificates via the `./bin/cryptic --onboard` script.

1. Choose the `Export GPG public key for admin registration` action.
2. Choose the `Request a TLS certificate from server` action.

Veryfy that you have got certificates, for example:

```
❯ tree ~/.cryptic
.../.cryptic
├── admin
│   ├── localhost_8443
│   │   ├── certificates
│   │   │   ├── admin.crt
│   │   │   ├── admin.csr
│   │   │   ├── admin.key
│   │   │   └── ca.crt
```

### Step 4: Log on via the cryptic_console

Example:

```
./script/cryptic_console -u admin --enable-db
```

### Step 5: Request new certificate when expired

The certificate issued is only valid for a short time. The Cryptic client
should automatically renew them before they expire. But if you haven't been
running the client for a while and the certificate has expired, then you can
just repeat **Step 3** above to request a new certificate. 


## Bootstrap File Format

Bootstrap files are stored in:
```
priv/ca/bootstrap/
```

Each file:
- Has a `.gpg` extension (e.g., `alice.gpg`, `bob.gpg`)
- Contains an ASCII-armored GPG public key
- Is automatically processed on server startup
- Once registered, the file can be removed (but doesn't need to be)

## Manual Bootstrap

If you need to manually create a bootstrap file:

```bash
# Export GPG public key
gpg --armor --export alice@cryptic.local > \
  _build/default/lib/cryptic/priv/ca/bootstrap/alice.gpg
```

## Security Notes

1. **No Network Exposure**: Bootstrap only works via filesystem access, not network
2. **Requires Server Access**: Only users with filesystem access to the server can bootstrap
3. **Audit Trail**: All bootstrap registrations are logged in the audit_log table
4. **Status Tracking**: Bootstrapped identities are marked with `status = "verified_bootstrap"`

## Bootstrapping Multiple Users

You can bootstrap multiple users at once by running the script for each user:

```bash
./scripts/bootstrap_gpg.sh alice
./scripts/bootstrap_gpg.sh bob
./scripts/bootstrap_gpg.sh charlie
```

Then restart the server or reload bootstrap registrations.

**Key Points**:
- Bootstrap is needed for the first user(s) to register their GPG identity
- After bootstrapping, use the `./bin/cryptic --onboard` script to request a certificate
- The onboarding script handles GPG key creation, CSR generation, and signing


## Troubleshooting

### Verify Registration via server shell

Check that the GPG identity was registered:

```erlang
%% From the Erlang shell:
{ok, DbRef} = cryptic_ca_init:get_db_ref().
cryptic_ca_store:list_gpg_identities(DbRef).
```

Or use the database inspection tool:

```erlang
cryptic_ca_store:inspect_db().
```

### GPG key not found

If you get "No GPG key found for user@cryptic.local":

```bash
# Create a GPG key for the user
gpg --batch --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Name-Real: Alice
Name-Email: alice@cryptic.local
Expire-Date: 0
%commit
EOF
```

### Already registered

If a GPG fingerprint is already registered, the bootstrap process will skip it
and log a debug message. This is normal and safe.

### Permission denied

Ensure the bootstrap directory is writable:

```bash
mkdir -p priv/ca/bootstrap
chmod 755 priv/ca/bootstrap
```

