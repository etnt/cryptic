# GPG Bootstrap Registration

This document explains how to bootstrap GPG registration using the
filesystem-based approach.

## Use Cases

The bootstrap mechanism serves two primary purposes:

### 1. Initial System Setup

When first deploying the system, you need at least one "root" or "admin" user
who can create invites for other users. This creates a chicken-and-egg problem:

- New users need invites to register
- But who creates the first invite?

**Solution**: Bootstrap the initial admin user(s) via the filesystem.
These users can then create invites for subsequent users, establishing
the chain of trust.

### 2. Legacy Certificate Migration

For users with existing client certificates that don't have GPG fingerprint
information embedded in the Subject Alternative Name (SAN) extension.
In older versions, certificates were issued without this information,
preventing automatic authentication.

## How It Works

Instead of exposing a network endpoint for bootstrapping (which would be a
security risk), the system uses a filesystem-based approach:

1. Users export their GPG public key to a designated directory
2. The server loads these keys on startup
3. GPG fingerprints are registered in the CA database
4. Users can then connect normally with their existing certificates

## How to Bootstrap a User

### Step 1: Export GPG Public Key

Use the provided script to export a user's GPG public key:

```bash
./scripts/bootstrap_gpg.sh admin
```

This will:
- Verify the GPG key exists for `admin@cryptic.local`
- Export the armored public key to `_build/default/lib/cryptic/priv/ca/bootstrap/admin.gpg`
- Display instructions for applying the change

### Step 2: Restart Server or Reload

The server automatically loads bootstrap registrations on startup. If the server
is already running, you can reload without restart:

```erlang
%% From the Erlang shell:
{ok, DbRef} = cryptic_ca_init:get_db_ref().
cryptic_ca_bootstrap:load_bootstrap_registrations(DbRef).
```

### Step 3: Verify Registration

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

## Bootstrap File Format

Bootstrap files are stored in:
```
_build/default/lib/cryptic/priv/ca/bootstrap/
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

You can bootstrap multiple users at once:

```bash
for user in alice bob charlie; do
    ./scripts/bootstrap_gpg.sh $user
done
```

Then restart the server or reload bootstrap registrations.

## Initial System Setup Example

When deploying a new Cryptic server from scratch (day zero), you need to:
1. Create the admin's GPG key
2. Generate the admin's client certificate
3. Bootstrap the admin's GPG registration
4. Start the server

### Complete Day Zero Setup

```bash
# 1. Create GPG key for admin user
gpg --batch --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Name-Real: Admin
Name-Email: admin@cryptic.local
Expire-Date: 0
%commit
EOF

# 2. Generate admin's client certificate
# First, ensure CA certificates exist (run once per deployment)
cd CA
make clean  # Clean old certs if they exist
make all    # Generate CA root certificate
cd ..

# Generate and install admin's client certificate
./scripts/bootstrap_cert.sh admin localhost 8443

# This creates certificates in:
#   $HOME/.cryptic/admin/localhost_8443/certificates/admin.crt
#   $HOME/.cryptic/admin/localhost_8443/certificates/admin.key
#   $HOME/.cryptic/admin/localhost_8443/certificates/admin.pem
#   $HOME/.cryptic/admin/localhost_8443/certificates/ca.crt

# 3. Bootstrap admin's GPG registration
cd ..
./scripts/bootstrap_gpg.sh admin

# 4. Start the server (bootstrap happens automatically)
./scripts/start-server.sh

# 5. Connect as admin and verify you can create invites
./scripts/cryptic_console --username admin \
  --cert ~/.cryptic/admin/localhost/certificates/admin.crt \
  --key ~/.cryptic/admin/localhost/certificates/admin.key

# In the console:
# > invite create --expiry 24 --note "Test invite"
```

**Once the admin is bootstrapped**, the normal invite-based onboarding flow
takes over:

1. Admin creates invite: `invite create --expiry 24 --note "Invite for Alice"`
2. Alice uses invite to register via external script or REST endpoint
3. Alice's certificate will include GPG info in SAN extension (no bootstrap needed)
4. Alice can create invites for others
5. Chain of trust is established

**Key Point**: Bootstrap is only needed for the initial admin user(s) who seed
the system. All subsequent users should use the invite-based registration flow,
which embeds GPG fingerprints in their certificates automatically.

## Troubleshooting

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
mkdir -p _build/default/lib/cryptic/priv/ca/bootstrap
chmod 755 _build/default/lib/cryptic/priv/ca/bootstrap
```

## Migration Path

Once all users have been migrated to certificates with embedded GPG fingerprints:

1. New certificates (issued after this feature) will have GPG info in SAN
2. Users with new certificates don't need bootstrapping
3. Bootstrap files can be cleaned up
4. The bootstrap mechanism can be deprecated in a future version
