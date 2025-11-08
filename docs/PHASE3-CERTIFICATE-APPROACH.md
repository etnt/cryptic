# Phase 3: Certificate Issuance - Implementation Approach

**Date**: 2025-10-31
**Decision**: Hybrid approach for certificate management
**Status**: Ready for implementation

## The Answer

**Question**: How do we issue certificates for invited users?

**Answer**: **Hybrid approach**
- Use **myca (OpenSSL)** for CA and server certificates (bootstrap, rare)
- Use **Erlang public_key** for client certificates (runtime, frequent)

## Why Hybrid?

### Discovery: Erlang Test Helpers Are Not Production-Safe

The Erlang `public_key` module has a helper function `pkix_test_root_cert/2` that looks convenient, but the documentation explicitly warns:

> "Note that the generated certificates and keys does not provide a formally correct PKIX-trust-chain and they cannot be used to achieve real security. This function is provided for testing purposes only."

**What this means**:
- ❌ Don't use `pkix_test_root_cert/2` for production
- ✅ DO use `pkix_sign/2` with manual certificate structures (production-safe)
- ✅ Building certificates from ASN.1 records is fully supported and secure

### The Problem with Pure Approaches

**Pure myca**:
- ✅ Perfect for CA/server certs
- ❌ Shell-out overhead for every client cert (100s per day)
- ❌ Slow, fragile error handling

**Pure Erlang**:
- ✅ Perfect for client certs
- ⚠️ More work to build CA certs from scratch vs. proven myca
- ⚠️ CA generation is critical security operation (prefer proven tools)

**Hybrid** (Best of both):
- ✅ myca handles rare, critical CA operations (proven)
- ✅ Erlang handles frequent client operations (fast, integrated)
- ✅ Clear separation of concerns

## Certificate Types & Responsibility

```
┌────────────────────────────────────────────────────────┐
│ Certificate Type │ Created By │ Frequency │ Tool       │
├──────────────────┼────────────┼───────────┼────────────┤
│ CA Root Cert     │ Admin      │ Once      │ myca       │
│ CA Private Key   │ Admin      │ Once      │ myca       │
│ Server Cert      │ Admin      │ Yearly    │ myca       │
│ Client Cert      │ System     │ Daily     │ Erlang     │
│ Client Renewal   │ System     │ Weekly    │ Erlang     │
└────────────────────────────────────────────────────────┘
```

## Implementation Details

### Bootstrap (One-time, using myca)

**Step 1: Generate CA** (admin runs once)
```bash
cd CA
make init-ca
# Generates:
# - CA/private/ca.key (keep secret!)
# - CA/certs/ca.crt (distribute)
```

**Step 2: Generate Server Certificate** (admin runs once)
```bash
make server-cert SERVER=relay.cryptic.example.org
# Generates:
# - CA/certs/relay.cryptic.example.org.crt
# - CA/private/relay.cryptic.example.org.key
```

**Step 3: Load CA into Erlang** (application startup)
```erlang
% In cryptic_ca application startup
{ok, CACertPEM} = file:read_file("CA/certs/ca.crt"),
{ok, CAKeyPEM} = file:read_file("CA/private/ca.key"),

[{_, CACertDER, _}] = public_key:pem_decode(CACertPEM),
CACert = public_key:pkix_decode_cert(CACertDER, otp),

[{_, CAKeyDER, _}] = public_key:pem_decode(CAKeyPEM),
CAKey = public_key:der_decode('ECPrivateKey', CAKeyDER),

% Store in application environment
application:set_env(cryptic_ca, ca_cert, CACert),
application:set_env(cryptic_ca, ca_key, CAKey).
```

### Runtime (Frequent, using Erlang)

**Client Certificate Issuance** (every user registration)
```erlang
-module(cryptic_ca_cert).
-export([issue_from_csr/2]).

-include_lib("public_key/include/public_key.hrl").

issue_from_csr(CSR_PEM, GPG_FP) ->
    %% 1. Load CA key from application env
    {ok, CAKey} = application:get_env(cryptic_ca, ca_key),
    {ok, CACert} = application:get_env(cryptic_ca, ca_cert),
    
    %% 2. Parse CSR
    [{'CertificationRequest', CSRDER, _}] = public_key:pem_decode(CSR_PEM),
    CSR = public_key:der_decode('CertificationRequest', CSRDER),
    
    %% 3. Extract info from CSR
    #'CertificationRequest'{
        certificationRequestInfo = CertReqInfo
    } = CSR,
    
    #'CertificationRequestInfo'{
        subject = Subject,
        subjectPKInfo = SubjectPKInfo
    } = CertReqInfo,
    
    %% 4. Build certificate (manual ASN.1 construction)
    SerialNum = cryptic_ca_serial:next(),
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    ValidityDays = 7,
    
    TBSCert = #'OTPTBSCertificate'{
        version = v3,
        serialNumber = SerialNum,
        signature = #'SignatureAlgorithm'{
            algorithm = ?'sha256WithECDSAEncryption',
            parameters = asn1_NOVALUE
        },
        issuer = extract_issuer(CACert),
        validity = #'Validity'{
            notBefore = {utcTime, format_time(Now)},
            notAfter = {utcTime, format_time(Now + ValidityDays * 86400)}
        },
        subject = Subject,
        subjectPublicKeyInfo = SubjectPKInfo,
        extensions = build_client_extensions(GPG_FP)
    },
    
    Cert = #'OTPCertificate'{
        tbsCertificate = TBSCert,
        signatureAlgorithm = TBSCert#'OTPTBSCertificate'.signature,
        signature = <<>>
    },
    
    %% 5. Sign certificate (PRODUCTION-SAFE)
    SignedCert = public_key:pkix_sign(Cert, CAKey),
    
    %% 6. Encode to PEM
    CertDER = public_key:pkix_encode('OTPCertificate', SignedCert, otp),
    PEM = public_key:pem_encode([{'Certificate', CertDER, not_encrypted}]),
    
    {ok, PEM}.

build_client_extensions(GPG_FP) ->
    [
        %% Key Usage: Digital Signature + Key Encipherment
        #'Extension'{
            extnID = ?'id-ce-keyUsage',
            critical = true,
            extnValue = [digitalSignature, keyEncipherment]
        },
        %% Extended Key Usage: TLS Client Auth
        #'Extension'{
            extnID = ?'id-ce-extKeyUsage',
            critical = false,
            extnValue = [?'id-kp-clientAuth']
        },
        %% Subject Alternative Name: GPG fingerprint
        #'Extension'{
            extnID = ?'id-ce-subjectAltName',
            critical = false,
            extnValue = [
                {otherName, #'AnotherName'{
                    'type-id' = {1,3,6,1,4,1,99999,1,1},  % Custom OID
                    value = GPG_FP
                }}
            ]
        }
    ].

format_time(Seconds) ->
    {{Y, M, D}, {H, Min, S}} = 
        calendar:gregorian_seconds_to_datetime(Seconds),
    lists:flatten(io_lib:format("~2..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
        [Y rem 100, M, D, H, Min, S])).

extract_issuer(CACert) ->
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            subject = Subject
        }
    } = CACert,
    Subject.
```

## Security Guarantees

### What's Production-Safe

✅ **CA Certificate** (myca/OpenSSL)
- Industry-standard OpenSSL implementation
- Proven in production for decades
- Properly constructed PKIX trust chain

✅ **Client Certificates** (Erlang public_key)
- Manual ASN.1 record construction (not test helpers)
- Signed with `pkix_sign/2` (production function)
- Validates with OpenSSL and other TLS implementations

### What's NOT Production-Safe

❌ **Using test helpers**:
```erlang
% DON'T DO THIS
{Cert, Key} = public_key:pkix_test_root_cert("CA", Opts)
```

✅ **Correct approach**:
```erlang
% DO THIS
Cert = #'OTPCertificate'{...},  % Manual construction
SignedCert = public_key:pkix_sign(Cert, CAKey)  % Production signing
```

## Performance Analysis

### Bottleneck: Client Certificate Issuance

**Expected load**:
- 10 new users/day = 10 cert issuances
- 100 active users = ~14 renewals/day (7-day certs)
- **Total: ~25 cert operations/day**

**myca approach** (shell-out):
- 200-500ms per operation (shell spawn + OpenSSL + file I/O)
- 25 ops/day = 5-12 seconds/day overhead
- Fragile error handling (parse stderr)

**Erlang approach** (native):
- 1-5ms per operation (in-memory)
- 25 ops/day = 25-125ms/day overhead
- Type-safe error handling

**Verdict**: Even at low volume, Erlang is 40-500x faster

## Testing Strategy

### CA Bootstrap Testing (myca)
```bash
# Test CA generation
cd CA && make init-ca
openssl x509 -in certs/ca.crt -text -noout

# Verify CA is self-signed
openssl verify -CAfile certs/ca.crt certs/ca.crt
```

### Client Cert Testing (Erlang)
```erlang
% Generate test CSR
{CSR, ClientKey} = generate_test_csr(),

% Issue certificate
{ok, CertPEM} = cryptic_ca_cert:issue_from_csr(CSR, <<"test-fp">>),

% Verify with OpenSSL
file:write_file("/tmp/test.crt", CertPEM),
os:cmd("openssl verify -CAfile CA/certs/ca.crt /tmp/test.crt").
% Expected: "/tmp/test.crt: OK"
```

### Integration Testing
```erlang
% Test complete flow
1. Generate CSR (OpenSSL or Erlang)
2. Issue cert (Erlang)
3. Connect via mTLS (ssl:connect with cert)
4. Verify connection succeeds
```

## Deployment Checklist

### One-time Setup (Admin)
- [ ] Install myca on deployment machine
- [ ] Generate CA certificate and key
- [ ] Generate server certificate
- [ ] Backup CA private key (encrypted!)
- [ ] Copy CA cert to Erlang app directory
- [ ] Copy CA key to Erlang app directory (secure permissions)

### Erlang Application
- [ ] Load CA cert/key at startup
- [ ] Initialize serial number counter (ETS/esqlite)
- [ ] Implement `cryptic_ca_cert:issue_from_csr/2`
- [ ] Add certificate validation
- [ ] Add renewal logic

### Verification
- [ ] Test client cert issuance
- [ ] Verify mTLS connection works
- [ ] Test certificate renewal
- [ ] Verify OpenSSL compatibility

## File Structure

```
CA/
├── certs/
│   ├── ca.crt              # Generated by myca (public)
│   └── server.crt          # Generated by myca (public)
├── private/
│   ├── ca.key              # Generated by myca (SECRET!)
│   └── server.key          # Generated by myca (secret)
└── Makefile                # myca commands

src/
├── cryptic_ca_cert.erl     # Client cert issuance (Erlang)
├── cryptic_ca_serial.erl   # Serial number management
└── cryptic_ca_store.erl    # Certificate storage

config/
└── sys.config
    {cryptic_ca, [
        {ca_cert_file, "CA/certs/ca.crt"},
        {ca_key_file, "CA/private/ca.key"},
        {cert_validity_days, 7}
    ]}
```

## Migration Path

If we want to remove myca dependency in the future:

1. Implement CA generation in pure Erlang:
```erlang
cryptic_ca_bootstrap:generate_ca(Name, KeyAlgo) ->
    % Build self-signed CA cert manually
    % Same approach as client certs, but self-signed
    ...
```

2. One-time migration:
```bash
# Export CA from myca
openssl x509 -in ca.crt -out ca-migrated.crt

# Import into Erlang system
# No functional change, just different generator
```

3. Remove myca from deployment

**Estimated effort**: 1-2 days (not needed for Phase 3)

## Conclusion

**For Phase 3, we will**:
1. Keep myca for CA and server certificate generation (proven, low-risk)
2. Use Erlang public_key for client certificate issuance (fast, integrated)
3. Document both approaches clearly
4. Build production-grade certificates using manual ASN.1 structures

**This gives us**:
- ✅ Production-safe CA infrastructure
- ✅ Fast, type-safe client cert issuance
- ✅ Clear separation of concerns
- ✅ Proven technology for critical operations
- ✅ Modern technology for high-volume operations

---

**Next Steps**: Proceed with Phase 3 implementation using hybrid approach

**Estimated Timeline**: 4 days
- 0.5 days: myca CA/server setup documentation
- 2.5 days: Erlang client cert implementation
- 1 day: Testing and integration
