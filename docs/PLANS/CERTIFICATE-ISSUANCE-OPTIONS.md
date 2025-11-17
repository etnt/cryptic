# Certificate Issuance Implementation Options

**Date**: 2025-10-31  
**Context**: Phase 3 implementation planning  
**Decision**: Choose certificate issuance approach for Cryptic CA

## Executive Summary

We need to select the best approach for issuing X.509 certificates in the Cryptic CA system. This document analyzes three options:

1. **Erlang/OTP `public_key` module** (native Erlang)
2. **libsodium via `enacl`** (modern crypto library)
3. **myca bash scripts** (current plan)

**Recommendation**: **Use Erlang/OTP `public_key` module** - See [Final Recommendation](#final-recommendation)

---

## Requirements

Our certificate issuance system must:

1. ✅ Parse and validate PKCS#10 CSRs (Certificate Signing Requests)
2. ✅ Generate X.509 certificates from CSRs
3. ✅ Sign certificates with CA private key (RSA or ECDSA)
4. ✅ Manage serial numbers (unique, monotonic)
5. ✅ Set certificate extensions (Key Usage, Extended Key Usage, SAN)
6. ✅ Configure validity periods (7 days default, configurable)
7. ✅ Support PEM encoding/decoding
8. ✅ Integrate seamlessly with Erlang
9. ✅ Support certificate renewal
10. ✅ No external dependencies (preferred)

---

## Option 1: Erlang/OTP `public_key` Module

### Overview

The `public_key` module is part of Erlang/OTP standard library and provides comprehensive X.509 certificate handling.

### Capabilities

**Available Functions** (from module inspection):
```erlang
%% Certificate Signing
pkix_sign(Cert, Key) -> SignedCert

%% Certificate Verification
pkix_verify(Cert, Key) -> boolean()

%% Certificate Encoding/Decoding
pkix_decode_cert(DER, Type) -> Certificate
pkix_encode(Type, Cert, Encoding) -> DER

%% Certificate Operations
pkix_is_issuer(Cert, IssuerCert) -> boolean()
pkix_is_self_signed(Cert) -> boolean()
pkix_subject_id(Cert) -> SubjectId
pkix_issuer_id(Cert, IssuerCert) -> IssuerId

%% Path Validation
pkix_path_validation(Cert, CertChain, Options) -> Result

%% Testing/Generation
pkix_test_data(Config) -> Certs
pkix_test_root_cert(Name, Key) -> Cert
```

### CSR Handling

The `public_key` module supports PKCS#10 CSRs:

```erlang
%% Parse CSR (PEM or DER)
{ok, PemBin} = file:read_file("request.csr"),
[{'CertificationRequest', DER, not_encrypted}] = public_key:pem_decode(PemBin),
CSR = public_key:pkix_decode_cert(DER, plain),

%% Validate CSR signature
public_key:pkix_verify(CSR, PublicKey)
```

### Certificate Generation Example

```erlang
%% Create certificate from CSR
-spec issue_certificate(binary(), term()) -> {ok, binary()} | {error, term()}.
issue_certificate(CSR_PEM, CAKey) ->
    %% Decode CSR
    [{'CertificationRequest', CSRDER, not_encrypted}] = 
        public_key:pem_decode(CSR_PEM),
    
    %% Build certificate structure
    Cert = #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            version = v3,
            serialNumber = generate_serial_number(),
            signature = #'SignatureAlgorithm'{
                algorithm = ?'sha256WithRSAEncryption'
            },
            issuer = get_ca_subject(),
            validity = #'Validity'{
                notBefore = format_time(erlang:system_time(second)),
                notAfter = format_time(erlang:system_time(second) + (7 * 86400))
            },
            subject = extract_subject_from_csr(CSRDER),
            subjectPublicKeyInfo = extract_pubkey_from_csr(CSRDER),
            extensions = build_extensions()
        }
    },
    
    %% Sign certificate
    SignedCert = public_key:pkix_sign(Cert, CAKey),
    
    %% Encode to PEM
    PEM = public_key:pem_encode([
        {'Certificate', SignedCert, not_encrypted}
    ]),
    {ok, PEM}.
```

### Pros

✅ **Native Erlang** - No external dependencies  
✅ **Fully featured** - Complete X.509 implementation  
✅ **Well documented** - OTP documentation and examples  
✅ **Type safe** - Erlang records for certificate structures  
✅ **Battle-tested** - Used in OTP SSL/TLS stack  
✅ **No shell-out** - Pure Erlang, no subprocess overhead  
✅ **Maintained** - Part of OTP, regular updates  
✅ **Performance** - Native code, no IPC overhead  

### Cons

❌ **Verbose API** - Certificate structures are complex  
❌ **Learning curve** - X.509 ASN.1 structures require understanding  
❌ **Documentation gaps** - Some advanced features poorly documented  

### Implementation Complexity

**Estimated effort**: 2-3 days

**Complexity**: Medium
- Certificate structure building: Complex but well-defined
- CSR parsing: Straightforward with `pem_decode`
- Signing: Single function call (`pkix_sign`)
- Extensions: Moderate complexity (ASN.1 encoding)

### Code Example: Complete Flow

```erlang
-module(cryptic_ca_cert).
-export([issue_cert_from_csr/3]).

-include_lib("public_key/include/public_key.hrl").

issue_cert_from_csr(CSR_PEM, CAPrivKey, SerialNum) ->
    %% 1. Decode CSR
    [{'CertificationRequest', CSRDER, not_encrypted}] = 
        public_key:pem_decode(CSR_PEM),
    
    #'CertificationRequest'{
        certificationRequestInfo = CertReqInfo
    } = public_key:der_decode('CertificationRequest', CSRDER),
    
    %% 2. Extract subject and public key from CSR
    #'CertificationRequestInfo'{
        subject = Subject,
        subjectPKInfo = SubjectPKInfo
    } = CertReqInfo,
    
    %% 3. Build certificate
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    ValidityDays = 7,
    
    TBSCert = #'OTPTBSCertificate'{
        version = v3,
        serialNumber = SerialNum,
        signature = #'SignatureAlgorithm'{
            algorithm = ?'sha256WithECDSAEncryption',
            parameters = asn1_NOVALUE
        },
        issuer = {rdnSequence, [
            [#'AttributeTypeAndValue'{
                type = ?'id-at-commonName',
                value = {utf8String, <<"Cryptic CA">>}
            }]
        ]},
        validity = #'Validity'{
            notBefore = {utcTime, format_utc_time(Now)},
            notAfter = {utcTime, format_utc_time(Now + ValidityDays * 86400)}
        },
        subject = Subject,
        subjectPublicKeyInfo = SubjectPKInfo,
        extensions = [
            #'Extension'{
                extnID = ?'id-ce-keyUsage',
                critical = true,
                extnValue = [digitalSignature, keyEncipherment]
            },
            #'Extension'{
                extnID = ?'id-ce-extKeyUsage',
                critical = false,
                extnValue = [?'id-kp-clientAuth']
            }
        ]
    },
    
    Cert = #'OTPCertificate'{
        tbsCertificate = TBSCert,
        signatureAlgorithm = TBSCert#'OTPTBSCertificate'.signature,
        signature = <<>> %% Will be filled by pkix_sign
    },
    
    %% 4. Sign certificate
    SignedCert = public_key:pkix_sign(Cert, CAPrivKey),
    
    %% 5. Encode to PEM
    CertDER = public_key:pkix_encode('OTPCertificate', SignedCert, otp),
    PEM = public_key:pem_encode([{'Certificate', CertDER, not_encrypted}]),
    
    {ok, PEM}.

format_utc_time(Seconds) ->
    {{Y, M, D}, {H, Min, S}} = 
        calendar:gregorian_seconds_to_datetime(Seconds),
    lists:flatten(io_lib:format("~2..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
        [Y rem 100, M, D, H, Min, S])).
```

---

## Option 2: libsodium via `enacl`

### Overview

libsodium is a modern cryptographic library. The `enacl` Erlang NIF provides bindings.

### Capabilities

**Available in libsodium/enacl:**
- ✅ Ed25519 signatures (modern, fast)
- ✅ X25519 key exchange
- ✅ Curve25519 encryption
- ❌ **No X.509 certificate support**
- ❌ **No CSR parsing**
- ❌ **No ASN.1 encoding**

### X.509 Support

**libsodium does NOT support X.509 certificates.**

It provides:
- Modern signature schemes (Ed25519)
- Encryption primitives (XSalsa20, ChaCha20)
- Key derivation (Argon2, HKDF)

But **NOT**:
- Certificate generation
- CSR handling
- X.509 encoding/decoding

### Alternative Approach: Custom Certificate Format

We could create a custom certificate format using libsodium signatures:

```erlang
%% Custom "certificate" (NOT X.509 compatible)
#{
    version => 1,
    serial => 12345,
    subject => <<"gpg:6A2C1F8D...">>,
    public_key => <<Ed25519PubKey:32/binary>>,
    issuer => <<"Cryptic CA">>,
    not_before => 1698765432,
    not_after => 1699370232,
    signature => <<Ed25519Sig:64/binary>>  % CA signs this structure
}
```

**Problem**: This breaks TLS compatibility!
- TLS requires X.509 certificates
- Browser/client validation expects X.509
- OpenSSL/LibreSSL won't recognize custom format

### Pros

✅ **Modern crypto** - Ed25519 is fast and secure  
✅ **Simple API** - Easier than X.509 ASN.1  
✅ **Small code** - Minimal implementation  

### Cons

❌ **No X.509 support** - Cannot generate standard certificates  
❌ **TLS incompatible** - Won't work with mTLS  
❌ **Custom format** - Requires custom client validation  
❌ **Not suitable** - Doesn't meet our requirements  

### Verdict

**❌ Not viable** - libsodium doesn't support X.509 certificates, which are required for TLS client authentication. We would need X.509 for mTLS compatibility.

---

## Option 3: myca Bash Scripts

### Overview

`myca` is a collection of bash scripts for CA operations, wrapping OpenSSL commands.

### Capabilities

**Features:**
- ✅ CSR parsing (via OpenSSL)
- ✅ Certificate generation (via OpenSSL)
- ✅ Serial number management (file-based)
- ✅ Certificate policies
- ✅ X.509 extensions

### Architecture

```
Erlang → Shell command → myca script → OpenSSL → Result → Parse → Erlang
```

### Example Usage

```erlang
%% Issue certificate via myca
issue_cert(CSR_File) ->
    Cmd = "myca sign-csr --csr " ++ CSR_File ++ " --days 7",
    Output = os:cmd(Cmd),
    parse_myca_output(Output).
```

### Pros

✅ **Working solution** - myca is already implemented  
✅ **Full featured** - Handles all X.509 operations  
✅ **OpenSSL backend** - Battle-tested crypto  

### Cons

❌ **External dependency** - Requires myca scripts + OpenSSL  
❌ **Shell overhead** - Process spawning for each operation  
❌ **Error handling** - Parsing shell output is fragile  
❌ **Security concerns** - Command injection risks  
❌ **Deployment complexity** - Must bundle bash scripts  
❌ **Testing difficulty** - Mocking shell commands is complex  
❌ **Performance** - IPC overhead for each operation  
❌ **Not idiomatic** - Shell-out from Erlang is antipattern  

### Code Example

```erlang
-module(cryptic_ca_myca).

issue_certificate(CSR_PEM, SerialNum) ->
    %% Write CSR to temp file
    CSRFile = "/tmp/csr-" ++ integer_to_list(SerialNum) ++ ".pem",
    ok = file:write_file(CSRFile, CSR_PEM),
    
    %% Call myca script
    Cmd = io_lib:format("myca sign-csr --csr ~s --days 7 --serial ~B",
                        [CSRFile, SerialNum]),
    
    case os:cmd(Cmd) of
        "ERROR:" ++ ErrorMsg ->
            {error, {myca_error, ErrorMsg}};
        Output ->
            %% Parse output to extract PEM
            parse_cert_from_output(Output)
    end.
```

### Implementation Complexity

**Estimated effort**: 1-2 days (if myca already configured)

**Complexity**: Low (if everything works), High (if debugging issues)
- Integration: Simple shell-out
- Error handling: Complex (parse stderr/stdout)
- Testing: Difficult (mock filesystem + shell)

---

## Comparison Matrix

| Feature | public_key | libsodium | myca |
|---------|-----------|-----------|------|
| **X.509 Support** | ✅ Full | ❌ None | ✅ Full |
| **CSR Parsing** | ✅ Native | ❌ No | ✅ Via OpenSSL |
| **No External Deps** | ✅ Yes | ⚠️ NIF | ❌ Bash+OpenSSL |
| **TLS Compatible** | ✅ Yes | ❌ No | ✅ Yes |
| **Performance** | ✅ Fast | ✅ Fast | ❌ Slow (IPC) |
| **Error Handling** | ✅ Type-safe | ✅ Type-safe | ❌ String parsing |
| **Testing** | ✅ Easy | ✅ Easy | ❌ Hard |
| **Deployment** | ✅ Built-in | ⚠️ NIF binary | ❌ Scripts+bins |
| **Maintenance** | ✅ OTP team | ⚠️ Third-party | ❌ Custom scripts |
| **Learning Curve** | ⚠️ Medium | ✅ Low | ✅ Low |
| **Implementation Time** | 2-3 days | N/A | 1-2 days |

---

## Final Recommendation

### ⚠️ **REVISED: Hybrid Approach - Keep myca for CA/Server, Use public_key for Client Certs**

**Critical Discovery**: The `public_key:pkix_test_root_cert/2` function is explicitly marked **for testing only** and states:

> "Note that the generated certificates and keys does not provide a formally correct PKIX-trust-chain and they cannot be used to achieve real security. This function is provided for testing purposes only."

This changes our analysis significantly.

### Updated Strategy

**Use myca for**:
- ✅ CA root certificate generation (one-time, critical security)
- ✅ Server certificate generation (one-time, critical security)
- ✅ Initial CA setup and bootstrap

**Use Erlang public_key for**:
- ✅ Client certificate issuance from CSRs (high volume, programmatic)
- ✅ Certificate renewal (automated, frequent)
- ✅ CSR parsing and validation

**Rationale:**

1. **CA/Server Certificates (myca)**:
   - Created once during deployment/bootstrap
   - Must be production-grade and PKIX-compliant
   - myca uses OpenSSL which is battle-tested for CA operations
   - Low frequency operation (setup/renewal every 1-5 years)
   - Shell overhead is acceptable for rare operations

2. **Client Certificates (public_key)**:
   - High volume (every user registration, renewal every 7 days)
   - Erlang's `pkix_sign/2` **can** create production certificates
   - The limitation is only on the **test helper** `pkix_test_root_cert/2`
   - Building certificates manually with ASN.1 records is production-safe
   - Performance matters here (no shell overhead)
   - Type-safe, testable, maintainable

### Why This Works

The key insight is that **Erlang public_key CAN create production certificates**, but:
- ❌ Don't use `pkix_test_root_cert/2` (test helper)
- ✅ DO use `pkix_sign/2` with manually constructed certificate records
- ✅ DO use proper ASN.1 structures (`OTPCertificate`, `OTPTBSCertificate`)

**Production-Safe Erlang Certificate Generation**:
```erlang
%% THIS IS PRODUCTION-SAFE (manual construction + pkix_sign)
TBSCert = #'OTPTBSCertificate'{
    version = v3,
    serialNumber = generate_serial_number(),
    signature = #'SignatureAlgorithm'{
        algorithm = ?'sha256WithECDSAEncryption',
        parameters = asn1_NOVALUE
    },
    issuer = CASubject,  % From CA certificate
    validity = #'Validity'{
        notBefore = {utcTime, format_time(Now)},
        notAfter = {utcTime, format_time(Now + 7*86400)}
    },
    subject = extract_subject_from_csr(CSR),
    subjectPublicKeyInfo = extract_pubkey_from_csr(CSR),
    extensions = build_production_extensions()  % Proper extensions
},

Cert = #'OTPCertificate'{
    tbsCertificate = TBSCert,
    signatureAlgorithm = TBSCert#'OTPTBSCertificate'.signature,
    signature = <<>>
},

%% This creates a PRODUCTION certificate
SignedCert = public_key:pkix_sign(Cert, CAPrivateKey).
```

**NOT Production-Safe** (test helper):
```erlang
%% DON'T USE THIS IN PRODUCTION
{Cert, PrivKey} = public_key:pkix_test_root_cert("Test CA", Opts).
```

### Implementation Plan Updated

**Phase 3: Certificate Issuance**

1. **Keep myca for bootstrap** (0.5 days)
   - Generate CA root certificate (one-time)
   - Generate server certificate (one-time)  
   - Document myca commands for initial setup

2. **Implement client cert issuance in Erlang** (2.5 days)
   - Load CA certificate and private key (from myca-generated files)
   - Parse CSRs using `public_key:pem_decode/1`
   - Build certificate structures manually (ASN.1 records)
   - Sign with `public_key:pkix_sign/2`
   - Encode to PEM with `public_key:pem_encode/1`

3. **Testing** (1 day)
   - Verify certificates work with OpenSSL
   - Verify mTLS connections work
   - Test certificate chain validation

**Total time**: 4 days (slightly more than pure Erlang, but safer)

### Division of Responsibilities

```
┌─────────────────────────────────────────────────────┐
│                  CA Infrastructure                   │
├─────────────────────────────────────────────────────┤
│                                                      │
│  myca (OpenSSL)                                      │
│  ===============                                     │
│  • CA root cert generation          (one-time)       │
│  • CA private key generation        (one-time)       │
│  • Server cert generation           (yearly)         │
│  • CA certificate renewal           (5 years)        │
│                                                      │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Erlang public_key                                   │
│  ==================                                  │
│  • Client cert issuance from CSR    (high volume)    │
│  • Client cert renewal              (every 7 days)   │
│  • CSR validation                   (per request)    │
│  • Certificate encoding/decoding    (frequent)       │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### Pros of Hybrid Approach

✅ **Best of both worlds**:
   - myca handles critical, rare CA operations (proven, trusted)
   - Erlang handles high-volume client operations (fast, integrated)

✅ **Security**: CA infrastructure uses battle-tested OpenSSL via myca

✅ **Performance**: Client cert issuance has no shell overhead

✅ **Maintainability**: Clear separation of concerns

✅ **Production-ready**: No reliance on test helpers

### Cons of Hybrid Approach

⚠️ **Two systems**: Must maintain both myca and Erlang certificate code

⚠️ **Bootstrap dependency**: Still need myca installed for initial setup

✅ **Acceptable trade-off**: Deployment-time dependency is fine, runtime dependency is not

### What This Means for Deployment

**One-time setup** (using myca):
```bash
# Generate CA
cd CA
make init-ca

# Generate server certificate
make server-cert SERVER=relay.cryptic.example.org
```

**Runtime operations** (using Erlang):
```erlang
% User requests certificate
cryptic_ca_cert:issue_from_csr(CSR, GPG_FP) ->
    % Pure Erlang, no shell-out
    % Uses CA key loaded at startup
    % Fast, type-safe, production-grade
```

### Migration Path

If we ever want to remove myca dependency:
1. Implement CA generation in Erlang (manually build CA cert)
2. One-time migration of existing CA
3. Remove myca from deployment

But for Phase 3, keeping myca for CA/server and using Erlang for clients is the pragmatic choice.

---

## Comparison Matrix (Updated)

| Feature | Hybrid (Recommended) | Pure public_key | Pure myca |
|---------|---------------------|-----------------|-----------|
| **CA Generation** | myca (OpenSSL) | Manual ASN.1 ⚠️ | myca ✅ |
| **Server Cert** | myca (OpenSSL) | Manual ASN.1 ⚠️ | myca ✅ |
| **Client Cert** | Erlang ✅ | Erlang ✅ | myca ❌ (slow) |
| **CSR Parsing** | Erlang ✅ | Erlang ✅ | OpenSSL via myca |
| **Performance** | ✅ Fast (runtime) | ✅ Fast | ❌ Slow (shell) |
| **Security** | ✅ Proven (CA) | ⚠️ Manual (CA) | ✅ Proven |
| **Testing** | ⚠️ Two systems | ✅ Pure Erlang | ❌ Hard |
| **Deployment** | ⚠️ myca needed | ✅ OTP only | ❌ myca needed |
| **Maintenance** | ⚠️ Two systems | ✅ One system | ❌ Shell-out |

⚠️ = Manual ASN.1 for CA certs is **possible** but more work than myca, and myca is battle-tested

---

## Updated Recommendation

### ✅ **Use Hybrid Approach for Phase 3**

**Short term (Phase 3)**:
1. Use myca for CA and server certificate generation (bootstrap)
2. Use Erlang public_key for client certificate issuance (runtime)
3. Document both approaches clearly

**Long term (future)**:
- Consider replacing myca with pure Erlang if team gains ASN.1 expertise
- For now, hybrid approach is pragmatic and production-safe

**Key Decision**: 
- Don't use `pkix_test_root_cert/2` for anything production
- DO use `pkix_sign/2` with manual certificate structures for client certs
- Keep myca for CA/server bootstrap (proven, low-risk)

---

**Decision Date**: 2025-10-31 (Revised)  
**Status**: ✅ Recommended - Hybrid approach (myca for CA, Erlang for clients)  
**Next Steps**: Update Phase 3 tasks to reflect hybrid approach

---

## Code Structure

```erlang
src/
├── cryptic_ca_cert.erl           % Certificate operations (public_key wrapper)
│   ├── issue_certificate/3      % Main entry point
│   ├── parse_csr/1              % Parse CSR PEM
│   ├── validate_csr/1           % Verify CSR signature
│   ├── build_certificate/3     % Create OTPCertificate record
│   ├── build_extensions/1      % Create X.509 extensions
│   └── sign_certificate/2      % Sign with CA key
│
├── cryptic_ca_serial.erl         % Serial number management
│   ├── next_serial/0            % Get next serial number
│   └── init_storage/0           % Initialize counter
│
└── cryptic_ca_store.erl          % Storage (already exists)
    └── store_certificate/2       % Persist issued cert
```

---

## Migration from myca (if needed)

If myca is already in use, migration is straightforward:

1. **Generate CA key pair** (one-time):
```erlang
%% Generate ECDSA key (if not exists)
PrivKey = public_key:generate_key({namedCurve, secp256r1}),
file:write_file("ca-key.pem", 
    public_key:pem_encode([{'ECPrivateKey', PrivKey, not_encrypted}])).
```

2. **Replace myca calls** with `cryptic_ca_cert:issue_certificate/3`

3. **Test compatibility**: Verify issued certificates work with existing TLS stack

---

## Security Considerations

### CA Private Key Protection

```erlang
%% Load CA key (keep in memory, don't write to disk frequently)
{ok, KeyPEM} = file:read_file("ca-key.pem"),
[{'ECPrivateKey', KeyDER, not_encrypted}] = public_key:pem_decode(KeyPEM),
CAPrivKey = public_key:der_decode('ECPrivateKey', KeyDER),

%% Store in protected ETS table
ets:new(ca_keys, [set, protected, named_table]),
ets:insert(ca_keys, {ca_private_key, CAPrivKey}).
```

### Serial Number Uniqueness

```erlang
%% Atomic serial number generation (ETS counter)
-spec next_serial() -> integer().
next_serial() ->
    ets:update_counter(ca_serial, counter, 1, {counter, 1}).
```

---

## References

- [Erlang public_key Module](https://www.erlang.org/doc/apps/public_key/public_key.html)
- [X.509 RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)
- [PKCS#10 RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986)
- [OTP SSL/TLS Documentation](https://www.erlang.org/doc/apps/ssl/ssl.html)

---

**Decision Date**: 2025-10-31  
**Status**: ✅ Recommended - Proceed with Erlang/OTP `public_key`  
**Next Steps**: Update Phase 3 implementation plan in IMPLEMENTATION-PLAN-GPG-ONBOARDING.md
