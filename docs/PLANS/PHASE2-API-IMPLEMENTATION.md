# Phase 2: API Implementation - Progress Report

**Date**: October 29, 2025  
**Status**: Core Implementation Complete, Routing Setup Pending  
**Branch**: onboarding

## Summary

Phase 2 implementation has successfully created the core API handlers for both WebSocket (trusted clients) and REST (public) operations. The handlers are implemented, documented, and compiling successfully.

## Completed Work

### 1. WebSocket Handler (cryptic_ca_ws_handler.erl)

**Purpose**: Handle invite operations from authenticated cryptic_console clients

**Implemented Commands**:
- ✅ `invite_create` - Create new invite tokens with expiry and metadata
- ✅ `invite_list` - List all invites created by the authenticated user
- ✅ `invite_revoke` - Revoke unused invite tokens
- ✅ `gpg_register_bootstrap` - Register GPG key for existing mTLS users

**Features**:
- JSON message protocol using jsx
- State management with GPG fingerprint tracking
- Comprehensive error handling and logging
- Authentication state tracking

**Code Statistics**:
- ~400 lines of code
- 4 command handlers
- Full EDoc documentation

### 2. REST Handler (cryptic_ca_rest_handler.erl)

**Purpose**: Handle public certificate authority operations

**Implemented Endpoints**:
- ✅ `POST /ca/v1/register-gpg` - Register new users with invite tokens
- ✅ `POST /ca/v1/csr` - Request certificates (placeholder for Phase 3)
- ✅ `GET /ca/v1/status/:fingerprint` - Check registration status

**Features**:
- Cowboy REST callback interface
- GPG signature verification for CSR requests
- Invite validation and consumption
- Identity status checking
- Content negotiation (JSON)
- Comprehensive error responses

**Code Statistics**:
- ~400 lines of code
- 3 REST endpoints
- Full EDoc documentation

### 3. Test Infrastructure

**Created Test Modules**:
- `cryptic_ca_ws_handler_tests.erl` - WebSocket handler tests
- `cryptic_ca_rest_handler_tests.erl` - REST handler tests

**Note**: Full integration tests require Cowboy server setup and will be implemented in Phase 6.

## Technical Highlights

### Error Handling

Both handlers implement comprehensive error handling:

```erlang
try
    %% Request processing
    handle_request(Data)
catch
    Error:Reason:Stack ->
        ?LOG_ERROR("Error: ~p:~p~nStack: ~p", [Error, Reason, Stack]),
        error_response(...)
end
```

### GPG Signature Verification

REST handler verifies GPG signatures for CSR requests:

```erlang
case cryptic_ca_gpg:verify_signature(GpgSig, GpgPub) of
    {ok, VerifiedCsr} ->
        %% Signature valid, proceed with cert issuance
        ...
    {error, Reason} ->
        error_response(<<"invalid_signature">>, Reason, ...)
end
```

### Invite Validation Flow

Complete invite-based registration:

1. Validate invite token (expiry, consumption status)
2. Extract and validate GPG public key
3. Compute GPG fingerprint
4. Register GPG identity
5. Consume invite (one-time use)
6. Return success response

## Pending Work

### 1. Cowboy Routing Configuration

Need to configure Cowboy routes in the main application:

```erlang
%% In cryptic_app.erl or similar
Dispatch = cowboy_router:compile([
    {'_', [
        {"/ca/v1/register-gpg", cryptic_ca_rest_handler, []},
        {"/ca/v1/csr", cryptic_ca_rest_handler, []},
        {"/ca/v1/status/:fingerprint", cryptic_ca_rest_handler, []},
        {"/ca/ws", cryptic_ca_ws_handler, []}
    ]}
]),

{ok, _} = cowboy:start_clear(
    ca_http_listener,
    [{port, 8080}],
    #{env => #{dispatch => Dispatch}}
).
```

### 2. Rate Limiting

Implement rate limiting for:
- Invite creation (10/day per user)
- Registration attempts (100/hour per IP)
- CSR requests (50/hour per fingerprint)

### 3. Integration Testing

Create full integration tests:
- Start Cowboy server
- Make HTTP requests
- Test WebSocket connections
- Verify end-to-end flows

### 4. Authentication

For WebSocket handler:
- Extract GPG fingerprint from mTLS certificate
- Validate certificate chain
- Associate WebSocket connection with GPG identity

## Module Dependencies

```
cryptic_ca_ws_handler
├── cryptic_invite_mgr (invite operations)
├── cryptic_gpg_registry (identity management)
├── cryptic_ca_gpg (GPG operations)
└── cryptic_ca_store (database access)

cryptic_ca_rest_handler
├── cryptic_invite_mgr (validation & consumption)
├── cryptic_gpg_registry (identity verification)
├── cryptic_ca_gpg (signature verification)
└── cryptic_ca_store (database access)
```

## API Documentation

### WebSocket Command Format

All commands use JSON format:

```json
{
  "command": "invite_create",
  "expiry_hours": 24,
  "meta": {"note": "Inviting Bob"}
}
```

Response:

```json
{
  "status": "success",
  "invite_id": "inv-8f3b12a4...",
  "expires_at": 1234567890
}
```

### REST Request Format

**Registration**:
```bash
POST /ca/v1/register-gpg
Content-Type: application/json

{
  "invite_id": "inv-123...",
  "gpg_pub": "-----BEGIN PGP PUBLIC KEY BLOCK-----..."
}
```

**CSR Submission**:
```bash
POST /ca/v1/csr
Content-Type: application/json

{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "gpg_fp": "ABCD1234...",
  "gpg_sig_b64": "BASE64(...)"
}
```

**Status Check**:
```bash
GET /ca/v1/status/ABCD1234...
```

## Next Steps

1. **Immediate** (Phase 2 completion):
   - Configure Cowboy routing in main application
   - Implement rate limiting middleware
   - Add mTLS authentication extraction for WebSocket

2. **Short-term** (Phase 3):
   - Implement actual certificate issuance (currently placeholder)
   - Integrate myca library for cert signing
   - Add certificate renewal support

3. **Testing** (Phase 6):
   - Create integration test suite
   - Test all endpoints end-to-end
   - Performance testing
   - Security testing

## Compilation Status

```bash
$ rebar3 compile
===> Verifying dependencies...
===> Analyzing applications...
===> Compiling cryptic
```

✅ All modules compile successfully
✅ No warnings or errors
✅ Ready for routing configuration

## Files Created/Modified

**New Files**:
- `src/cryptic_ca_ws_handler.erl` (401 lines)
- `src/cryptic_ca_rest_handler.erl` (405 lines)
- `test/cryptic_ca_ws_handler_tests.erl` (54 lines)
- `test/cryptic_ca_rest_handler_tests.erl` (60 lines)

**Modified Files**:
- `docs/IMPLEMENTATION-PLAN-GPG-ONBOARDING.md` (progress tracking)

**Total Lines Added**: ~920 lines of production code + tests + documentation

## Conclusion

Phase 2 core implementation is complete with both WebSocket and REST handlers fully implemented and documented. The handlers provide a clean, well-structured API for invite management and GPG registration.

Next priorities are:
1. Cowboy routing setup
2. Rate limiting implementation  
3. mTLS authentication integration
4. Move to Phase 3 (Certificate Issuance)

---

**Prepared by**: GitHub Copilot  
**Review Status**: Ready for routing configuration and integration
