# CA API Testing Documentation

## Overview

This document describes the Common Test suite for the Certificate Authority API, which provides comprehensive integration testing for both WebSocket and REST endpoints, including rate limiting functionality.

## Test Suite: cryptic_ca_api_SUITE

### Purpose

The `cryptic_ca_api_SUITE` provides integration tests for:
- WebSocket-based invite management
- REST API endpoints (registration, CSR, status)
- Rate limiting enforcement
- End-to-end onboarding flows
- Invite consumption and validation

### Running the Tests

```bash
# Run all CA API tests
rebar3 ct --suite=test/cryptic_ca_api_SUITE

# Run a specific test
rebar3 ct --suite=test/cryptic_ca_api_SUITE --case=ws_invite_create_success

# Run a specific group
rebar3 ct --suite=test/cryptic_ca_api_SUITE --group=websocket_api
```

### Test Structure

#### Test Groups

1. **websocket_api** (sequential)
   - Tests WebSocket handler functionality
   - Authentication checks
   - Invite creation, listing, and revocation
   - GPG registration via WebSocket

2. **rest_api** (sequential)
   - Tests REST endpoint functionality
   - Registration validation
   - CSR handling (placeholder)
   - Status queries

3. **integration** (sequential)
   - End-to-end flows
   - Cross-component interactions
   - Invite consumption validation

#### Test Cases

##### WebSocket API Tests

- `ws_invite_create_unauthenticated/1` - Verifies authentication is required
- `ws_unknown_command/1` - Tests error handling for invalid commands
- `ws_gpg_register_bootstrap/1` - Tests bootstrap GPG registration
- `ws_invite_create_success/1` - Tests successful invite creation with rate limiting
- `ws_invite_list_success/1` - Tests invite listing with rate limiting
- `ws_invite_revoke_success/1` - Tests invite revocation with rate limiting

##### REST API Tests

- `rest_register_gpg_invalid_invite/1` - Tests registration with invalid invite
- `rest_status_not_found/1` - Tests status query for non-existent GPG fingerprint
- `rest_csr_placeholder/1` - Tests CSR endpoint (placeholder implementation)

##### Integration Tests

- `full_onboarding_flow/1` - Complete user onboarding: bootstrap → invite → registration
- `invite_consumption_prevents_reuse/1` - Verifies invites can only be used once

### Setup and Teardown

#### init_per_suite

1. Starts required applications (crypto, asn1, public_key, ssl, jsx)
2. Configures rate limiting policies
3. Creates test database
4. Starts rate limiter (without link to prevent premature termination)

#### end_per_suite

1. Stops rate limiter
2. Closes database connection
3. Cleans up test database file
4. Unsets application environment

#### init_per_group / end_per_group

Simple passthrough - all setup/teardown happens at suite level.

#### init_per_testcase / end_per_testcase

- Logs test case start/end for debugging

### Test Data

Tests use predictable test data for reproducibility:

```erlang
InviterFp = <<"TEST_INVITER_FP_001">>,
InviteeFp = <<"TEST_INVITEE_FP_002">>,
BootstrapFp = <<"BOOTSTRAP_GPG_FP_001">>,
...
```

### Important Implementation Details

#### Rate Limiter Lifecycle

The rate limiter must be started with `start/0` (not `start_link/0`) in test environments because:
- `start_link/0` links the process to the caller (init_per_suite process)
- When init_per_suite completes, linked processes terminate
- `start/0` creates an independent process that survives suite initialization

This is why `cryptic_ca_rate_limiter` exports both functions:
- `start_link/0` - For production use in supervision trees
- `start/0` - For test environments

#### State Tuple Format

WebSocket handler state uses tuple format for testing:
```erlang
State = {state, GpgFingerprint, DbRef, Authenticated}
```

Where:
- `GpgFingerprint` - Binary GPG fingerprint of current user (or `undefined`)
- `DbRef` - Database reference
- `Authenticated` - Boolean indicating authentication status

#### Database Type Mappings

SQLite stores Erlang types differently:
- Booleans: `true` → `1`, `false` → `0`
- Status atoms: Stored as binaries (e.g., `<<"verified_bootstrap">>`)

Tests must account for these mappings when asserting database values.

### Coverage

The test suite covers:
- ✅ WebSocket command handling
- ✅ REST endpoint responses
- ✅ Authentication enforcement
- ✅ Rate limiting integration
- ✅ Database persistence
- ✅ Invite lifecycle management
- ✅ GPG registration flows
- ✅ Error handling

### Known Limitations

1. **CSR Endpoint**: Currently a placeholder - returns 501 Not Implemented
2. **Rate Limit Testing**: Basic rate limit integration tested, but comprehensive rate limit boundary testing is in `cryptic_ca_rate_limiter_tests.erl`
3. **Real WebSocket**: Tests call handler functions directly rather than over actual WebSocket connections

### Future Enhancements

1. Add comprehensive CSR testing when myca integration is complete
2. Add tests for certificate issuance and revocation
3. Add performance/load tests for rate limiting
4. Add tests for concurrent invite operations
5. Add tests for expired invite cleanup

## Test Results

Current status: **11/11 tests passing** ✅

```
%%% cryptic_ca_api_SUITE: ...........
All 11 tests passed.
```

## Troubleshooting

### Rate Limiter `noproc` Errors

**Symptom**: Tests fail with `{noproc, {gen_server, call, [cryptic_ca_rate_limiter, ...]}}`

**Cause**: Rate limiter started with `start_link/0` instead of `start/0`, causing it to terminate when init_per_suite completes.

**Solution**: Use `cryptic_ca_rate_limiter:start()` in test suites.

### Database Lock Errors

**Symptom**: `{error, {database_locked, ...}}`

**Cause**: Multiple tests trying to access database concurrently

**Solution**: Tests are run sequentially within groups to avoid this issue.

### Type Mismatch Assertions

**Symptom**: Expected atom/boolean, got binary/integer

**Cause**: SQLite type mappings differ from Erlang native types

**Solution**: Assert against database-native types:
- `?assertEqual(1, ...)` instead of `?assertEqual(true, ...)`
- `?assertEqual(<<"verified_bootstrap">>, ...)` instead of `?assertEqual(verified_bootstrap, ...)`

## Related Documentation

- [Rate Limiting Documentation](RATE-LIMITING.md) - Detailed rate limiting architecture and policies
- [Phase 2 Completion Report](PHASE2-RATE-LIMITING-COMPLETION.md) - Implementation summary
- Main README - Project overview and setup instructions
