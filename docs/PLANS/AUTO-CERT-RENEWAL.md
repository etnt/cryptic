# Automatic Certificate Renewal Plan

## Overview

This document outlines the plan for implementing automatic certificate renewal in the Cryptic messaging system. Currently, when a client certificate expires, users must manually run `cryptic --onboard` to issue a new CSR signed with their GPG key. This plan aims to automate this process.

## Current State Analysis

### Existing Infrastructure

1. **Certificate Lifecycle**
   - Certificates issued by CA with configurable validity (default: 7 days)
   - `cryptic_cert_monitor` gen_server on **server side** monitors expiration
   - Server-side monitor checks every hour and warns 2 days before expiry
   - Expired certificates marked with 'expired' status automatically

2. **Certificate Issuance Flow**
   - User runs `cryptic-onboard` script
   - Script generates TLS key pair (ECDSA secp384r1)
   - Creates CSR with GPG fingerprint in CN
   - Signs CSR with GPG private key
   - Submits signed CSR to CA via REST API (`POST /ca/v1/csr`)
   - CA validates GPG signature and issues certificate

3. **Client Certificate Storage**
   - Location: `~/.cryptic/<username>/<server_host>_<port>/certificates/`
   - Files: `<username>.crt`, `<username>.key`, `ca.crt`
   - `cryptic_ws_client` loads certificates on startup via environment variables or config

4. **WebSocket Connection**
   - `cryptic_ws_client` establishes mTLS connection using client certificate
   - Uses `gun` HTTP client library with TLS options
   - Certificate loaded once during `connect_websocket/1` call
   - No mechanism currently exists to reload/update certificate on live connection

## Requirements

### Functional Requirements

1. **FR1: Automatic Detection**
   - Client shall detect when certificate is approaching expiration
   - Detection threshold: 25% of certificate lifespan remaining
   - For 7-day cert: trigger renewal at ~1.75 days remaining

2. **FR2: Automatic Renewal**
   - Client shall automatically generate new CSR
   - Client shall sign CSR with existing GPG key (no user interaction)
   - Client shall submit signed CSR to CA REST endpoint
   - Process shall complete without user intervention

3. **FR3: Seamless Transition**
   - Client shall continue operating during renewal process
   - Connection shall gracefully transition to new certificate
   - No message loss during certificate rotation

4. **FR4: Failure Handling**
   - System shall retry failed renewal attempts (with backoff)
   - User shall be notified if automatic renewal fails
   - System shall continue using old certificate until renewal succeeds
   - Fallback to manual process if automatic renewal repeatedly fails

5. **FR5: Security**
   - GPG private key access shall remain secure
   - No weakening of authentication mechanisms
   - Audit trail for automatic renewals

### Non-Functional Requirements

1. **NFR1: Minimal Disruption**
   - Connection downtime during certificate rotation: < 5 seconds
   - Messages queued during reconnection

2. **NFR2: Configurability**
   - Renewal threshold configurable (default: 25%)
   - Retry intervals configurable
   - Option to disable automatic renewal and fall back to manual

3. **NFR3: Observability**
   - Log all renewal attempts and outcomes
   - Metrics for renewal success/failure rates
   - User notification on renewal completion

## Architecture Design

### Components

#### 1. New Module: `cryptic_cert_renewal`

A new gen_server that monitors client certificate expiration and orchestrates renewal.

**Responsibilities:**
- Parse client certificate to extract validity period
- Calculate renewal trigger time (e.g., 75% through validity)
- Generate new CSR using existing identity
- Sign CSR with GPG key
- Submit CSR to CA REST endpoint
- Handle response and save new certificate
- Trigger connection restart with new certificate

**State:**
```erlang
-record(renewal_state, {
    username :: binary(),
    server_host :: binary(),
    server_port :: integer(),
    cert_file :: string(),
    key_file :: string(),
    ca_file :: string(),
    cert_dir :: string(),           % Base directory for certificates
    gpg_fingerprint :: binary(),
    gpg_email :: binary(),
    
    % Certificate lifecycle
    cert_expires_at :: integer(),   % Unix timestamp
    cert_issued_at :: integer(),    % Unix timestamp
    renewal_threshold :: float(),   % Percentage (default: 0.25 for 25%)
    renewal_trigger_time :: integer(), % Unix timestamp when renewal should occur
    
    % Renewal process state
    renewal_in_progress :: boolean(),
    renewal_attempts :: integer(),
    last_renewal_attempt :: integer(), % Unix timestamp
    
    % Timers
    check_timer_ref :: reference(),
    
    % Configuration
    auto_renewal_enabled :: boolean(), % Feature flag
    max_retry_attempts :: integer(),   % Default: 5
    retry_interval :: integer(),       % Seconds, default: 3600 (1 hour)
    
    % Callbacks
    ws_client_pid :: pid() | undefined % For triggering reconnection
}).
```

**API:**
```erlang
-module(cryptic_cert_renewal).

%% API
-export([
    start_link/1,
    check_now/0,
    get_status/0,
    enable/0,
    disable/0
]).

%% Configuration map
%% #{
%%   username => <<"alice">>,
%%   server_host => <<"localhost">>,
%%   server_port => 8443,
%%   cert_file => "/path/to/alice.crt",
%%   key_file => "/path/to/alice.key",
%%   ca_file => "/path/to/ca.crt",
%%   gpg_fingerprint => <<"ABC123...">>,
%%   gpg_email => <<"alice@example.com">>,
%%   renewal_threshold => 0.25,  % Optional, default 25%
%%   auto_renewal_enabled => true % Optional, default true
%% }
-spec start_link(Config :: map()) -> {ok, pid()} | {error, term()}.

%% Trigger immediate renewal check (for testing/debugging)
-spec check_now() -> ok.

%% Get current renewal status
-spec get_status() -> map().

%% Enable/disable automatic renewal at runtime
-spec enable() -> ok.
-spec disable() -> ok.
```

**Internal Functions:**
```erlang
%% Parse certificate and extract validity dates
-spec parse_certificate(CertFile :: string()) -> 
    {ok, IssuedAt :: integer(), ExpiresAt :: integer()} | {error, term()}.

%% Calculate when renewal should be triggered
-spec calculate_renewal_time(IssuedAt, ExpiresAt, Threshold) -> TriggerTime
    when IssuedAt :: integer(),
         ExpiresAt :: integer(),
         Threshold :: float(),
         TriggerTime :: integer().

%% Generate new CSR (reuse logic from cryptic-onboard script)
-spec generate_csr(State) -> {ok, CsrPem :: binary(), NewState} | {error, term(), State}.

%% Sign CSR with GPG
-spec sign_csr_with_gpg(CsrPem, GpgFingerprint) -> 
    {ok, GpgSignature :: binary()} | {error, term()}.

%% Submit CSR to CA REST endpoint
-spec submit_csr_to_ca(CsrPem, GpgFp, GpgSig, ServerHost, ServerPort) ->
    {ok, CertPem :: binary()} | {error, term()}.

%% Save new certificate to disk
-spec save_new_certificate(CertPem, CertFile) -> ok | {error, term()}.

%% Trigger WebSocket client reconnection with new certificate
-spec trigger_reconnection(WsClientPid) -> ok.
```

#### 2. Modified Module: `cryptic_ws_client`

**New Functionality:**
- API to trigger certificate reload and reconnection
- Gracefully close current connection
- Re-read certificate files from disk
- Re-establish mTLS connection with new certificate

**New API Functions:**
```erlang
%% Request certificate rotation and reconnection
-spec reload_certificate_and_reconnect(Pid :: pid()) -> ok.

%% Internal: Perform graceful reconnection
-spec do_reload_certificate(State) -> {ok, NewState} | {error, Reason, State}.
```

**Reconnection Strategy:**
```erlang
do_reload_certificate(State) ->
    %% 1. Close existing WebSocket and gun connection gracefully
    case State#state.conn_pid of
        undefined -> ok;
        ConnPid ->
            case State#state.stream_ref of
                undefined -> ok;
                StreamRef ->
                    %% Send close frame to WebSocket
                    gun:ws_send(ConnPid, StreamRef, close)
            end,
            %% Give it a moment to close cleanly
            timer:sleep(100),
            gun:close(ConnPid)
    end,
    
    %% 2. Re-read certificate files (new cert should be on disk)
    %%    Certificate paths remain the same, just file contents changed
    
    %% 3. Re-establish connection with new certificate
    %%    Reuse existing connect_websocket/1 logic
    case connect_websocket(State#state{conn_pid = undefined, 
                                      stream_ref = undefined,
                                      connected = false}) of
        {ok, NewState} ->
            ?info("Successfully reconnected with new certificate", []),
            {ok, NewState};
        {error, Reason} ->
            ?error("Failed to reconnect with new certificate: ~p", [Reason]),
            {error, Reason, State}
    end.
```

#### 3. Integration Point: `cryptic_console` / `cryptic_tui_bridge`

**Startup Integration:**
- Start `cryptic_cert_renewal` gen_server after WebSocket client starts
- Pass WebSocket client PID to renewal server
- Pass certificate configuration from console config

**Example Integration:**
```erlang
%% In cryptic_console startup sequence:
case cryptic_ws_client:start_link(Username, ServerHost, Config) of
    {ok, WsClientPid} ->
        %% Start certificate renewal monitor
        RenewalConfig = Config#{
            username => Username,
            server_host => ServerHost,
            server_port => maps:get(server_port, Config, 8443),
            ws_client_pid => WsClientPid,
            auto_renewal_enabled => 
                application:get_env(cryptic, auto_cert_renewal, true)
        },
        case cryptic_cert_renewal:start_link(RenewalConfig) of
            {ok, RenewalPid} ->
                %% Success - both started
                {ok, WsClientPid, RenewalPid};
            {error, RenewalReason} ->
                %% Log warning but continue without auto-renewal
                ?warning("Failed to start certificate renewal monitor: ~p", 
                        [RenewalReason]),
                ?warning("Certificate renewal will be manual only", []),
                {ok, WsClientPid, undefined}
        end;
    {error, WsReason} ->
        {error, WsReason}
end.
```

#### 4. GPG Integration via erl_gpg Library

**Current State:**
- Cryptic already uses the `erl_gpg` library (https://github.com/etnt/erl_gpg)
- Developed in-house as a standalone Erlang GPG wrapper
- Currently supports: `verify/2,3`, `verify_detached/3,4`, `compute_fingerprint/1,2`, `get_key_info/1,2`
- **Missing:** `sign/2,3` and `sign_detached/3,4` functions for creating signatures

**Required Enhancement:**
Add signing capabilities to `erl_gpg_api` module to support automatic certificate renewal.

**New Functions to Add to erl_gpg:**

```erlang
%% In erl_gpg_api.erl

%%% @doc Sign data with a GPG private key (inline signature).
%%%
%%% Creates a GPG signature that includes both the original data and the signature.
%%% Uses the GPG agent for passphrase management - user will be prompted if
%%% passphrase is not cached.
%%%
%%% @param Data The data to sign (binary)
%%% @param SignerKeyId The GPG key ID or fingerprint to sign with
%%% @returns `{ok, SignedData}' where SignedData is ASCII-armored GPG message
%%%          including both data and signature, or `{error, Reason}'
-spec sign(binary(), string()) -> {ok, binary()} | {error, term()}.
sign(Data, SignerKeyId) ->
    sign(Data, SignerKeyId, []).

-spec sign(binary(), string(), proplists:proplist()) -> 
    {ok, binary()} | {error, term()}.
sign(Data, SignerKeyId, Options) ->
    start_worker(sign, Data, {SignerKeyId, Options}).

%%% @doc Create a detached GPG signature.
%%%
%%% Creates a GPG signature that is separate from the data being signed.
%%% This is the format used for CSR signing in the onboarding process.
%%% Uses the GPG agent for passphrase management.
%%%
%%% == Example ==
%%%
%%% ```
%%% CSR_PEM = <<"-----BEGIN CERTIFICATE REQUEST-----\n...">>,
%%% GpgFingerprint = "ABC123...DEF789",
%%% {ok, Signature} = erl_gpg_api:sign_detached(CSR_PEM, GpgFingerprint, []),
%%% %% Signature is ASCII-armored: <<"-----BEGIN PGP SIGNATURE-----\n...">>
%%% '''
%%%
%%% @param Data The data to sign (binary)
%%% @param SignerKeyId The GPG key ID or fingerprint to sign with (string)
%%% @param Options Proplist of options:
%%%        - `{armor, true}' - Output ASCII-armored (default: true)
%%%        - `{home_dir, Path}' - Custom GPG home directory
%%%        - `{detach_sign, true}' - Create detached signature (default: true)
%%% @returns `{ok, Signature}' where Signature is ASCII-armored detached signature,
%%%          or `{error, Reason}'
-spec sign_detached(binary(), string(), proplists:proplist()) ->
    {ok, binary()} | {error, term()}.
sign_detached(Data, SignerKeyId, Options) ->
    %% Force detach_sign option
    Options1 = [{detach_sign, true} | proplists:delete(detach_sign, Options)],
    start_worker(sign, Data, {SignerKeyId, Options1}).
```

**Worker Implementation (erl_gpg_worker.erl):**

```erlang
%% Add to handle_operation/3 in erl_gpg_worker.erl

handle_operation(sign, Data, {SignerKeyId, Options}) ->
    %% Build GPG command
    Armor = proplists:get_value(armor, Options, true),
    DetachSign = proplists:get_value(detach_sign, Options, false),
    HomeDir = proplists:get_value(home_dir, Options, undefined),
    
    Args = lists:flatten([
        case HomeDir of
            undefined -> [];
            Dir -> ["--homedir", Dir]
        end,
        case Armor of
            true -> ["--armor"];
            false -> []
        end,
        case DetachSign of
            true -> ["--detach-sign"];
            false -> ["--sign"]
        end,
        ["--local-user", SignerKeyId],
        %% Use pinentry for passphrase (GPG agent integration)
        ["--pinentry-mode", "default"]
    ]),
    
    %% Execute GPG with stdin/stdout
    Port = open_port({spawn_executable, "/usr/bin/gpg"},
                     [binary, {args, Args}, 
                      {line, 16384}, exit_status, use_stdio, stderr_to_stdout]),
    
    %% Send data to sign
    port_command(Port, Data),
    port_close(Port),
    
    %% Collect output
    collect_output(Port).
```

**Integration in cryptic_cert_renewal:**

```erlang
%% In cryptic_cert_renewal.erl

sign_csr_with_gpg(CsrPem, GpgFingerprint) ->
    try
        %% Use erl_gpg_api to sign (GPG agent handles passphrase)
        case erl_gpg_api:sign_detached(CsrPem, binary_to_list(GpgFingerprint), []) of
            {ok, GpgSignature} ->
                ?info("CSR signed successfully with GPG key ~s", [GpgFingerprint]),
                {ok, GpgSignature};
            {error, Reason} ->
                ?error("Failed to sign CSR with GPG: ~p", [Reason]),
                {error, {gpg_sign_failed, Reason}}
        end
    catch
        Class:Error:Stacktrace ->
            ?error("Exception during GPG signing: ~p:~p~n~p",
                  [Class, Error, Stacktrace]),
            {error, {gpg_sign_exception, Error}}
    end.
```

**Advantages of Using erl_gpg:**

1. **Consistency:** Already using `erl_gpg` for verification throughout Cryptic
2. **Maintained In-House:** Can extend/fix as needed for our requirements
3. **GPG Agent Integration:** Proper support for passphrase caching via GPG agent
4. **Type Safety:** Erlang-native interface with proper error handling
5. **Testing:** Can mock/stub for unit tests without shell dependencies
6. **Portability:** Abstracts platform differences in GPG CLI

**GPG Agent Integration:**

The `erl_gpg` library will use GPG's native agent support:
- User prompted for passphrase on first signing attempt
- Agent caches passphrase for configurable duration (default: 10 minutes)
- Subsequent signatures within cache period use cached passphrase
- No passphrase storage in Cryptic application
- Secure and user-friendly approach

**Fallback Options:**

If GPG agent is unavailable or passphrase prompt fails:
1. Log detailed error message
2. Notify user that manual renewal is required
3. Provide instructions to enable GPG agent or run manual `cryptic --onboard`
4. Continue using existing certificate until resolved

### Renewal Flow Sequence

```
┌─────────────┐
│   Client    │
│   Startup   │
└──────┬──────┘
       │
       ├─ Load certificate
       ├─ Parse validity dates
       ├─ Calculate renewal_trigger_time
       │  (issued_at + (expires_at - issued_at) * 0.75)
       │
       ▼
┌──────────────────────┐
│ cryptic_cert_renewal │  (gen_server)
│   periodic check     │
└──────────┬───────────┘
           │
           │ check_timer fires every 1 hour
           │
           ▼
    ┌──────────────┐
    │ Now >=       │ NO
    │ trigger_time?├────┐
    └──────┬───────┘    │
           │ YES        │
           │            │
           ▼            ▼
    ┌──────────────┐   Reschedule
    │   Generate   │   timer
    │   new CSR    │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  Sign CSR    │
    │  with GPG    │ (GPG agent prompts if needed)
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  Submit to   │  POST /ca/v1/csr
    │  CA REST API │  {csr_pem, gpg_fp, gpg_sig_b64}
    └──────┬───────┘
           │
           ├─ Success: New cert returned
           │
           ▼
    ┌──────────────┐
    │  Save new    │  ~/.cryptic/.../certificates/user.crt
    │  certificate │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │  Trigger     │  cryptic_ws_client:reload_certificate_and_reconnect/1
    │  reconnection│
    └──────┬───────┘
           │
           ▼
    ┌──────────────────────┐
    │ cryptic_ws_client    │
    │ - Close WS/gun conn  │
    │ - Re-read cert files │
    │ - Reconnect with TLS │
    └──────────┬───────────┘
           │
           ├─ gun_upgrade success
           │
           ▼
    ┌──────────────┐
    │  Connection  │
    │  restored    │
    │  with new    │
    │  certificate │
    └──────────────┘
```

### Error Handling

1. **GPG Signing Fails**
   - Log error with details
   - Schedule retry with exponential backoff
   - Notify user after N failed attempts
   - Suggest manual renewal after max retries

2. **CA Rejects CSR**
   - Could be due to:
     - GPG key revoked/suspended
     - Rate limiting
     - Invalid signature
   - Log detailed CA response
   - Retry with backoff for transient errors
   - Alert user for permanent errors (revoked status)

3. **Network Failure**
   - CA endpoint unreachable
   - Retry with backoff
   - Continue using existing cert
   - If cert expires before CA reachable, fall back to manual

4. **Reconnection Failure**
   - New cert might be invalid
   - Fall back to old cert if still valid
   - Retry renewal process
   - Alert user if both certs invalid

5. **Certificate File I/O Errors**
   - Permission issues writing new cert
   - Disk full
   - Log detailed error
   - Alert user - manual intervention required

### Retry Strategy

```erlang
-define(RETRY_SCHEDULE, [
    {1, 300},      % Attempt 1: retry after 5 minutes
    {2, 900},      % Attempt 2: retry after 15 minutes  
    {3, 3600},     % Attempt 3: retry after 1 hour
    {4, 7200},     % Attempt 4: retry after 2 hours
    {5, 14400}     % Attempt 5: retry after 4 hours
]).                % After 5 attempts: notify user, fall back to manual

calculate_retry_delay(AttemptNumber) ->
    case lists:keyfind(AttemptNumber, 1, ?RETRY_SCHEDULE) of
        {_, Delay} -> Delay;
        false -> 
            %% Max attempts exceeded
            {error, max_retries_exceeded}
    end.
```

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1)

1. **Create `cryptic_cert_renewal` module**
   - Implement gen_server skeleton
   - Certificate parsing logic
   - Renewal time calculation
   - Periodic check timer

2. **Certificate utilities**
   - Parse X.509 certificates using `public_key` module
   - Extract `notBefore` and `notAfter` dates
   - Convert to Unix timestamps

**Deliverables:**
- `src/cryptic_cert_renewal.erl` with basic monitoring
- Unit tests for certificate parsing
- Unit tests for renewal time calculation

### Phase 2: CSR Generation & erl_gpg Enhancement (Week 2) ✅ COMPLETED

1. **Enhance erl_gpg Library** ✅
   - ✅ Add `sign/2,3` function for inline signatures
   - ✅ Add `sign_detached/3,4` function for detached signatures
   - ✅ Update `erl_gpg_worker` to handle sign operations
   - ✅ Test signing with GPG agent integration (13 test cases)
   - ✅ Committed to erl_gpg repository (commit 7fd6263)
   - ⏳ Tag new version (e.g., v1.1.0) - TODO

2. **CSR Generation in Cryptic** ✅
   - ✅ Implemented pure Erlang CSR generation using `public_key` module
   - ✅ Replaced OpenSSL shell commands with ASN.1 operations
   - ✅ Reuses existing TLS private key
   - ✅ Integrated `erl_gpg_api:sign_detached/3` for CSR signing
   - ✅ Removed all shell dependencies (os:cmd removed)

**Deliverables:**
- ✅ Enhanced `erl_gpg` library with signing support (committed to repo)
- ✅ Pure Erlang CSR generation in `cryptic_cert_renewal`
- ✅ All Phase 1 tests still passing (14/14)
- ⏳ Integration tests for CSR generation - TODO
- ⏳ Updated rebar.lock with new erl_gpg version - TODO after tagging

### Phase 3: CA Communication (Week 3)

1. **REST Client**
   - HTTP client for `POST /ca/v1/csr`
   - JSON encoding/decoding
   - Response parsing and validation

2. **Certificate Persistence**
   - Atomic file write (write to temp, then rename)
   - Backup old certificate before replacing
   - File permission management (600 for private keys)

**Deliverables:**
- CA REST client
- Certificate file management
- Integration tests against test CA

### Phase 4: WebSocket Reconnection (Week 4) ⚙️ IN PROGRESS

1. **Modify `cryptic_ws_client`** ✅ PARTIALLY COMPLETE
   - ✅ Add `reload_certificate_and_reconnect/1` API
   - ✅ Implement graceful disconnection (`close_connection_gracefully/1`)
   - ✅ Certificate reload logic (re-reads from disk on reconnect)
   - ✅ Connection re-establishment (reuses existing `connect_websocket/1`)
   - ✅ Compiles successfully

2. **Message Queueing** ✅ ALREADY IMPLEMENTED
   - ✅ Pending messages already queued during reconnection
   - ✅ Automatic message resending after reconnection
   - ✅ No message loss during certificate rotation

**Deliverables:**
- ✅ Enhanced `cryptic_ws_client` with reload capability
- ⏳ Integration tests for certificate rotation - TODO
- ⏳ End-to-end test with renewal + reconnection - TODO
- ⏳ Connect renewal module to WS client - TODO

### Phase 5: Integration & Testing (Week 5)

1. **Console Integration**
   - Start renewal monitor from `cryptic_console`
   - Configuration management
   - User notifications

2. **Error Handling**
   - Implement retry logic
   - User notifications for failures
   - Logging and observability

3. **Testing**
   - End-to-end renewal scenarios
   - Failure scenario testing
   - Performance testing (connection downtime)

**Deliverables:**
- Fully integrated system
- Comprehensive test suite
- Updated documentation

### Phase 6: Documentation & Deployment (Week 6)

1. **User Documentation**
   - Update QUICKSTART.md
   - Configuration guide
   - Troubleshooting section

2. **Admin Documentation**
   - CA configuration for renewals
   - Monitoring recommendations
   - Audit log interpretation

3. **Deployment**
   - Feature flag for gradual rollout
   - Migration guide for existing installations
   - Backwards compatibility testing

**Deliverables:**
- Complete documentation
- Deployment guide
- Release notes

## Configuration

### Application Environment Variables

```erlang
%% config/sys.config
{cryptic, [
    {auto_cert_renewal_enabled, true},          % Feature flag
    {cert_renewal_threshold, 0.25},             % 25% of lifespan
    {cert_renewal_check_interval, 3600},        % Check every hour (seconds)
    {cert_renewal_max_retries, 5},
    {cert_renewal_retry_intervals, [300, 900, 3600, 7200, 14400]},
    
    %% Notification settings
    {cert_renewal_notify_success, true},        % Notify user on success
    {cert_renewal_notify_failure, true},        % Notify user on failure
    
    %% GPG settings
    {gpg_agent_enabled, true},                  % Use GPG agent
    {gpg_sign_timeout, 30000}                   % 30 seconds for GPG sign
]}.
```

### User Configuration File

```json
// ~/.cryptic/<username>/config.json
{
  "gpg_fingerprint": "ABC123...",
  "gpg_email": "user@example.com",
  "username": "alice",
  "default_server": "https://localhost:8443",
  
  "auto_renewal": {
    "enabled": true,
    "threshold": 0.25,
    "notify_on_success": true,
    "notify_on_failure": true
  }
}
```

## User Experience

### Successful Renewal (Transparent)

```
[11:45:32] System: Certificate expiring in 1.5 days, initiating automatic renewal...
[11:45:33] System: Renewal successful, reconnecting with new certificate
[11:45:34] System: Connected (alice@localhost)
[11:45:34] System: Certificate renewed successfully, valid until 2025-11-26 11:45:33
```

### Failed Renewal (Requires Attention)

```
[11:45:32] System: Certificate expiring in 1.5 days, initiating automatic renewal...
[11:45:33] Warning: Automatic renewal failed: GPG signing error
[11:45:33] System: Will retry in 5 minutes (attempt 1/5)

... (after 5 failed attempts) ...

[14:23:45] Alert: Automatic certificate renewal failed after 5 attempts
[14:23:45] Alert: Certificate expires in 1.2 days
[14:23:45] Alert: Please run manual renewal: cryptic --onboard
[14:23:45] Alert: Error details: GPG key locked - passphrase required
```

### Manual Override

User can always trigger manual renewal:
```bash
# Force immediate renewal check
cryptic --renew-cert

# Disable automatic renewal
cryptic --disable-auto-renewal

# Enable automatic renewal
cryptic --enable-auto-renewal
```

## Security Considerations

### Threat Model

1. **GPG Key Compromise**
   - Risk: Attacker with GPG key can request certificates
   - Mitigation: GPG agent timeout, HSM for sensitive deployments
   - Detection: CA audit logs show unusual CSR patterns

2. **Certificate Theft**
   - Risk: Attacker steals certificate from disk
   - Existing: File permissions (600), encrypted home directory
   - No change to threat model

3. **Man-in-the-Middle on Renewal**
   - Risk: Attacker intercepts renewal request
   - Mitigation: HTTPS to CA, verify CA certificate
   - No degradation from manual process

4. **Denial of Service**
   - Risk: Attacker prevents renewal (network blocking)
   - Mitigation: Retry logic, early renewal trigger (25% threshold)
   - User alert if renewal fails repeatedly

### Audit Trail

All automatic renewals logged in both:

1. **Client Side**
   ```
   ~/.cryptic/<username>/logs/renewal.log
   2025-11-19 11:45:32 [INFO] Certificate renewal triggered (expires: 2025-11-20)
   2025-11-19 11:45:33 [INFO] CSR generated and signed with GPG
   2025-11-19 11:45:33 [INFO] CSR submitted to CA
   2025-11-19 11:45:34 [INFO] New certificate received (serial: ABC123)
   2025-11-19 11:45:34 [INFO] Connection reestablished with new certificate
   ```

2. **Server Side (CA)**
   - Existing `audit_log` table tracks all CSR submissions
   - No changes needed to CA audit system
   - Can query for automatic renewal patterns if needed

## Testing Strategy

### Unit Tests

1. **Certificate Parsing**
   - Parse valid certificate → extract dates correctly
   - Parse expired certificate → detect expiration
   - Parse invalid certificate → return error

2. **Renewal Time Calculation**
   - 7-day cert, 25% threshold → trigger at 5.25 days
   - Different thresholds → correct trigger times
   - Edge cases (very short/long validity periods)

3. **CSR Generation**
   - Generate valid CSR with GPG fingerprint
   - CSR includes correct SAN entries
   - Private key reused from existing cert

### Integration Tests

1. **End-to-End Renewal**
   - Start with valid certificate
   - Fast-forward time to renewal threshold
   - Verify renewal triggered automatically
   - Verify new certificate issued
   - Verify connection reestablished
   - Verify no message loss

2. **Failure Scenarios**
   - GPG signing fails → retry logic triggers
   - CA rejects CSR → appropriate error handling
   - Network unavailable → retry with backoff
   - Reconnection fails → fallback logic

3. **Security Tests**
   - Verify GPG signature validation
   - Verify CA certificate validation
   - Verify certificate chain of trust

### Performance Tests

1. **Connection Downtime**
   - Measure time from old cert close to new cert connected
   - Target: < 5 seconds
   - Measure message queue depth during transition

2. **System Load**
   - Renewal should not spike CPU/memory
   - Multiple clients renewing simultaneously

### Manual Test Scenarios

1. **Happy Path**
   - Install system with 7-day cert
   - Wait for 5 days (or mock time)
   - Observe automatic renewal
   - Verify continued operation

2. **GPG Agent Scenario**
   - Start with GPG agent caching passphrase
   - Observe renewal works without prompt
   - Restart with agent cache cleared
   - Verify renewal prompts for passphrase once

3. **Network Failure**
   - Start renewal with network disconnected
   - Observe retry logic
   - Reconnect network
   - Verify renewal completes

4. **Certificate Expiry During Downtime**
   - Shutdown client for > 7 days
   - Restart with expired certificate
   - Observe renewal triggered immediately
   - Verify connection established with new cert

## Metrics & Monitoring

### Prometheus Metrics (if metrics enabled)

```erlang
%% Counters
cryptic_cert_renewal_attempts_total{result="success|failure"}
cryptic_cert_renewal_reconnects_total{result="success|failure"}

%% Gauges  
cryptic_cert_expires_at_seconds  % Unix timestamp
cryptic_cert_renewal_trigger_at_seconds  % Unix timestamp
cryptic_cert_days_until_expiry

%% Histograms
cryptic_cert_renewal_duration_seconds
cryptic_cert_reconnect_duration_seconds
```

### Log Messages

All renewal events logged at appropriate levels:
- `info`: Successful renewal steps
- `warning`: Retry attempts, approaching expiry
- `error`: Failed renewals, permanent errors
- `debug`: Detailed renewal process information

## Rollout Strategy

### Phase 1: Opt-In Beta (Week 7)

- Feature flag disabled by default
- Documentation for early adopters
- Collect feedback on UX and edge cases

### Phase 2: Opt-Out Default (Week 9)

- Feature flag enabled by default
- Users can opt-out via config
- Monitor for issues at scale

### Phase 3: Fully Enabled (Week 11)

- Remove opt-out option (or keep for special cases)
- Automatic renewal standard behavior
- Manual renewal still available as backup

## Open Questions & Future Enhancements

### Open Questions

1. **Q: Should renewal create a new TLS key pair, or reuse existing?**
   - Reusing key: Simpler, faster, no change to CN
   - New key: Better forward secrecy, but what about GPG fingerprint in CN?
   - **Recommendation:** Reuse key for now, new key generation is future enhancement

2. **Q: How to handle multiple concurrent certificates (old + new during overlap)?**
   - Server accepts both during transition period?
   - **Recommendation:** Immediate cutover, rely on retry logic if issues

3. **Q: Should renewal work with revoked GPG keys?**
   - No - revoked means user is blocked
   - **Recommendation:** Fail renewal, require admin intervention

### Future Enhancements

1. **Certificate Rotation Schedule**
   - Allow admin to set rotation windows (e.g., only during off-peak hours)
   - Useful for servers with scheduled maintenance

2. **Pre-Renewal Testing**
   - Generate and test new cert before cutting over
   - Fall back to old cert if new one doesn't work

3. **HSM Integration**
   - Store GPG keys in Hardware Security Module
   - Enterprise deployment option

4. **Multiple Certificate Support**
   - Handle multiple server connections
   - Each with independent renewal cycle

5. **Certificate Pinning**
   - Pin CA certificate, detect MITM
   - Additional security layer

6. **Automated Backup Key Rotation**
   - Periodically generate new GPG subkeys
   - Migrate to new subkey automatically

## References

- **X.509 Certificate Format:** RFC 5280
- **PKCS#10 CSR:** RFC 2986
- **OpenPGP Message Format:** RFC 4880
- **TLS 1.3:** RFC 8446
- **Erlang public_key module:** https://www.erlang.org/doc/man/public_key.html
- **gun HTTP client:** https://ninenines.eu/docs/en/gun/2.0/guide/
- **erl_gpg library:** https://github.com/etnt/erl_gpg (in-house GPG wrapper)

## Related Work

### erl_gpg Library Enhancement

The automatic certificate renewal feature requires extending the `erl_gpg` library with signing capabilities. This work should be done in the erl_gpg repository first, then integrated into Cryptic.

**erl_gpg Repository Tasks:**
1. Add `sign/2,3` API functions to `erl_gpg_api.erl`
2. Add `sign_detached/3` API function for detached signatures
3. Implement `sign` operation in `erl_gpg_worker.erl`
4. Handle GPG agent integration (pinentry mode)
5. Add comprehensive tests for signing operations
6. Update erl_gpg documentation
7. Tag new release (e.g., v1.1.0)

**Integration into Cryptic:**
1. Update `rebar.config` to reference new erl_gpg version
2. Run `rebar3 upgrade erl_gpg` to update rebar.lock
3. Use new signing functions in `cryptic_cert_renewal`

**Cross-Repository Coordination:**
- erl_gpg enhancement can be developed in parallel with Phase 1 (Core Infrastructure)
- Must be completed before Phase 2 implementation begins
- Consider creating a feature branch in erl_gpg for development
- Merge to main and tag before integrating into Cryptic

## Appendix: Code Snippets

### A. Certificate Parsing Example

```erlang
parse_certificate(CertFile) ->
    case file:read_file(CertFile) of
        {ok, CertPem} ->
            try
                %% Decode PEM to DER
                [{'Certificate', CertDer, not_encrypted}] = 
                    public_key:pem_decode(CertPem),
                
                %% Decode DER to OTP certificate record
                Cert = public_key:pkix_decode_cert(CertDer, otp),
                
                %% Extract validity period
                #'OTPCertificate'{
                    tbsCertificate = #'OTPTBSCertificate'{
                        validity = #'Validity'{
                            notBefore = NotBefore,
                            notAfter = NotAfter
                        }
                    }
                } = Cert,
                
                %% Convert to Unix timestamps
                IssuedAt = validity_time_to_unix(NotBefore),
                ExpiresAt = validity_time_to_unix(NotAfter),
                
                {ok, IssuedAt, ExpiresAt}
            catch
                Class:Reason:Stacktrace ->
                    ?error("Failed to parse certificate ~s: ~p:~p~n~p",
                          [CertFile, Class, Reason, Stacktrace]),
                    {error, {parse_failed, Class, Reason}}
            end;
        {error, Reason} ->
            {error, {read_failed, Reason}}
    end.

%% Convert X.509 validity time to Unix timestamp
validity_time_to_unix({utcTime, TimeStr}) ->
    %% TimeStr format: "YYMMDDHHMMSSZ"
    %% Example: "251119114500Z" = November 19, 2025, 11:45:00 UTC
    parse_utc_time(TimeStr);
validity_time_to_unix({generalTime, TimeStr}) ->
    %% TimeStr format: "YYYYMMDDHHMMSSZ"
    %% Example: "20251119114500Z"
    parse_general_time(TimeStr).
```

### B. CSR Generation Example

```erlang
generate_csr(State) ->
    #renewal_state{
        key_file = KeyFile,
        gpg_fingerprint = GpgFp,
        gpg_email = GpgEmail
    } = State,
    
    try
        %% Read existing private key
        {ok, KeyPem} = file:read_file(KeyFile),
        [KeyEntry] = public_key:pem_decode(KeyPem),
        PrivateKey = public_key:pem_entry_decode(KeyEntry),
        
        %% Create subject with GPG fingerprint
        Subject = {rdnSequence, [
            [{'AttributeTypeAndValue',
              ?'id-at-commonName',
              {utf8String, <<GpgFp/binary, ".gpg.cryptic.local">>}
            }]
        ]},
        
        %% Create CSR with SAN extension
        SubjectAltName = [
            {dNSName, binary_to_list(<<GpgFp/binary, ".gpg.cryptic.local">>)},
            {rfc822Name, binary_to_list(GpgEmail)}
        ],
        
        Extensions = [
            #'Extension'{
                extnID = ?'id-ce-subjectAltName',
                critical = false,
                extnValue = SubjectAltName
            }
        ],
        
        %% Build CSR info
        CsrInfo = #'CertificationRequestInfo'{
            version = v1,
            subject = Subject,
            subjectPKInfo = #'SubjectPublicKeyInfo'{
                algorithm = #'AlgorithmIdentifier'{
                    algorithm = ?'id-ecPublicKey',
                    parameters = {namedCurve, ?'secp384r1'}
                },
                subjectPublicKey = public_key:der_encode(
                    'ECPoint', 
                    element(2, PrivateKey)
                )
            },
            attributes = [
                #'Attribute'{
                    type = ?'id-at-extensionRequest',
                    values = [public_key:der_encode(
                        'Extensions', Extensions
                    )]
                }
            ]
        },
        
        %% Sign CSR with private key
        CsrInfoDer = public_key:der_encode('CertificationRequestInfo', CsrInfo),
        Signature = public_key:sign(CsrInfoDer, sha384, PrivateKey),
        
        Csr = #'CertificationRequest'{
            certificationRequestInfo = CsrInfo,
            signatureAlgorithm = #'AlgorithmIdentifier'{
                algorithm = ?'ecdsa-with-SHA384',
                parameters = asn1_NOVALUE
            },
            signature = Signature
        },
        
        %% Encode to PEM
        CsrDer = public_key:der_encode('CertificationRequest', Csr),
        CsrPem = public_key:pem_encode([
            {'CertificateRequest', CsrDer, not_encrypted}
        ]),
        
        {ok, CsrPem, State}
    catch
        Class:Reason:Stacktrace ->
            ?error("Failed to generate CSR: ~p:~p~n~p",
                  [Class, Reason, Stacktrace]),
            {error, {csr_generation_failed, Class, Reason}, State}
    end.
```

---

**Document Version:** 1.0  
**Last Updated:** November 19, 2025  
**Authors:** Cryptic Development Team  
**Status:** DRAFT - Ready for Review
