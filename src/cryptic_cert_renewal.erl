%% @doc Certificate Renewal Monitor for Automatic Client Certificate Renewal
%%
%% This gen_server monitors client certificate expiration and orchestrates
%% automatic renewal when the certificate approaches expiration. It handles:
%%
%% <ul>
%%   <li>Certificate expiry monitoring with configurable thresholds</li>
%%   <li>Automatic CSR generation and GPG signing</li>
%%   <li>Certificate renewal via CA REST API</li>
%%   <li>WebSocket client reconnection with new certificate</li>
%%   <li>Retry logic with exponential backoff</li>
%% </ul>
%%
%% == Configuration ==
%%
%% ```
%% {cryptic, [
%%     {auto_cert_renewal_enabled, true},
%%     {cert_renewal_threshold, 0.25},           %% 25% of lifespan
%%     {cert_renewal_check_interval, 3600},      %% Check every hour (seconds)
%%     {cert_renewal_max_retries, 5},
%%     {cert_renewal_retry_intervals, [300, 900, 3600, 7200, 14400]}
%% ]}.
%% '''
%%
%% == Renewal Flow ==
%%
%% 1. Parse certificate to extract validity period
%% 2. Calculate renewal trigger time (issued_at + (expires_at - issued_at) * 0.75)
%% 3. Periodically check if current time >= trigger time
%% 4. Generate new CSR and sign with GPG key
%% 5. Submit signed CSR to CA REST endpoint
%% 6. Save new certificate to disk
%% 7. Trigger WebSocket client reconnection
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since November 2025
-module(cryptic_cert_renewal).
-behaviour(gen_server).

-include("cryptic.hrl").
-include_lib("public_key/include/public_key.hrl").

%% API
-export([
    start_link/1,
    check_now/0,
    get_status/0,
    enable/0,
    disable/0
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

%% Exported for testing
-ifdef(TEST).
-export([
    parse_certificate/1,
    validity_time_to_unix/1,
    calculate_renewal_time/3
]).
-endif.

%% Internal state record
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
    check_timer_ref :: reference() | undefined,
    
    % Configuration
    auto_renewal_enabled = true :: boolean(), % Feature flag, default: true
    max_retry_attempts = 5 :: integer(),      % Default: 5
    retry_interval = 3600 :: integer(),       % Seconds, default: 3600 (1 hour)
    
    % Callbacks
    ws_client_pid :: pid() | undefined % For triggering reconnection
}).

-type renewal_state() :: #renewal_state{}.

%%====================================================================
%% API Functions
%%====================================================================

%% @doc Start the certificate renewal monitor.
%%
%% Configuration map should contain:
%% ```
%% #{
%%   username => <<"alice">>,
%%   server_host => <<"localhost">>,
%%   server_port => 8443,
%%   cert_file => "/path/to/alice.crt",
%%   key_file => "/path/to/alice.key",
%%   ca_file => "/path/to/ca.crt",
%%   gpg_fingerprint => <<"ABC123...">>,
%%   gpg_email => <<"alice@example.com">>,
%%   renewal_threshold => 0.25,        % Optional, default 25%
%%   auto_renewal_enabled => true,     % Optional, default true
%%   ws_client_pid => Pid              % Optional, set later via set_ws_client/1
%% }
%% '''
%%
%% @param Config Configuration map with certificate and GPG information
%% @returns `{ok, Pid}' on success, `{error, Reason}' on failure
-spec start_link(Config :: map()) -> {ok, pid()} | {error, term()}.
start_link(Config) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

%% @doc Trigger immediate renewal check (for testing/debugging).
%%
%% @returns `ok'
-spec check_now() -> ok.
check_now() ->
    gen_server:cast(?MODULE, check_now).

%% @doc Get current renewal status and statistics.
%%
%% Returns a map containing:
%% <ul>
%%   <li>`enabled' - Whether auto-renewal is enabled</li>
%%   <li>`cert_expires_at' - Certificate expiration timestamp</li>
%%   <li>`renewal_trigger_time' - When renewal will be triggered</li>
%%   <li>`renewal_in_progress' - Whether renewal is currently running</li>
%%   <li>`renewal_attempts' - Number of renewal attempts made</li>
%%   <li>`last_renewal_attempt' - Timestamp of last attempt</li>
%%   <li>`time_until_renewal' - Seconds until renewal trigger</li>
%%   <li>`time_until_expiry' - Seconds until certificate expires</li>
%% </ul>
%%
%% @returns Status map
-spec get_status() -> map().
get_status() ->
    gen_server:call(?MODULE, get_status).

%% @doc Enable automatic certificate renewal at runtime.
%%
%% @returns `ok'
-spec enable() -> ok.
enable() ->
    gen_server:call(?MODULE, enable).

%% @doc Disable automatic certificate renewal at runtime.
%%
%% @returns `ok'
-spec disable() -> ok.
disable() ->
    gen_server:call(?MODULE, disable).

%%====================================================================
%% gen_server Callbacks
%%====================================================================

%% @private
init(Config) ->
    ?info("Starting certificate renewal monitor", []),

    %% Extract configuration
    Username = maps:get(username, Config),
    ServerHost = maps:get(server_host, Config),
    ServerPort = maps:get(server_port, Config, 8443),
    CertFile = maps:get(cert_file, Config),
    KeyFile = maps:get(key_file, Config),
    CAFile = maps:get(ca_file, Config),
    GpgFingerprint = maps:get(gpg_fingerprint, Config),
    GpgEmail = maps:get(gpg_email, Config),

    %% Configuration options with defaults
    RenewalThreshold = maps:get(renewal_threshold, Config, 0.25),
    AutoRenewalEnabled = maps:get(auto_renewal_enabled, Config, true),
    WsClientPid = maps:get(ws_client_pid, Config, undefined),

    %% Application-level configuration
    CheckInterval = application:get_env(cryptic, cert_renewal_check_interval, 3600),
    MaxRetries = application:get_env(cryptic, cert_renewal_max_retries, 5),
    RetryInterval = application:get_env(cryptic, cert_renewal_retry_interval, 3600),

    %% Extract certificate directory from cert_file path
    CertDir = filename:dirname(filename:dirname(CertFile)),

    %% Parse certificate to get validity period
    case parse_certificate(CertFile) of
        {ok, IssuedAt, ExpiresAt} ->
            %% Calculate when renewal should trigger
            TriggerTime = calculate_renewal_time(IssuedAt, ExpiresAt, RenewalThreshold),

            %% Log certificate information
            Now = erlang:system_time(second),
            DaysUntilExpiry = (ExpiresAt - Now) div 86400,
            DaysUntilRenewal = (TriggerTime - Now) div 86400,

            ?info("Certificate loaded: expires in ~p days", [DaysUntilExpiry]),
            ?info("Renewal will trigger in ~p days (at ~p% of lifespan)", 
                  [DaysUntilRenewal, trunc(RenewalThreshold * 100)]),

            %% Schedule first check (delayed start: 10 seconds after initialization)
            InitialDelay = 10000,  % 10 seconds
            CheckTimerRef = erlang:send_after(InitialDelay, self(), check_renewal),

            ?info("Certificate renewal monitor initialized", []),
            ?info("  Check interval: ~p seconds", [CheckInterval]),
            ?info("  Max retries: ~p", [MaxRetries]),
            ?info("  Retry interval: ~p seconds", [RetryInterval]),

            State = #renewal_state{
                username = Username,
                server_host = ServerHost,
                server_port = ServerPort,
                cert_file = CertFile,
                key_file = KeyFile,
                ca_file = CAFile,
                cert_dir = CertDir,
                gpg_fingerprint = GpgFingerprint,
                gpg_email = GpgEmail,
                cert_expires_at = ExpiresAt,
                cert_issued_at = IssuedAt,
                renewal_threshold = RenewalThreshold,
                renewal_trigger_time = TriggerTime,
                renewal_in_progress = false,
                renewal_attempts = 0,
                last_renewal_attempt = 0,
                check_timer_ref = CheckTimerRef,
                auto_renewal_enabled = AutoRenewalEnabled,
                max_retry_attempts = MaxRetries,
                retry_interval = RetryInterval,
                ws_client_pid = WsClientPid
            },
            
            {ok, State};
        {error, Reason} ->
            ?error("Failed to parse certificate ~s: ~p", [CertFile, Reason]),
            {stop, {certificate_parse_failed, Reason}}
    end.

%% @private
handle_call(get_status, _From, State) ->
    Now = erlang:system_time(second),
    Status = #{
        enabled => State#renewal_state.auto_renewal_enabled,
        cert_expires_at => State#renewal_state.cert_expires_at,
        cert_issued_at => State#renewal_state.cert_issued_at,
        renewal_trigger_time => State#renewal_state.renewal_trigger_time,
        renewal_threshold => State#renewal_state.renewal_threshold,
        renewal_in_progress => State#renewal_state.renewal_in_progress,
        renewal_attempts => State#renewal_state.renewal_attempts,
        last_renewal_attempt => State#renewal_state.last_renewal_attempt,
        time_until_renewal => max(0, State#renewal_state.renewal_trigger_time - Now),
        time_until_expiry => max(0, State#renewal_state.cert_expires_at - Now),
        username => State#renewal_state.username,
        server_host => State#renewal_state.server_host,
        server_port => State#renewal_state.server_port
    },
    {reply, Status, State};

handle_call(enable, _From, State) ->
    ?info("Certificate auto-renewal enabled", []),
    {reply, ok, State#renewal_state{auto_renewal_enabled = true}};

handle_call(disable, _From, State) ->
    ?info("Certificate auto-renewal disabled", []),
    {reply, ok, State#renewal_state{auto_renewal_enabled = false}};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

%% @private
handle_cast(check_now, State) ->
    ?info("Manual renewal check triggered", []),
    NewState = perform_renewal_check(State),
    {noreply, NewState};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(check_renewal, State) ->
    %% Perform periodic renewal check
    NewState = perform_renewal_check(State),
    
    %% Schedule next check
    CheckInterval = application:get_env(cryptic, cert_renewal_check_interval, 3600),
    CheckTimerRef = erlang:send_after(CheckInterval * 1000, self(), check_renewal),
    
    {noreply, NewState#renewal_state{check_timer_ref = CheckTimerRef}};

handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, State) ->
    %% Cancel check timer
    case State#renewal_state.check_timer_ref of
        undefined -> ok;
        TimerRef -> erlang:cancel_timer(TimerRef)
    end,
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal Functions
%%====================================================================

%% @private
%% @doc Parse certificate and extract validity dates.
%%
%% @param CertFile Path to certificate file
%% @returns `{ok, IssuedAt, ExpiresAt}' with Unix timestamps, or `{error, Reason}'
-spec parse_certificate(string()) ->
    {ok, IssuedAt :: integer(), ExpiresAt :: integer()} | {error, term()}.
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

%% @private
%% @doc Convert X.509 validity time to Unix timestamp.
%%
%% Handles both utcTime and generalTime formats.
-spec validity_time_to_unix(term()) -> integer().
validity_time_to_unix({utcTime, TimeStr}) ->
    %% utcTime format: "YYMMDDHHMMSSZ" (2-digit year)
    %% Example: "251119114500Z" = November 19, 2025, 11:45:00 UTC
    parse_utc_time(TimeStr);
validity_time_to_unix({generalTime, TimeStr}) ->
    %% generalTime format: "YYYYMMDDHHMMSSZ" (4-digit year)
    %% Example: "20251119114500Z"
    parse_general_time(TimeStr).

%% @private
%% @doc Parse UTCTime format to Unix timestamp.
%%
%% UTCTime uses 2-digit year (YY):
%% - 00-49 interpreted as 2000-2049
%% - 50-99 interpreted as 1950-1999
-spec parse_utc_time(string()) -> integer().
parse_utc_time(TimeStr) when is_list(TimeStr) ->
    %% Format: "YYMMDDHHMMSSZ"
    [YY, MM, DD, HH, Min, SS | _] = 
        [list_to_integer([A, B]) || 
         <<A, B>> <= list_to_binary(TimeStr), 
         A >= $0, A =< $9, B >= $0, B =< $9],
    
    %% Convert 2-digit year to 4-digit
    Year = if
        YY >= 50 -> 1900 + YY;
        true -> 2000 + YY
    end,
    
    %% Convert to Unix timestamp
    datetime_to_unix({{Year, MM, DD}, {HH, Min, SS}}).

%% @private
%% @doc Parse GeneralTime format to Unix timestamp.
-spec parse_general_time(string()) -> integer().
parse_general_time(TimeStr) when is_list(TimeStr) ->
    %% Format: "YYYYMMDDHHMMSSZ"
    <<YearBin:4/binary, MMBin:2/binary, DDBin:2/binary,
      HHBin:2/binary, MinBin:2/binary, SSBin:2/binary, _Rest/binary>> = 
        list_to_binary(TimeStr),
    
    Year = binary_to_integer(YearBin),
    MM = binary_to_integer(MMBin),
    DD = binary_to_integer(DDBin),
    HH = binary_to_integer(HHBin),
    Min = binary_to_integer(MinBin),
    SS = binary_to_integer(SSBin),
    
    %% Convert to Unix timestamp
    datetime_to_unix({{Year, MM, DD}, {HH, Min, SS}}).

%% @private
%% @doc Convert Erlang datetime to Unix timestamp.
-spec datetime_to_unix(calendar:datetime()) -> integer().
datetime_to_unix(DateTime) ->
    %% Erlang datetime is in UTC
    %% Unix epoch: January 1, 1970, 00:00:00 UTC
    EpochSeconds = calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}}),
    calendar:datetime_to_gregorian_seconds(DateTime) - EpochSeconds.

%% @private
%% @doc Calculate when renewal should be triggered.
%%
%% @param IssuedAt Unix timestamp when certificate was issued
%% @param ExpiresAt Unix timestamp when certificate expires
%% @param Threshold Percentage of lifespan after which to renew (0.0 to 1.0)
%% @returns Unix timestamp when renewal should trigger
-spec calculate_renewal_time(integer(), integer(), float()) -> integer().
calculate_renewal_time(IssuedAt, ExpiresAt, Threshold) 
  when is_integer(IssuedAt), is_integer(ExpiresAt), 
       is_float(Threshold), Threshold > 0.0, Threshold < 1.0 ->
    Lifespan = ExpiresAt - IssuedAt,
    TimeBeforeRenewal = trunc(Lifespan * (1.0 - Threshold)),
    IssuedAt + TimeBeforeRenewal.

%% @private
%% @doc Perform renewal check and initiate renewal if needed.
-spec perform_renewal_check(renewal_state()) -> renewal_state().
perform_renewal_check(State) ->
    Now = erlang:system_time(second),
    
    %% Check if renewal should be triggered
    ShouldRenew = State#renewal_state.auto_renewal_enabled andalso
                  Now >= State#renewal_state.renewal_trigger_time andalso
                  not State#renewal_state.renewal_in_progress,
    
    case ShouldRenew of
        true ->
            %% Log renewal trigger
            DaysUntilExpiry = (State#renewal_state.cert_expires_at - Now) div 86400,
            ?info("Certificate renewal triggered: ~p days until expiry", [DaysUntilExpiry]),
            
            %% Perform renewal process
            NewState = State#renewal_state{
                renewal_in_progress = true,
                last_renewal_attempt = Now,
                renewal_attempts = State#renewal_state.renewal_attempts + 1
            },
            
            perform_renewal_process(NewState);
        false ->
            %% Log status if close to renewal time
            TimeUntilRenewal = State#renewal_state.renewal_trigger_time - Now,
            if
                TimeUntilRenewal > 0 andalso TimeUntilRenewal < 86400 ->
                    HoursUntilRenewal = TimeUntilRenewal div 3600,
                    ?dbg("Certificate renewal in ~p hours~n", [HoursUntilRenewal]);
                true ->
                    ok
            end,
            State
    end.

%% @private
%% @doc Execute the complete renewal process.
-spec perform_renewal_process(renewal_state()) -> renewal_state().
perform_renewal_process(State) ->
    Username = State#renewal_state.username,
    KeyFile = State#renewal_state.key_file,
    CertFile = State#renewal_state.cert_file,
    ServerHost = State#renewal_state.server_host,
    ServerPort = State#renewal_state.server_port,
    GpgFingerprint = State#renewal_state.gpg_fingerprint,
    
    ?info("Starting certificate renewal process for ~s", [Username]),
    
    %% Step 1: Generate CSR
    case generate_csr(Username, KeyFile, CertFile) of
        {ok, CsrPem} ->
            ?info("CSR generated successfully", []),
            
            %% Step 2: Sign CSR with GPG
            case sign_csr_with_gpg(CsrPem, GpgFingerprint) of
                {ok, GpgSignature} ->
                    ?info("CSR signed with GPG successfully", []),
                    
                    %% Step 3: Submit to CA
                    case submit_csr_to_ca(ServerHost, ServerPort, CsrPem, 
                                          GpgFingerprint, GpgSignature) of
                        {ok, NewCertPem} ->
                            ?info("New certificate received from CA", []),
                            
                            %% Step 4: Install new certificate
                            case install_new_certificate(NewCertPem, CertFile) of
                                ok ->
                                    ?info("New certificate installed successfully", []),
                                    
                                    %% Step 5: Trigger WebSocket reconnect
                                    WsPid = State#renewal_state.ws_client_pid,
                                    case trigger_websocket_reconnect(WsPid) of
                                        ok ->
                                            ?info("Certificate renewal completed successfully", []),
                                            
                                            %% Parse new certificate for updated timestamps
                                            {ok, IssuedAt, ExpiresAt} = 
                                                parse_certificate(CertFile),
                                            Threshold = State#renewal_state.renewal_threshold,
                                            NewTriggerTime = calculate_renewal_time(
                                                IssuedAt, ExpiresAt, Threshold
                                            ),
                                            
                                            %% Reset renewal state
                                            State#renewal_state{
                                                cert_issued_at = IssuedAt,
                                                cert_expires_at = ExpiresAt,
                                                renewal_trigger_time = NewTriggerTime,
                                                renewal_in_progress = false,
                                                renewal_attempts = 0
                                            };
                                        {error, ReconnectError} ->
                                            ?warning("Failed to trigger reconnect: ~p", 
                                                   [ReconnectError]),
                                            %% Cert is installed but reconnect failed
                                            %% Mark as success but log warning
                                            State#renewal_state{
                                                renewal_in_progress = false,
                                                renewal_attempts = 0
                                            }
                                    end;
                                {error, InstallError} ->
                                    ?error("Failed to install certificate: ~p", [InstallError]),
                                    handle_renewal_failure(State, InstallError)
                            end;
                        {error, CaError} ->
                            ?error("CA rejected CSR: ~p", [CaError]),
                            handle_renewal_failure(State, CaError)
                    end;
                {error, GpgError} ->
                    ?error("GPG signing failed: ~p", [GpgError]),
                    handle_renewal_failure(State, GpgError)
            end;
        {error, CsrError} ->
            ?error("CSR generation failed: ~p", [CsrError]),
            handle_renewal_failure(State, CsrError)
    end.

%% @private
%% @doc Handle renewal failure with retry logic.
-spec handle_renewal_failure(renewal_state(), term()) -> renewal_state().
handle_renewal_failure(State, Reason) ->
    MaxAttempts = State#renewal_state.max_retry_attempts,
    CurrentAttempts = State#renewal_state.renewal_attempts,
    
    if
        CurrentAttempts >= MaxAttempts ->
            ?error("Certificate renewal failed after ~p attempts: ~p", 
                  [MaxAttempts, Reason]),
            ?error("Manual intervention required - please run: cryptic --onboard", []),
            
            %% Reset renewal state but keep failure count for visibility
            State#renewal_state{
                renewal_in_progress = false
            };
        true ->
            RetryInterval = State#renewal_state.retry_interval,
            ?warning("Renewal attempt ~p/~p failed, will retry in ~p seconds", 
                   [CurrentAttempts, MaxAttempts, RetryInterval]),
            
            %% Schedule retry
            erlang:send_after(RetryInterval * 1000, self(), check_renewal),
            
            State#renewal_state{
                renewal_in_progress = false
            }
    end.

%%====================================================================
%% Phase 2: CSR Generation & Renewal Process
%%====================================================================

%% @private
%% @doc Generate a Certificate Signing Request (CSR) using existing private key.
%%
%% This function creates a CSR using pure Erlang (public_key module). The CSR includes:
%% - Common Name (CN) from username
%% - Existing private key (key file remains unchanged)
%% - Subject information matching original certificate
%%
%% @param Username The username to use as CN in the CSR
%% @param KeyFile Path to existing private key file
%% @param CertFile Path to existing certificate (to extract subject info)
%% @returns {ok, CsrPem} where CsrPem is the PEM-encoded CSR,
%%          or {error, Reason} on failure
-spec generate_csr(binary(), string(), string()) -> {ok, binary()} | {error, term()}.
generate_csr(Username, KeyFile, CertFile) ->
    try
        %% Read existing certificate to extract subject information
        SubjectName = case file:read_file(CertFile) of
            {ok, CertPem} ->
                [{'Certificate', CertDer, not_encrypted}] = 
                    public_key:pem_decode(CertPem),
                Cert = public_key:pkix_decode_cert(CertDer, otp),
                #'OTPCertificate'{
                    tbsCertificate = #'OTPTBSCertificate'{
                        subject = CertSubject
                    }
                } = Cert,
                %% Extract CN from subject
                case extract_cn_from_subject(CertSubject) of
                    "unknown" -> binary_to_list(Username);
                    CN -> CN
                end;
            {error, _} ->
                %% Fallback to username if cert can't be read
                binary_to_list(Username)
        end,
        
        %% Read private key
        {ok, KeyPem} = file:read_file(KeyFile),
        [KeyEntry] = public_key:pem_decode(KeyPem),
        PrivateKey = public_key:pem_entry_decode(KeyEntry),
        
        %% Build subject as RDN sequence
        %% Subject format: /CN=username
        CsrSubject = {rdnSequence, [
            [#'AttributeTypeAndValue'{
                type = ?'id-at-commonName',
                value = {utf8String, list_to_binary(SubjectName)}
            }]
        ]},
        
        %% Extract public key from private key
        PublicKey = case PrivateKey of
            #'RSAPrivateKey'{modulus = N, publicExponent = E} ->
                #'RSAPublicKey'{modulus = N, publicExponent = E};
            #'ECPrivateKey'{publicKey = PubKey} ->
                PubKey;
            _ ->
                ?error("Unsupported key type: ~p", [element(1, PrivateKey)]),
                throw({error, unsupported_key_type})
        end,
        
        %% Build SubjectPublicKeyInfo
        SubjectPKInfo = case PublicKey of
            #'RSAPublicKey'{} ->
                %% RSA public key
                PubKeyDer = public_key:der_encode('RSAPublicKey', PublicKey),
                #'OTPSubjectPublicKeyInfo'{
                    algorithm = #'PublicKeyAlgorithm'{
                        algorithm = ?'rsaEncryption',
                        parameters = {asn1_OPENTYPE, <<5, 0>>} % NULL
                    },
                    subjectPublicKey = PubKeyDer
                };
            _ ->
                ?error("Unsupported public key type for CSR", []),
                throw({error, unsupported_pubkey_type})
        end,
        
        %% Build CertificationRequestInfo
        CertReqInfo = #'CertificationRequestInfo'{
            version = v1,
            subject = CsrSubject,
            subjectPKInfo = SubjectPKInfo,
            attributes = []  % No extensions
        },
        
        %% Encode and sign the request
        CertReqInfoDer = public_key:der_encode('CertificationRequestInfo', CertReqInfo),
        
        %% Sign with private key
        Signature = case PrivateKey of
            #'RSAPrivateKey'{} ->
                %% SHA256 with RSA
                public_key:sign(CertReqInfoDer, sha256, PrivateKey);
            _ ->
                throw({error, unsupported_signature_algorithm})
        end,
        
        %% Build complete CertificationRequest
        CertReq = #'CertificationRequest'{
            certificationRequestInfo = CertReqInfo,
            signatureAlgorithm = #'CertificationRequest_signatureAlgorithm'{
                algorithm = ?'sha256WithRSAEncryption',
                parameters = {asn1_OPENTYPE, <<5, 0>>} % NULL
            },
            signature = Signature
        },
        
        %% Encode to DER
        CsrDer = public_key:der_encode('CertificationRequest', CertReq),
        
        %% Convert to PEM
        CsrPemEntry = {'CertificationRequest', CsrDer, not_encrypted},
        CsrPem = public_key:pem_encode([CsrPemEntry]),
        
        ?info("CSR generated successfully for ~s", [SubjectName]),
        {ok, CsrPem}
    catch
        throw:{error, Reason} ->
            {error, Reason};
        Class:CatchReason:Stacktrace ->
            ?error("Exception during CSR generation: ~p:~p~n~p",
                  [Class, CatchReason, Stacktrace]),
            {error, {csr_generation_exception, CatchReason}}
    end.

%% @private
%% @doc Extract Common Name from X.509 subject.
-spec extract_cn_from_subject(term()) -> string().
extract_cn_from_subject({rdnSequence, RDNList}) ->
    %% Search for CN attribute in the RDN sequence
    case find_cn_in_rdn(RDNList) of
        {ok, CN} -> CN;
        not_found -> "unknown"
    end;
extract_cn_from_subject(_) ->
    "unknown".

%% @private
%% @doc Find CN attribute in RDN list.
-spec find_cn_in_rdn(list()) -> {ok, string()} | not_found.
find_cn_in_rdn([]) ->
    not_found;
find_cn_in_rdn([RDN | Rest]) ->
    case find_cn_in_attributes(RDN) of
        {ok, CN} -> {ok, CN};
        not_found -> find_cn_in_rdn(Rest)
    end.

%% @private
%% @doc Find CN in attribute list.
-spec find_cn_in_attributes(list()) -> {ok, string()} | not_found.
find_cn_in_attributes([]) ->
    not_found;
find_cn_in_attributes([#'AttributeTypeAndValue'{
    type = ?'id-at-commonName',
    value = {utf8String, CN}
} | _]) ->
    {ok, binary_to_list(CN)};
find_cn_in_attributes([#'AttributeTypeAndValue'{
    type = ?'id-at-commonName',
    value = CN
} | _]) when is_list(CN) ->
    {ok, CN};
find_cn_in_attributes([_ | Rest]) ->
    find_cn_in_attributes(Rest).

%% @private
%% @doc Sign CSR with GPG key using erl_gpg library.
%%
%% This function creates a detached GPG signature over the CSR using the
%% erl_gpg library. The signature proves the CSR was created by the holder
%% of the GPG private key.
%%
%% == GPG Agent Integration ==
%% This function relies on GPG agent for passphrase handling:
%% - First call: GPG agent prompts user for passphrase
%% - Passphrase cached in agent (default: 10 minutes)
%% - Subsequent calls use cached passphrase
%%
%% @param CsrPem The PEM-encoded CSR to sign
%% @param GpgFingerprint The GPG key fingerprint to sign with
%% @returns {ok, SignaturePem} where SignaturePem is the PEM-encoded
%%          detached signature, or {error, Reason} on failure
-spec sign_csr_with_gpg(binary(), binary()) -> {ok, binary()} | {error, term()}.
sign_csr_with_gpg(CsrPem, GpgFingerprint) ->
    try
        %% Use erl_gpg_api to sign (GPG agent handles passphrase)
        KeyID = binary_to_list(GpgFingerprint),
        case erl_gpg_api:sign_detached(CsrPem, KeyID, "") of
            {ok, Result} ->
                %% Extract signature from stdout
                SignaturePem = maps:get(stdout, Result),
                ?info("CSR signed successfully with GPG key ~s", [GpgFingerprint]),
                {ok, SignaturePem};
            {error, Reason} ->
                ?error("Failed to sign CSR with GPG: ~p", [Reason]),
                {error, {gpg_sign_failed, Reason}}
        end
    catch
        Class:CatchReason:Stacktrace ->
            ?error("Exception during GPG signing: ~p:~p~n~p",
                  [Class, CatchReason, Stacktrace]),
            {error, {gpg_sign_exception, CatchReason}}
    end.

%% @private
%% @doc Submit signed CSR to CA REST endpoint.
%%
%% This function POSTs the signed CSR to the CA's REST API endpoint.
%% The CA will verify the GPG signature and issue a new certificate.
%%
%% == Request Format ==
%% POST /ca/v1/csr
%% Content-Type: application/json
%% {
%%   "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
%%   "gpg_fingerprint": "ABC123...",
%%   "gpg_signature_b64": "base64_encoded_signature"
%% }
%%
%% == Response Format ==
%% 200 OK
%% Content-Type: application/json
%% {
%%   "success": true,
%%   "certificate_pem": "-----BEGIN CERTIFICATE-----...",
%%   "valid_until": "2025-11-26T11:45:33Z"
%% }
%%
%% @param ServerHost CA server hostname
%% @param ServerPort CA server port
%% @param CsrPem PEM-encoded CSR
%% @param GpgFingerprint GPG key fingerprint
%% @param GpgSignature PEM-encoded detached GPG signature
%% @returns {ok, CertificatePem} on success, or {error, Reason} on failure
-spec submit_csr_to_ca(binary(), integer(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, term()}.
submit_csr_to_ca(ServerHost, ServerPort, CsrPem, GpgFingerprint, GpgSignature) ->
    try
        %% Build request URL
        Url = io_lib:format("https://~s:~p/ca/v1/csr", 
                           [binary_to_list(ServerHost), ServerPort]),
        
        %% Build JSON request body
        RequestBody = jsx:encode(#{
            <<"csr_pem">> => CsrPem,
            <<"gpg_fingerprint">> => GpgFingerprint,
            <<"gpg_signature_pem">> => GpgSignature
        }),
        
        %% Make HTTPS request
        Headers = [{"Content-Type", "application/json"}],
        
        ?info("Submitting CSR to CA: ~s", [Url]),
        
        case httpc:request(post, {Url, Headers, "application/json", RequestBody}, 
                          [{ssl, [{verify, verify_none}]}], []) of
            {ok, {{_, 200, _}, _ResponseHeaders, ResponseBody}} ->
                %% Parse JSON response
                Response = jsx:decode(list_to_binary(ResponseBody), [return_maps]),
                
                case maps:get(<<"success">>, Response, false) of
                    true ->
                        CertPem = maps:get(<<"certificate_pem">>, Response),
                        ValidUntil = maps:get(<<"valid_until">>, Response, <<"unknown">>),
                        ?info("New certificate issued, valid until: ~s", [ValidUntil]),
                        {ok, CertPem};
                    false ->
                        ErrorMsg = maps:get(<<"error">>, Response, <<"unknown error">>),
                        ?error("CA rejected CSR: ~s", [ErrorMsg]),
                        {error, {ca_rejected, ErrorMsg}}
                end;
            
            {ok, {{_, StatusCode, _}, _ResponseHeaders, ResponseBody}} ->
                ?error("CA returned error ~p: ~s", [StatusCode, ResponseBody]),
                {error, {http_error, StatusCode, ResponseBody}};
            
            {error, HttpReason} ->
                ?error("HTTP request to CA failed: ~p", [HttpReason]),
                {error, {http_request_failed, HttpReason}}
        end
    catch
        Class:CatchReason:Stacktrace ->
            ?error("Exception during CA submission: ~p:~p~n~p",
                  [Class, CatchReason, Stacktrace]),
            {error, {ca_submission_exception, CatchReason}}
    end.

%% @private
%% @doc Install new certificate, backing up the old one.
%%
%% This function:
%% 1. Creates backup of existing certificate
%% 2. Writes new certificate to disk
%% 3. Updates file permissions
%% 4. Validates the new certificate
%%
%% @param NewCertPem PEM-encoded new certificate
%% @param CertFile Path to certificate file
%% @returns ok on success, or {error, Reason} on failure
-spec install_new_certificate(binary(), string()) -> ok | {error, term()}.
install_new_certificate(NewCertPem, CertFile) ->
    try
        %% Create backup of existing certificate
        Timestamp = integer_to_list(erlang:system_time(second)),
        BackupFile = CertFile ++ ".backup." ++ Timestamp,
        
        case file:read_file(CertFile) of
            {ok, OldCertPem} ->
                ok = file:write_file(BackupFile, OldCertPem),
                ?info("Backed up old certificate to ~s", [BackupFile]);
            {error, enoent} ->
                ?info("No existing certificate to backup", [])
        end,
        
        %% Write new certificate
        ok = file:write_file(CertFile, NewCertPem),
        ?info("New certificate installed: ~s", [CertFile]),
        
        %% Set proper permissions (readable by user only)
        ok = file:change_mode(CertFile, 8#600),
        
        %% Validate the new certificate
        case parse_certificate(CertFile) of
            {ok, IssuedAt, ExpiresAt} ->
                Now = erlang:system_time(second),
                if
                    Now < IssuedAt ->
                        ?warning("New certificate not yet valid (future dated)", []),
                        ok;
                    Now >= ExpiresAt ->
                        ?error("New certificate is already expired!", []),
                        {error, certificate_expired};
                    true ->
                        DaysValid = (ExpiresAt - Now) div 86400,
                        ?info("New certificate valid for ~p days", [DaysValid]),
                        ok
                end;
            {error, ParseReason} ->
                ?error("Failed to parse new certificate: ~p", [ParseReason]),
                {error, {parse_new_cert_failed, ParseReason}}
        end
    catch
        Class:CatchReason:Stacktrace ->
            ?error("Exception during certificate installation: ~p:~p~n~p",
                  [Class, CatchReason, Stacktrace]),
            {error, {install_exception, CatchReason}}
    end.

%% @private
%% @doc Trigger WebSocket client to reconnect with new certificate.
%%
%% This function notifies the WebSocket client that a new certificate
%% has been installed and it should gracefully disconnect and reconnect.
%%
%% @param WsClientPid PID of the WebSocket client gen_server
%% @returns ok on success, or {error, Reason} on failure
-spec trigger_websocket_reconnect(pid() | undefined) -> ok | {error, term()}.
trigger_websocket_reconnect(undefined) ->
    ?warning("No WebSocket client PID available, cannot trigger reconnect", []),
    {error, no_ws_client_pid};
trigger_websocket_reconnect(WsClientPid) ->
    try
        %% Trigger certificate reload and reconnection
        %% The new certificate has already been saved to disk by install_new_certificate/2
        %% The WebSocket client will gracefully close, re-read the certificate, and reconnect
        case is_process_alive(WsClientPid) of
            true ->
                ok = cryptic_ws_client:reload_certificate_and_reconnect(WsClientPid),
                ?info("Triggered WebSocket certificate reload and reconnection", []),
                ok;
            false ->
                ?error("WebSocket client process is dead", []),
                {error, ws_client_dead}
        end
    catch
        Class:Reason:Stacktrace ->
            ?error("Exception during WebSocket reconnect trigger: ~p:~p~n~p",
                  [Class, Reason, Stacktrace]),
            {error, {reconnect_trigger_exception, Reason}}
    end.
