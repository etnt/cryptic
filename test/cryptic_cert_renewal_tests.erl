%%%-------------------------------------------------------------------
%%% @doc Unit tests for cryptic_cert_renewal module
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_cert_renewal_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%%%===================================================================
%%% Test Setup
%%%===================================================================

setup() ->
    %% Start event manager (required by logging macros)
    case whereis(cryptic_event_manager) of
        undefined ->
            gen_event:start_link({local, cryptic_event_manager});
        _ ->
            ok
    end,

    %% Start required applications
    application:ensure_all_started(asn1),
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),

    %% Create temporary test directory
    TestDir = "/tmp/cryptic_cert_renewal_test_" ++ 
              integer_to_list(erlang:system_time(millisecond)),
    ok = file:make_dir(TestDir),
    
    TestDir.

cleanup(TestDir) ->
    %% Clean up test directory
    os:cmd("rm -rf " ++ TestDir),
    ok.

%%%===================================================================
%%% Certificate Time Conversion Tests
%%%===================================================================

time_conversion_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_) -> [
         ?_test(test_utc_time_parsing()),
         ?_test(test_general_time_parsing()),
         ?_test(test_datetime_to_unix()),
         ?_test(test_utc_time_year_conversion())
     ]
     end}.

test_utc_time_parsing() ->
    %% Test utcTime format: "YYMMDDHHMMSSZ"
    
    %% Test date: November 19, 2025, 11:45:30 UTC
    %% 2025 → YY = 25 (2000 + 25)
    TimeStr1 = "251119114530Z",
    Result1 = cryptic_cert_renewal:validity_time_to_unix({utcTime, TimeStr1}),
    
    %% Verify it's a reasonable Unix timestamp (after 2025)
    ExpectedMin = datetime_to_unix({{2025, 11, 19}, {11, 45, 30}}),
    ?assertEqual(ExpectedMin, Result1),
    
    %% Test date in 1990s: "991231235959Z" (December 31, 1999)
    %% 99 → 1999 (1900 + 99)
    TimeStr2 = "991231235959Z",
    Result2 = cryptic_cert_renewal:validity_time_to_unix({utcTime, TimeStr2}),
    Expected2 = datetime_to_unix({{1999, 12, 31}, {23, 59, 59}}),
    ?assertEqual(Expected2, Result2),
    
    %% Test date in 2000s: "000101000000Z" (January 1, 2000)
    %% 00 → 2000 (2000 + 0)
    TimeStr3 = "000101000000Z",
    Result3 = cryptic_cert_renewal:validity_time_to_unix({utcTime, TimeStr3}),
    Expected3 = datetime_to_unix({{2000, 1, 1}, {0, 0, 0}}),
    ?assertEqual(Expected3, Result3),
    
    ok.

test_general_time_parsing() ->
    %% Test generalTime format: "YYYYMMDDHHMMSSZ"
    
    %% Test date: November 19, 2025, 11:45:30 UTC
    TimeStr1 = "20251119114530Z",
    Result1 = cryptic_cert_renewal:validity_time_to_unix({generalTime, TimeStr1}),
    Expected1 = datetime_to_unix({{2025, 11, 19}, {11, 45, 30}}),
    ?assertEqual(Expected1, Result1),
    
    %% Test date: December 31, 2099, 23:59:59 UTC
    TimeStr2 = "20991231235959Z",
    Result2 = cryptic_cert_renewal:validity_time_to_unix({generalTime, TimeStr2}),
    Expected2 = datetime_to_unix({{2099, 12, 31}, {23, 59, 59}}),
    ?assertEqual(Expected2, Result2),
    
    ok.

test_datetime_to_unix() ->
    %% Test conversion of known datetimes to Unix timestamps
    
    %% Unix epoch: January 1, 1970, 00:00:00 UTC → 0
    ?assertEqual(0, datetime_to_unix({{1970, 1, 1}, {0, 0, 0}})),
    
    %% January 1, 2000, 00:00:00 UTC → 946684800
    ?assertEqual(946684800, datetime_to_unix({{2000, 1, 1}, {0, 0, 0}})),
    
    %% January 1, 2020, 00:00:00 UTC → 1577836800
    ?assertEqual(1577836800, datetime_to_unix({{2020, 1, 1}, {0, 0, 0}})),
    
    ok.

test_utc_time_year_conversion() ->
    %% Test the 2-digit year conversion rules:
    %% 00-49 → 2000-2049
    %% 50-99 → 1950-1999
    
    %% Year 00 → 2000
    Time00 = "000101000000Z",
    Result00 = cryptic_cert_renewal:validity_time_to_unix({utcTime, Time00}),
    Expected00 = datetime_to_unix({{2000, 1, 1}, {0, 0, 0}}),
    ?assertEqual(Expected00, Result00),
    
    %% Year 49 → 2049
    Time49 = "491231235959Z",
    Result49 = cryptic_cert_renewal:validity_time_to_unix({utcTime, Time49}),
    Expected49 = datetime_to_unix({{2049, 12, 31}, {23, 59, 59}}),
    ?assertEqual(Expected49, Result49),
    
    %% Year 50 → 1950
    Time50 = "500101000000Z",
    Result50 = cryptic_cert_renewal:validity_time_to_unix({utcTime, Time50}),
    Expected50 = datetime_to_unix({{1950, 1, 1}, {0, 0, 0}}),
    ?assertEqual(Expected50, Result50),
    
    %% Year 99 → 1999
    Time99 = "991231235959Z",
    Result99 = cryptic_cert_renewal:validity_time_to_unix({utcTime, Time99}),
    Expected99 = datetime_to_unix({{1999, 12, 31}, {23, 59, 59}}),
    ?assertEqual(Expected99, Result99),
    
    ok.

%%%===================================================================
%%% Renewal Time Calculation Tests
%%%===================================================================

renewal_calculation_test_() ->
    [
        ?_test(test_renewal_time_25_percent()),
        ?_test(test_renewal_time_10_percent()),
        ?_test(test_renewal_time_50_percent()),
        ?_test(test_renewal_time_edge_cases())
    ].

test_renewal_time_25_percent() ->
    %% Test default 25% threshold (renew at 75% of lifespan)
    
    %% 7-day certificate (604800 seconds)
    %% Issued: Jan 1, 2025, 00:00:00
    %% Expires: Jan 8, 2025, 00:00:00
    IssuedAt = datetime_to_unix({{2025, 1, 1}, {0, 0, 0}}),
    ExpiresAt = datetime_to_unix({{2025, 1, 8}, {0, 0, 0}}),
    Threshold = 0.25,
    
    RenewalTime = cryptic_cert_renewal:calculate_renewal_time(
        IssuedAt, ExpiresAt, Threshold
    ),
    
    %% Should renew after 75% of 7 days = 5.25 days = 453600 seconds
    Expected = IssuedAt + 453600,
    ?assertEqual(Expected, RenewalTime),
    
    %% Verify it's between issued and expiry
    ?assert(RenewalTime > IssuedAt),
    ?assert(RenewalTime < ExpiresAt),
    
    ok.

test_renewal_time_10_percent() ->
    %% Test 10% threshold (renew at 90% of lifespan)
    
    %% 30-day certificate
    IssuedAt = datetime_to_unix({{2025, 1, 1}, {0, 0, 0}}),
    ExpiresAt = datetime_to_unix({{2025, 1, 31}, {0, 0, 0}}),
    Threshold = 0.10,
    
    RenewalTime = cryptic_cert_renewal:calculate_renewal_time(
        IssuedAt, ExpiresAt, Threshold
    ),
    
    %% 30 days = 2592000 seconds
    %% Renew after 90% = 2332800 seconds
    Lifespan = ExpiresAt - IssuedAt,
    Expected = IssuedAt + trunc(Lifespan * 0.9),
    ?assertEqual(Expected, RenewalTime),
    
    ok.

test_renewal_time_50_percent() ->
    %% Test 50% threshold (renew at halfway point)
    
    IssuedAt = datetime_to_unix({{2025, 1, 1}, {0, 0, 0}}),
    ExpiresAt = datetime_to_unix({{2025, 1, 15}, {0, 0, 0}}),
    Threshold = 0.50,
    
    RenewalTime = cryptic_cert_renewal:calculate_renewal_time(
        IssuedAt, ExpiresAt, Threshold
    ),
    
    %% 14 days = 1209600 seconds
    %% Renew after 50% = 604800 seconds (7 days)
    Lifespan = ExpiresAt - IssuedAt,
    Expected = IssuedAt + (Lifespan div 2),
    ?assertEqual(Expected, RenewalTime),
    
    ok.

test_renewal_time_edge_cases() ->
    %% Test with 1-hour certificate
    Now = erlang:system_time(second),
    OneHourLater = Now + 3600,
    Threshold = 0.25,
    
    RenewalTime = cryptic_cert_renewal:calculate_renewal_time(
        Now, OneHourLater, Threshold
    ),
    
    %% Should renew after 45 minutes (2700 seconds)
    Expected = Now + 2700,
    ?assertEqual(Expected, RenewalTime),
    
    ok.

%%%===================================================================
%%% Certificate Parsing Tests
%%%===================================================================

certificate_parsing_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(TestDir) -> [
         ?_test(test_parse_valid_certificate(TestDir)),
         ?_test(test_parse_missing_certificate(TestDir)),
         ?_test(test_parse_invalid_certificate(TestDir))
     ]
     end}.

test_parse_valid_certificate(TestDir) ->
    %% Create a test certificate using OpenSSL
    CertFile = TestDir ++ "/test_cert.pem",
    KeyFile = TestDir ++ "/test_key.pem",
    
    %% Generate self-signed certificate valid for 7 days
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -nodes "
        "-keyout ~s -out ~s -days 7 "
        "-subj '/CN=test.cryptic.local' 2>/dev/null",
        [KeyFile, CertFile]
    ),
    os:cmd(Cmd),
    
    %% Parse the certificate
    case cryptic_cert_renewal:parse_certificate(CertFile) of
        {ok, IssuedAt, ExpiresAt} ->
            %% Verify IssuedAt is around now
            Now = erlang:system_time(second),
            ?assert(abs(IssuedAt - Now) < 60), % Within 1 minute
            
            %% Verify ExpiresAt is about 7 days later
            SevenDays = 7 * 24 * 3600,
            Diff = ExpiresAt - IssuedAt,
            ?assert(abs(Diff - SevenDays) < 60), % Within 1 minute
            
            ok;
        {error, Reason} ->
            ?assert(false, io_lib:format("Certificate parsing failed: ~p", [Reason]))
    end.

test_parse_missing_certificate(_TestDir) ->
    %% Try to parse non-existent certificate
    Result = cryptic_cert_renewal:parse_certificate("/nonexistent/cert.pem"),
    ?assertMatch({error, {read_failed, _}}, Result),
    ok.

test_parse_invalid_certificate(TestDir) ->
    %% Create file with invalid PEM content
    InvalidCertFile = TestDir ++ "/invalid_cert.pem",
    ok = file:write_file(InvalidCertFile, "This is not a valid certificate\n"),
    
    %% Try to parse it
    Result = cryptic_cert_renewal:parse_certificate(InvalidCertFile),
    ?assertMatch({error, {parse_failed, _, _}}, Result),
    ok.

%%%===================================================================
%%% Gen_server API Tests
%%%===================================================================

gen_server_api_test_() ->
    {setup,
     fun setup_gen_server/0,
     fun cleanup_gen_server/1,
     fun(State) -> {inparallel, [
         ?_test(test_get_status(State)),
         ?_test(test_enable_disable(State)),
         ?_test(test_check_now(State))
     ]}
     end}.

setup_gen_server() ->
    setup(),
    
    %% Start event bus (required by cryptic_cert_renewal)
    case whereis(cryptic_event_bus) of
        undefined ->
            {ok, _BusPid} = cryptic_event_bus:start_link();
        _ ->
            ok
    end,
    
    %% Create test certificate
    TestDir = "/tmp/cryptic_renewal_gen_server_test_" ++ 
              integer_to_list(erlang:system_time(millisecond)),
    ok = file:make_dir(TestDir),
    
    CertFile = TestDir ++ "/test_cert.pem",
    KeyFile = TestDir ++ "/test_key.pem",
    
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -nodes "
        "-keyout ~s -out ~s -days 7 "
        "-subj '/CN=test.cryptic.local' 2>/dev/null",
        [KeyFile, CertFile]
    ),
    os:cmd(Cmd),
    
    %% Start cryptic_cert_renewal gen_server
    Config = #{
        username => <<"test_user">>,
        server_host => <<"localhost">>,
        server_port => 8443,
        cert_file => CertFile,
        key_file => KeyFile,
        ca_file => "/tmp/ca.crt",
        gpg_fingerprint => <<"1234567890ABCDEF">>,
        gpg_email => <<"test@cryptic.local">>,
        renewal_threshold => 0.25,
        check_interval => 3600,
        max_retries => 5,
        retry_interval => 300,
        auto_renewal_enabled => true
    },
    
    {ok, Pid} = cryptic_cert_renewal:start_link(Config),
    
    #{pid => Pid, test_dir => TestDir}.

cleanup_gen_server(#{pid := Pid, test_dir := TestDir}) ->
    %% Stop gen_server
    catch gen_server:stop(Pid),
    
    %% Clean up
    os:cmd("rm -rf " ++ TestDir),
    ok.

test_get_status(#{pid := _Pid}) ->
    %% Get status from running gen_server
    Status = cryptic_cert_renewal:get_status(),
    
    %% Verify status map structure
    ?assertMatch(#{
        username := _,
        server_host := _,
        server_port := _,
        cert_expires_at := _,
        cert_issued_at := _,
        renewal_trigger_time := _,
        renewal_in_progress := _,
        enabled := _
    }, Status),
    
    %% Verify types
    ?assert(is_binary(maps:get(username, Status))),
    ?assert(is_integer(maps:get(cert_expires_at, Status))),
    ?assert(is_boolean(maps:get(enabled, Status))),
    
    ok.

test_enable_disable(#{pid := _Pid}) ->
    %% Test enable/disable API
    
    %% Disable auto-renewal
    ok = cryptic_cert_renewal:disable(),
    Status1 = cryptic_cert_renewal:get_status(),
    ?assertEqual(false, maps:get(enabled, Status1)),
    
    %% Enable auto-renewal
    ok = cryptic_cert_renewal:enable(),
    Status2 = cryptic_cert_renewal:get_status(),
    ?assertEqual(true, maps:get(enabled, Status2)),
    
    ok.

test_check_now(#{pid := _Pid}) ->
    %% Test manual renewal check
    Result = cryptic_cert_renewal:check_now(),
    ?assertEqual(ok, Result),
    
    %% Status should still be accessible
    Status = cryptic_cert_renewal:get_status(),
    ?assertMatch(#{username := _}, Status),
    
    ok.

%%%===================================================================
%%% Helper Functions
%%%===================================================================

%% @private
%% @doc Convert Erlang datetime to Unix timestamp (matches implementation).
datetime_to_unix(DateTime) ->
    EpochSeconds = calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}}),
    calendar:datetime_to_gregorian_seconds(DateTime) - EpochSeconds.
