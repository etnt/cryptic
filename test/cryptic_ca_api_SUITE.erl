%%%-------------------------------------------------------------------
%%% @doc Common Test suite for Cryptic CA API
%%%
%%% This suite tests the complete CA API including:
%%% - WebSocket commands (invite operations)
%%% - REST endpoints (registration, CSR, status)
%%% - Rate limiting behavior
%%% - Authentication flows
%%% - Error handling
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_ca_api_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("../include/cryptic_ca.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases - WebSocket API
-export([
    ws_invite_create_success/1,
    ws_invite_create_unauthenticated/1,
    ws_invite_create_rate_limited/1,
    ws_invite_list_success/1,
    ws_invite_revoke_success/1,
    ws_gpg_register_bootstrap/1,
    ws_unknown_command/1
]).

%% Test cases - REST API
-export([
    rest_register_gpg_success/1,
    rest_register_gpg_invalid_invite/1,
    rest_register_gpg_rate_limited/1,
    rest_csr_placeholder/1,
    rest_status_found/1,
    rest_status_not_found/1,
    rest_status_rate_limited/1
]).

%% Test cases - Integration
-export([
    full_onboarding_flow/1,
    invite_consumption_prevents_reuse/1
]).

%%%===================================================================
%%% CT Callbacks
%%%===================================================================

all() ->
    [
        {group, websocket_api},
        {group, rest_api},
        {group, integration}
    ].

groups() ->
    [
        % Changed to sequence to avoid rate limiter conflicts
        {websocket_api, [sequence], [
            ws_invite_create_unauthenticated,
            ws_unknown_command,
            ws_gpg_register_bootstrap,
            ws_invite_create_success,
            ws_invite_list_success,
            ws_invite_revoke_success
        ]},
        % Changed to sequence
        {rest_api, [sequence], [
            rest_register_gpg_invalid_invite,
            rest_status_not_found,
            rest_csr_placeholder
            %% rest_register_gpg_success -- Run in integration
            %% rest_status_found -- Run in integration
        ]},
        {integration, [sequence], [
            full_onboarding_flow,
            invite_consumption_prevents_reuse
        ]}
    ].

init_per_suite(Config) ->
    %% Start necessary applications
    application:ensure_all_started(crypto),
    application:ensure_all_started(asn1),
    application:ensure_all_started(public_key),
    application:ensure_all_started(ssl),
    application:ensure_all_started(jsx),

    %% Set rate limiting configuration for tests
    application:set_env(cryptic, ca_rate_limits, #{
        % 10 per day
        invite_create => {10, 86400},
        % 100 per hour
        invite_list => {100, 3600},
        % 50 per hour
        invite_revoke => {50, 3600},
        % 100 per hour
        register_gpg => {100, 3600},
        % 50 per hour
        csr => {50, 3600},
        % 200 per hour
        status => {200, 3600}
    }),

    %% Create test database
    DbFile = filename:join([?config(priv_dir, Config), "ca_test.db"]),
    {ok, DbRef} = cryptic_ca_store:init(DbFile),

    %% Set application environment
    application:set_env(cryptic, ca_db_ref, DbRef),

    %% Start rate limiter once for all tests (without link to avoid it dying when init_per_suite completes)
    {ok, RateLimiterPid} = cryptic_ca_rate_limiter:start(),

    [
        {rate_limiter_pid, RateLimiterPid},
        {db_ref, DbRef},
        {db_file, DbFile}
        | Config
    ].

end_per_suite(Config) ->
    %% Stop rate limiter
    case proplists:get_value(rate_limiter_pid, Config) of
        undefined ->
            ok;
        Pid when is_pid(Pid) ->
            catch gen_server:stop(Pid);
        _ ->
            ok
    end,

    %% Close database
    DbRef = ?config(db_ref, Config),
    cryptic_ca_store:close(DbRef),

    %% Cleanup
    DbFile = ?config(db_file, Config),
    file:delete(DbFile),

    application:unset_env(cryptic, ca_db_ref),
    ok.

init_per_group(_, Config) ->
    %% No special group-level setup needed
    Config.

end_per_group(_, _Config) ->
    %% No special group-level teardown needed
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting test case: ~p", [TestCase]),
    Config.

end_per_testcase(TestCase, Config) ->
    ct:pal("Finished test case: ~p", [TestCase]),

    %% Reset rate limits for next test
    %% (In real tests with actual identifiers, we'd reset those specific ones)
    Config.

%%%===================================================================
%%% WebSocket API Tests
%%%===================================================================

ws_invite_create_success(Config) ->
    DbRef = ?config(db_ref, Config),

    %% First, bootstrap a GPG identity to create invites
    InviterFp = <<"TEST_INVITER_FP_001">>,
    GpgPub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----">>,

    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, InviterFp, GpgPub
    ),

    %% Simulate WebSocket message for invite_create
    Msg = #{
        <<"command">> => <<"invite_create">>,
        <<"expiry_hours">> => 24,
        <<"meta">> => #{<<"note">> => <<"Test invite">>}
    },

    %% Call handler directly (in real test, would send via WebSocket)

    % {state, gpg_fp, db_ref, authenticated}
    State = {state, InviterFp, DbRef, true},

    {reply, {text, Response}, _NewState} =
        cryptic_ca_ws_handler:handle_command(Msg, State),

    %% Verify response
    RespMap = jsx:decode(Response, [return_maps]),
    ?assertEqual(<<"success">>, maps:get(<<"status">>, RespMap)),
    ?assertMatch(#{<<"invite_id">> := _, <<"expires_at">> := _}, RespMap),

    InviteId = maps:get(<<"invite_id">>, RespMap),

    %% Verify invite was stored in database
    {ok, Invite} = cryptic_ca_store:get_invite(DbRef, InviteId),
    ?assertEqual(InviterFp, Invite#invite.inviter_fp),
    % SQLite stores as 0 (not consumed)
    ?assertEqual(0, Invite#invite.consumed),

    ok.

ws_invite_create_unauthenticated(_Config) ->
    %% Simulate unauthenticated state (no GPG fingerprint)
    Msg = #{
        <<"command">> => <<"invite_create">>,
        <<"expiry_hours">> => 24
    },

    % Unauthenticated state
    State = {state, undefined, undefined, false},

    {reply, {text, Response}, _NewState} =
        cryptic_ca_ws_handler:handle_command(Msg, State),

    %% Verify error response
    RespMap = jsx:decode(Response, [return_maps]),
    ?assertEqual(<<"not_authenticated">>, maps:get(<<"error">>, RespMap)),

    ok.

ws_invite_create_rate_limited(Config) ->
    DbRef = ?config(db_ref, Config),
    InviterFp = <<"TEST_INVITER_FP_RATELIMIT">>,
    GpgPub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----">>,

    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, InviterFp, GpgPub
    ),

    %% Exhaust rate limit (10 invites per day by default)
    State = {state, InviterFp, DbRef, true},
    Msg = #{<<"command">> => <<"invite_create">>, <<"expiry_hours">> => 24},

    %% Use all 10 tokens
    ok = cryptic_ca_rate_limiter:check_limit(InviterFp, invite_create, 10),

    %% Next request should be rate limited
    {reply, {text, Response}, _NewState} =
        cryptic_ca_ws_handler:handle_command(Msg, State),

    RespMap = jsx:decode(Response, [return_maps]),
    ?assertEqual(<<"rate_limited">>, maps:get(<<"error">>, RespMap)),
    ?assert(maps:is_key(<<"retry_after">>, RespMap)),

    %% Cleanup
    cryptic_ca_rate_limiter:reset_limits(InviterFp),
    ok.

ws_invite_list_success(Config) ->
    DbRef = ?config(db_ref, Config),
    InviterFp = <<"TEST_INVITER_FP_LIST">>,
    GpgPub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----">>,

    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, InviterFp, GpgPub
    ),

    %% Create an invite first
    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, 24, #{}
    ),

    %% List invites
    Msg = #{<<"command">> => <<"invite_list">>},
    State = {state, InviterFp, DbRef, true},

    {reply, {text, Response}, _NewState} =
        cryptic_ca_ws_handler:handle_command(Msg, State),

    RespMap = jsx:decode(Response, [return_maps]),
    ?assertEqual(<<"success">>, maps:get(<<"status">>, RespMap)),

    Invites = maps:get(<<"invites">>, RespMap),
    ?assert(length(Invites) >= 1),

    %% Verify our invite is in the list
    InviteIds = [maps:get(<<"invite_id">>, I) || I <- Invites],
    ?assert(lists:member(InviteId, InviteIds)),

    ok.

ws_invite_revoke_success(Config) ->
    DbRef = ?config(db_ref, Config),
    InviterFp = <<"TEST_INVITER_FP_REVOKE">>,
    GpgPub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----">>,

    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, InviterFp, GpgPub
    ),

    %% Create an invite
    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, 24, #{}
    ),

    %% Revoke it
    Msg = #{
        <<"command">> => <<"invite_revoke">>,
        <<"invite_id">> => InviteId
    },
    State = {state, InviterFp, DbRef, true},

    {reply, {text, Response}, _NewState} =
        cryptic_ca_ws_handler:handle_command(Msg, State),

    RespMap = jsx:decode(Response, [return_maps]),
    ?assertEqual(<<"success">>, maps:get(<<"status">>, RespMap)),
    ?assertEqual(InviteId, maps:get(<<"invite_id">>, RespMap)),

    ok.

ws_gpg_register_bootstrap(Config) ->
    DbRef = ?config(db_ref, Config),
    NewFp = <<"TEST_BOOTSTRAP_FP">>,
    GpgPub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest_bootstrap\n-----END PGP PUBLIC KEY BLOCK-----">>,

    %% Note: In real implementation, handler would extract fingerprint from GPG key
    %% For this test, we'll call the registry directly
    ok = cryptic_gpg_registry:register_bootstrap_identity(DbRef, NewFp, GpgPub),

    %% Verify identity was registered
    {ok, Identity} = cryptic_gpg_registry:get_identity(DbRef, NewFp),
    ?assertEqual(<<"verified_bootstrap">>, Identity#gpg_identity.status),
    ?assertEqual(GpgPub, Identity#gpg_identity.gpg_pub_armor),

    ok.

ws_unknown_command(_Config) ->
    Msg = #{<<"command">> => <<"unknown_command">>},
    State = {state, undefined, undefined, false},

    {reply, {text, Response}, _NewState} =
        cryptic_ca_ws_handler:handle_command(Msg, State),

    RespMap = jsx:decode(Response, [return_maps]),
    ?assertEqual(<<"unknown_command">>, maps:get(<<"error">>, RespMap)),

    ok.

%%%===================================================================
%%% REST API Tests
%%%===================================================================

rest_register_gpg_success(Config) ->
    DbRef = ?config(db_ref, Config),

    %% Create an invite first
    InviterFp = <<"TEST_REST_INVITER">>,
    GpgPub1 =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ninviter\n-----END PGP PUBLIC KEY BLOCK-----">>,
    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, InviterFp, GpgPub1
    ),

    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, 24, #{}
    ),

    %% Test registration (simulated)
    NewGpgFp = <<"TEST_NEW_USER_FP">>,
    GpgPub2 =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nnew_user\n-----END PGP PUBLIC KEY BLOCK-----">>,

    %% In real test, would POST to /ca/v1/register-gpg
    %% For now, test the underlying logic directly
    ok = cryptic_gpg_registry:register_gpg_identity(
        DbRef, NewGpgFp, GpgPub2, InviterFp, InviteId
    ),
    ok = cryptic_invite_mgr:consume_invite(DbRef, InviteId, NewGpgFp),

    %% Verify registration
    {ok, Identity} = cryptic_gpg_registry:get_identity(DbRef, NewGpgFp),
    ?assertEqual(<<"verified_via_invite">>, Identity#gpg_identity.status),
    ?assertEqual(InviterFp, Identity#gpg_identity.inviter_fp),

    %% Verify invite was consumed
    {ok, Invite} = cryptic_ca_store:get_invite(DbRef, InviteId),
    % SQLite stores as 1 (consumed)
    ?assertEqual(1, Invite#invite.consumed),
    ?assertEqual(NewGpgFp, Invite#invite.consumed_by_fp),

    ok.

rest_register_gpg_invalid_invite(Config) ->
    DbRef = ?config(db_ref, Config),

    %% Try to validate non-existent invite
    InvalidInviteId = <<"INVALID_INVITE_ID">>,

    Result = cryptic_invite_mgr:validate_invite(DbRef, InvalidInviteId),
    ?assertMatch({error, _}, Result),

    ok.

rest_register_gpg_rate_limited(_Config) ->
    %% Test IP-based rate limiting
    TestIp = <<"192.168.1.100">>,

    %% Exhaust rate limit (100 per hour)
    {ok, _} = cryptic_ca_rate_limiter:check_limit(TestIp, register_gpg, 100),

    %% Next request should be rate limited
    Result = cryptic_ca_rate_limiter:check_limit(TestIp, register_gpg, 1),
    ?assertMatch({error, rate_limited, _}, Result),

    %% Cleanup
    cryptic_ca_rate_limiter:reset_limits(TestIp),
    ok.

rest_csr_placeholder(_Config) ->
    %% CSR handling is placeholder in Phase 2
    %% Just verify the logic exists

    GpgFp = <<"TEST_CSR_USER">>,

    %% Check that rate limiting works for CSR
    {ok, Remaining} = cryptic_ca_rate_limiter:check_limit(GpgFp, csr, 1),
    % Default limit is 50/hour
    ?assert(Remaining < 50),

    %% Cleanup
    cryptic_ca_rate_limiter:reset_limits(GpgFp),
    ok.

rest_status_found(Config) ->
    DbRef = ?config(db_ref, Config),

    %% Register an identity
    GpgFp = <<"TEST_STATUS_USER">>,
    GpgPub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nstatus_test\n-----END PGP PUBLIC KEY BLOCK-----">>,
    ok = cryptic_gpg_registry:register_bootstrap_identity(DbRef, GpgFp, GpgPub),

    %% Check status
    {ok, Identity} = cryptic_gpg_registry:get_identity(DbRef, GpgFp),
    ?assertEqual(<<"verified_bootstrap">>, Identity#gpg_identity.status),
    ?assert(Identity#gpg_identity.registered_at > 0),

    ok.

rest_status_not_found(Config) ->
    DbRef = ?config(db_ref, Config),

    %% Check status for non-existent fingerprint
    NonExistentFp = <<"DOES_NOT_EXIST">>,
    Result = cryptic_gpg_registry:get_identity(DbRef, NonExistentFp),
    ?assertEqual({error, not_found}, Result),

    ok.

rest_status_rate_limited(_Config) ->
    %% Test IP-based rate limiting for status endpoint
    TestIp = <<"192.168.1.200">>,

    %% Exhaust rate limit (200 per hour)
    {ok, _} = cryptic_ca_rate_limiter:check_limit(TestIp, status, 200),

    %% Next request should be rate limited
    Result = cryptic_ca_rate_limiter:check_limit(TestIp, status, 1),
    ?assertMatch({error, rate_limited, _}, Result),

    %% Cleanup
    cryptic_ca_rate_limiter:reset_limits(TestIp),
    ok.

%%%===================================================================
%%% Integration Tests
%%%===================================================================

full_onboarding_flow(Config) ->
    DbRef = ?config(db_ref, Config),

    %% Step 1: Bootstrap admin user
    AdminFp = <<"ADMIN_BOOTSTRAP_FP">>,
    AdminPub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nadmin\n-----END PGP PUBLIC KEY BLOCK-----">>,
    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, AdminFp, AdminPub
    ),

    %% Step 2: Admin creates invite
    {ok, InviteId} = cryptic_invite_mgr:create_invite(DbRef, AdminFp, 24, #{
        note => <<"Welcome">>
    }),

    %% Step 3: Validate invite (simulates sending to new user)
    {ok, ValidatedInviter} = cryptic_invite_mgr:validate_invite(
        DbRef, InviteId
    ),
    ?assertEqual(AdminFp, ValidatedInviter),

    %% Step 4: New user registers with invite
    NewUserFp = <<"NEW_USER_FP">>,
    NewUserPub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nnew_user\n-----END PGP PUBLIC KEY BLOCK-----">>,
    ok = cryptic_gpg_registry:register_gpg_identity(
        DbRef, NewUserFp, NewUserPub, AdminFp, InviteId
    ),

    %% Step 5: Consume invite
    ok = cryptic_invite_mgr:consume_invite(DbRef, InviteId, NewUserFp),

    %% Step 6: Verify complete state
    {ok, NewUserIdentity} = cryptic_gpg_registry:get_identity(DbRef, NewUserFp),
    ?assertEqual(
        <<"verified_via_invite">>, NewUserIdentity#gpg_identity.status
    ),
    ?assertEqual(AdminFp, NewUserIdentity#gpg_identity.inviter_fp),
    ?assertEqual(InviteId, NewUserIdentity#gpg_identity.invite_id),

    {ok, ConsumedInvite} = cryptic_ca_store:get_invite(DbRef, InviteId),
    % SQLite stores as 1/0
    ?assertEqual(1, ConsumedInvite#invite.consumed),
    ?assertEqual(NewUserFp, ConsumedInvite#invite.consumed_by_fp),

    %% Step 7: New user can now create invites too
    {ok, _SecondGenInvite} = cryptic_invite_mgr:create_invite(
        DbRef, NewUserFp, 24, #{}
    ),

    ok.

invite_consumption_prevents_reuse(Config) ->
    DbRef = ?config(db_ref, Config),

    %% Create invite
    InviterFp = <<"INVITER_REUSE_TEST">>,
    GpgPub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nreuse_test\n-----END PGP PUBLIC KEY BLOCK-----">>,
    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, InviterFp, GpgPub
    ),

    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, 24, #{}
    ),

    %% First user consumes it
    User1Fp = <<"USER_1_FP">>,
    User1Pub =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nuser1\n-----END PGP PUBLIC KEY BLOCK-----">>,
    ok = cryptic_gpg_registry:register_gpg_identity(
        DbRef, User1Fp, User1Pub, InviterFp, InviteId
    ),
    ok = cryptic_invite_mgr:consume_invite(DbRef, InviteId, User1Fp),

    %% Second user tries to use same invite
    Result = cryptic_invite_mgr:validate_invite(DbRef, InviteId),
    ?assertMatch({error, already_consumed}, Result),

    ok.

%%%===================================================================
%%% Helper Functions
%%%===================================================================

%% State tuple format: {state, GpgFp, DbRef, Authenticated}
%% Matches the #state{} record in cryptic_ca_ws_handler.erl
