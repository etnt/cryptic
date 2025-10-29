%% @doc Unit tests for cryptic_invite_mgr module
-module(cryptic_invite_mgr_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/cryptic_ca.hrl").

%%====================================================================
%% Test Fixtures
%%====================================================================

setup() ->
    DbFile =
        "/tmp/cryptic_invite_test_" ++
            integer_to_list(erlang:system_time(millisecond)) ++ ".db",
    {ok, DbRef} = cryptic_ca_store:init(DbFile),

    %% Create a default GPG identity for use as inviter (satisfies foreign key constraint)
    DefaultIdentity = #gpg_identity{
        gpg_fp = <<"DEFAULT_INVITER">>,
        gpg_pub_armor =
            <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ndefault\n-----END PGP PUBLIC KEY BLOCK-----">>,
        status = <<"verified_bootstrap">>,
        inviter_fp = undefined,
        registered_at = 900000,
        last_seen = 900000,
        invite_id = undefined
    },
    ok = cryptic_ca_store:insert_gpg_identity(DbRef, DefaultIdentity),

    {DbRef, DbFile}.

cleanup({DbRef, DbFile}) ->
    cryptic_ca_store:close(DbRef),
    file:delete(DbFile).

%%====================================================================
%% Invite ID Generation Tests
%%====================================================================

generate_invite_id_test() ->
    Id1 = cryptic_invite_mgr:generate_invite_id(),
    Id2 = cryptic_invite_mgr:generate_invite_id(),

    %% Should be binaries
    ?assert(is_binary(Id1)),
    ?assert(is_binary(Id2)),

    %% Should start with "inv-"
    ?assertEqual(<<"inv-">>, binary:part(Id1, 0, 4)),
    ?assertEqual(<<"inv-">>, binary:part(Id2, 0, 4)),

    %% Should be unique
    ?assertNotEqual(Id1, Id2),

    %% Should be reasonable length (inv- + UUID)
    ?assert(byte_size(Id1) > 30).

%%====================================================================
%% Invite Creation Tests
%%====================================================================

create_invite_test_() ->
    [
        {"Create basic invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_create_invite_basic(DbRef))
            end}},
        {"Create invite with metadata",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_create_invite_with_metadata(DbRef))
            end}},
        {"Create invite with expiry",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_create_invite_with_expiry(DbRef))
            end}}
    ].

test_create_invite_basic(DbRef) ->
    InviterFp = <<"DEFAULT_INVITER">>,
    % 1 day
    ExpiresIn = 86400,
    Metadata = #{},

    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, ExpiresIn, Metadata
    ),

    %% Should get a valid invite ID
    ?assert(is_binary(InviteId)),
    ?assertEqual(<<"inv-">>, binary:part(InviteId, 0, 4)),

    %% Should be in database
    {ok, Invite} = cryptic_ca_store:get_invite(DbRef, InviteId),
    ?assertEqual(InviterFp, Invite#invite.inviter_fp),
    ?assertEqual(0, Invite#invite.consumed).

test_create_invite_with_metadata(DbRef) ->
    InviterFp = <<"DEFAULT_INVITER">>,
    ExpiresIn = 86400,
    Metadata = #{
        <<"role">> => <<"admin">>,
        <<"department">> => <<"engineering">>
    },

    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, ExpiresIn, Metadata
    ),

    %% Retrieve and check metadata
    {ok, Invite} = cryptic_ca_store:get_invite(DbRef, InviteId),
    ?assert(is_binary(Invite#invite.meta)),

    %% Decode metadata
    DecodedMeta = jsx:decode(Invite#invite.meta, [return_maps]),
    ?assertEqual(<<"admin">>, maps:get(<<"role">>, DecodedMeta)),
    ?assertEqual(<<"engineering">>, maps:get(<<"department">>, DecodedMeta)).

test_create_invite_with_expiry(DbRef) ->
    InviterFp = <<"DEFAULT_INVITER">>,
    % 1 hour (parameter is in hours, not seconds)
    ExpiresInHours = 1,
    Metadata = #{},

    Now = erlang:system_time(second),
    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, ExpiresInHours, Metadata
    ),

    %% Check expiry time (1 hour = 3600 seconds)
    {ok, Invite} = cryptic_ca_store:get_invite(DbRef, InviteId),
    ExpectedExpiry = Now + (ExpiresInHours * 3600),

    %% Allow 2 second tolerance for test execution time
    ?assert(abs(Invite#invite.expires_at - ExpectedExpiry) =< 2).

%%====================================================================
%% Invite Validation Tests
%%====================================================================

validate_invite_test_() ->
    [
        {"Validate valid invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_validate_valid_invite(DbRef))
            end}},
        {"Validate expired invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_validate_expired_invite(DbRef))
            end}},
        {"Validate consumed invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_validate_consumed_invite(DbRef))
            end}},
        {"Validate nonexistent invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_validate_nonexistent_invite(DbRef))
            end}}
    ].

test_validate_valid_invite(DbRef) ->
    InviterFp = <<"DEFAULT_INVITER">>,
    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, 86400, #{}
    ),

    %% Should be valid and return the inviter fingerprint
    ?assertMatch({ok, _}, cryptic_invite_mgr:validate_invite(DbRef, InviteId)).

test_validate_expired_invite(DbRef) ->
    %% Create an already-expired invite manually
    InviteId = <<"inv-expired-test">>,
    Now = erlang:system_time(second),
    Invite = #invite{
        invite_id = InviteId,
        inviter_fp = <<"DEFAULT_INVITER">>,
        issued_at = Now - 10000,
        % Expired 5000 seconds ago
        expires_at = Now - 5000,
        consumed = 0,
        consumed_at = undefined,
        consumed_by_fp = undefined,
        meta = undefined
    },
    ok = cryptic_ca_store:insert_invite(DbRef, Invite),

    %% Should be invalid (expired)
    ?assertEqual(
        {error, expired}, cryptic_invite_mgr:validate_invite(DbRef, InviteId)
    ).

test_validate_consumed_invite(DbRef) ->
    InviterFp = <<"DEFAULT_INVITER">>,
    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, 86400, #{}
    ),

    %% Consume it
    ConsumerFp = <<"CONSUMER_FP">>,
    ok = cryptic_invite_mgr:consume_invite(DbRef, InviteId, ConsumerFp),

    %% Should be invalid (already consumed)
    ?assertEqual(
        {error, already_consumed},
        cryptic_invite_mgr:validate_invite(DbRef, InviteId)
    ).

test_validate_nonexistent_invite(DbRef) ->
    FakeInviteId = <<"inv-does-not-exist">>,
    ?assertEqual(
        {error, not_found},
        cryptic_invite_mgr:validate_invite(DbRef, FakeInviteId)
    ).

%%====================================================================
%% Invite Consumption Tests
%%====================================================================

consume_invite_test_() ->
    [
        {"Consume valid invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_consume_valid_invite(DbRef))
            end}},
        {"Consume invalid invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_consume_invalid_invite(DbRef))
            end}}
    ].

test_consume_valid_invite(DbRef) ->
    InviterFp = <<"DEFAULT_INVITER">>,
    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, 86400, #{}
    ),

    ConsumerFp = <<"CONSUMER_123">>,
    ?assertEqual(
        ok, cryptic_invite_mgr:consume_invite(DbRef, InviteId, ConsumerFp)
    ),

    %% Verify it's consumed
    {ok, Invite} = cryptic_ca_store:get_invite(DbRef, InviteId),
    ?assertEqual(1, Invite#invite.consumed),
    ?assertEqual(ConsumerFp, Invite#invite.consumed_by_fp),
    ?assert(is_integer(Invite#invite.consumed_at)),

    %% Try to consume again - should fail
    ?assertEqual(
        {error, already_consumed},
        cryptic_invite_mgr:consume_invite(DbRef, InviteId, <<"ANOTHER_FP">>)
    ).

test_consume_invalid_invite(DbRef) ->
    %% Try to consume non-existent invite
    ?assertMatch(
        {error, _},
        cryptic_invite_mgr:consume_invite(DbRef, <<"inv-fake">>, <<"FP">>)
    ).

%%====================================================================
%% Invite Listing Tests
%%====================================================================

list_user_invites_test_() ->
    [
        {"List user invites",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_list_user_invites(DbRef))
            end}}
    ].

test_list_user_invites(DbRef) ->
    InviterFp = <<"DEFAULT_INVITER">>,

    %% Create multiple invites
    _InviteIds = lists:map(
        fun(N) ->
            Meta = #{<<"index">> => N},
            {ok, Id} = cryptic_invite_mgr:create_invite(
                DbRef, InviterFp, 86400, Meta
            ),
            Id
        end,
        lists:seq(1, 5)
    ),

    %% List them
    {ok, InviteInfos} = cryptic_invite_mgr:list_user_invites(DbRef, InviterFp),
    ?assertEqual(5, length(InviteInfos)),

    %% Verify structure of returned info
    [FirstInfo | _] = InviteInfos,
    ?assert(is_map(FirstInfo)),
    ?assert(maps:is_key(invite_id, FirstInfo)),
    ?assert(maps:is_key(issued_at, FirstInfo)),
    ?assert(maps:is_key(expires_at, FirstInfo)),
    ?assert(maps:is_key(consumed, FirstInfo)),
    ?assert(maps:is_key(expired, FirstInfo)),
    ?assert(maps:is_key(meta, FirstInfo)),

    %% All should be unconsumed
    ?assert(
        lists:all(
            fun(Info) ->
                not maps:get(consumed, Info)
            end,
            InviteInfos
        )
    ),

    %% All should be not expired
    ?assert(
        lists:all(
            fun(Info) ->
                not maps:get(expired, Info)
            end,
            InviteInfos
        )
    ).

%%====================================================================
%% Invite Revocation Tests
%%====================================================================

revoke_invite_test_() ->
    [
        {"Revoke invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_revoke_invite(DbRef))
            end}}
    ].

test_revoke_invite(DbRef) ->
    InviterFp = <<"DEFAULT_INVITER">>,
    {ok, InviteId} = cryptic_invite_mgr:create_invite(
        DbRef, InviterFp, 86400, #{}
    ),

    %% Should exist initially and return inviter fingerprint
    ?assertMatch({ok, _}, cryptic_invite_mgr:validate_invite(DbRef, InviteId)),

    %% Revoke it
    ?assertEqual(ok, cryptic_invite_mgr:revoke_invite(DbRef, InviteId)),

    %% Should not be found after revocation (revoke marks as consumed)
    ?assertEqual(
        {error, already_consumed},
        cryptic_invite_mgr:validate_invite(DbRef, InviteId)
    ).

%%====================================================================
%% Cleanup Expired Invites Tests
%%====================================================================

cleanup_expired_invites_test_() ->
    [
        {"Cleanup expired invites",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_cleanup_expired_invites(DbRef))
            end}}
    ].

test_cleanup_expired_invites(DbRef) ->
    Now = erlang:system_time(second),

    %% Create expired invites
    lists:foreach(
        fun(N) ->
            Invite = #invite{
                invite_id = iolist_to_binary([
                    <<"inv-expired-">>, integer_to_binary(N)
                ]),
                inviter_fp = <<"DEFAULT_INVITER">>,
                issued_at = Now - 10000,
                expires_at = Now - 5000,
                consumed = 0,
                consumed_at = undefined,
                consumed_by_fp = undefined,
                meta = undefined
            },
            ok = cryptic_ca_store:insert_invite(DbRef, Invite)
        end,
        lists:seq(1, 3)
    ),

    %% Create valid invite
    {ok, ValidId} = cryptic_invite_mgr:create_invite(
        DbRef, <<"DEFAULT_INVITER">>, 86400, #{}
    ),

    %% Cleanup
    {ok, Count} = cryptic_invite_mgr:cleanup_expired_invites(DbRef),
    ?assert(Count >= 3),

    %% Valid invite should still exist and return inviter fingerprint
    ?assertMatch({ok, _}, cryptic_invite_mgr:validate_invite(DbRef, ValidId)).
