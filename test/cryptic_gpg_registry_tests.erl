%% @doc Unit tests for cryptic_gpg_registry module
-module(cryptic_gpg_registry_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/cryptic_ca.hrl").

%%====================================================================
%% Test Fixtures
%%====================================================================

setup() ->
    DbFile =
        "/tmp/cryptic_gpg_registry_test_" ++
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

    %% Create a default invite for tests that need invite_id (satisfies foreign key constraint)
    DefaultInvite = #invite{
        invite_id = <<"inv-001">>,
        inviter_fp = <<"DEFAULT_INVITER">>,
        issued_at = 900000,
        expires_at = 9999999999,
        consumed = 0,
        consumed_at = undefined,
        consumed_by_fp = undefined,
        meta = undefined
    },
    ok = cryptic_ca_store:insert_invite(DbRef, DefaultInvite),

    {DbRef, DbFile}.

cleanup({DbRef, DbFile}) ->
    cryptic_ca_store:close(DbRef),
    file:delete(DbFile).

%%====================================================================
%% GPG Identity Registration Tests
%%====================================================================

register_gpg_identity_test_() ->
    [
        {"Register via invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_register_via_invite(DbRef))
            end}},
        {"Register bootstrap",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_register_bootstrap(DbRef))
            end}},
        {"Register duplicate",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_register_duplicate(DbRef))
            end}}
    ].

test_register_via_invite(DbRef) ->
    GpgFp = <<"FP_REGISTER_001">>,
    GpgPubArmor =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest key\n-----END PGP PUBLIC KEY BLOCK-----">>,
    InviterFp = <<"DEFAULT_INVITER">>,
    % Use the default invite created in setup
    InviteId = <<"inv-001">>,

    %% Register identity
    ?assertEqual(
        ok,
        cryptic_gpg_registry:register_gpg_identity(
            DbRef, GpgFp, GpgPubArmor, InviterFp, InviteId
        )
    ),

    %% Verify it exists
    {ok, Identity} = cryptic_gpg_registry:get_identity(DbRef, GpgFp),
    ?assertEqual(GpgFp, Identity#gpg_identity.gpg_fp),
    ?assertEqual(<<"verified_via_invite">>, Identity#gpg_identity.status),
    ?assertEqual(InviterFp, Identity#gpg_identity.inviter_fp),
    ?assertEqual(InviteId, Identity#gpg_identity.invite_id).

test_register_bootstrap(DbRef) ->
    GpgFp = <<"FP_BOOTSTRAP_001">>,
    GpgPubArmor =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nbootstrap key\n-----END PGP PUBLIC KEY BLOCK-----">>,

    %% Register bootstrap identity
    ?assertEqual(
        ok,
        cryptic_gpg_registry:register_bootstrap_identity(
            DbRef, GpgFp, GpgPubArmor
        )
    ),

    %% Verify it exists
    {ok, Identity} = cryptic_gpg_registry:get_identity(DbRef, GpgFp),
    ?assertEqual(GpgFp, Identity#gpg_identity.gpg_fp),
    ?assertEqual(<<"verified_bootstrap">>, Identity#gpg_identity.status),
    ?assertEqual(undefined, Identity#gpg_identity.inviter_fp),
    ?assertEqual(undefined, Identity#gpg_identity.invite_id).

test_register_duplicate(DbRef) ->
    GpgFp = <<"FP_DUPLICATE">>,
    GpgPubArmor =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----">>,

    %% Register first time - should succeed
    ?assertEqual(
        ok,
        cryptic_gpg_registry:register_bootstrap_identity(
            DbRef, GpgFp, GpgPubArmor
        )
    ),

    %% Try to register again - should fail
    ?assertMatch(
        {error, _},
        cryptic_gpg_registry:register_bootstrap_identity(
            DbRef, GpgFp, GpgPubArmor
        )
    ).

%%====================================================================
%% Identity Status Verification Tests
%%====================================================================

verify_identity_status_test_() ->
    [
        {"Verify status via invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_verify_status_via_invite(DbRef))
            end}},
        {"Verify status bootstrap",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_verify_status_bootstrap(DbRef))
            end}},
        {"Verify status not found",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_verify_status_not_found(DbRef))
            end}}
    ].

test_verify_status_via_invite(DbRef) ->
    GpgFp = <<"FP_STATUS_001">>,
    GpgPubArmor =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----">>,

    ok = cryptic_gpg_registry:register_gpg_identity(
        DbRef, GpgFp, GpgPubArmor, <<"DEFAULT_INVITER">>, <<"inv-001">>
    ),

    {ok, Status} = cryptic_gpg_registry:verify_identity_status(DbRef, GpgFp),
    ?assertEqual(verified_via_invite, Status).

test_verify_status_bootstrap(DbRef) ->
    GpgFp = <<"FP_STATUS_002">>,
    GpgPubArmor =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----">>,

    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, GpgFp, GpgPubArmor
    ),

    {ok, Status} = cryptic_gpg_registry:verify_identity_status(DbRef, GpgFp),
    ?assertEqual(verified_bootstrap, Status).

test_verify_status_not_found(DbRef) ->
    ?assertEqual(
        {error, not_found},
        cryptic_gpg_registry:verify_identity_status(DbRef, <<"FP_NONEXISTENT">>)
    ).

%%====================================================================
%% Identity Listing Tests
%%====================================================================

list_identities_test_() ->
    [
        {"List all identities",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_list_all_identities(DbRef))
            end}},
        {"List verified identities",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_list_verified_identities(DbRef))
            end}},
        {"List pending identities",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_list_pending_identities(DbRef))
            end}}
    ].

test_list_all_identities(DbRef) ->
    %% Create various identities
    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, <<"FP_ALL_001">>, <<"key1">>
    ),
    ok = cryptic_gpg_registry:register_gpg_identity(
        DbRef,
        <<"FP_ALL_002">>,
        <<"key2">>,
        <<"DEFAULT_INVITER">>,
        <<"inv-001">>
    ),

    %% List all
    {ok, Identities} = cryptic_gpg_registry:list_all_identities(DbRef),
    ?assert(length(Identities) >= 2).

test_list_verified_identities(DbRef) ->
    %% Create verified identities
    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, <<"FP_VERIFIED_001">>, <<"key1">>
    ),
    ok = cryptic_gpg_registry:register_gpg_identity(
        DbRef,
        <<"FP_VERIFIED_002">>,
        <<"key2">>,
        <<"DEFAULT_INVITER">>,
        <<"inv-001">>
    ),

    %% Create pending identity manually
    PendingIdentity = #gpg_identity{
        gpg_fp = <<"FP_PENDING">>,
        gpg_pub_armor = <<"pending key">>,
        status = <<"pending">>,
        inviter_fp = undefined,
        registered_at = erlang:system_time(second),
        last_seen = erlang:system_time(second),
        invite_id = undefined
    },
    ok = cryptic_ca_store:insert_gpg_identity(DbRef, PendingIdentity),

    %% List verified only
    {ok, Verified} = cryptic_gpg_registry:list_verified_identities(DbRef),
    ?assert(length(Verified) >= 2),

    %% All should be verified (either via invite or bootstrap)
    ?assert(
        lists:all(
            fun(Identity) ->
                Status = Identity#gpg_identity.status,
                Status =:= <<"verified_via_invite">> orelse
                    Status =:= <<"verified_bootstrap">>
            end,
            Verified
        )
    ).

test_list_pending_identities(DbRef) ->
    %% Create pending identities
    lists:foreach(
        fun(N) ->
            Identity = #gpg_identity{
                gpg_fp = iolist_to_binary([
                    <<"FP_PENDING_">>, integer_to_binary(N)
                ]),
                gpg_pub_armor = <<"pending key">>,
                status = <<"pending">>,
                inviter_fp = undefined,
                registered_at = erlang:system_time(second),
                last_seen = erlang:system_time(second),
                invite_id = undefined
            },
            ok = cryptic_ca_store:insert_gpg_identity(DbRef, Identity)
        end,
        lists:seq(1, 3)
    ),

    %% List pending
    {ok, Pending} = cryptic_gpg_registry:list_pending_identities(DbRef),
    ?assert(length(Pending) >= 3),

    %% All should be pending
    ?assert(
        lists:all(
            fun(Identity) ->
                Identity#gpg_identity.status =:= <<"pending">>
            end,
            Pending
        )
    ).

%%====================================================================
%% Identity Revocation Tests
%%====================================================================

revoke_identity_test_() ->
    [
        {"Revoke identity",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_revoke_identity(DbRef))
            end}},
        {"Revoke nonexistent",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_revoke_nonexistent(DbRef))
            end}}
    ].

test_revoke_identity(DbRef) ->
    GpgFp = <<"FP_REVOKE_001">>,
    GpgPubArmor =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----">>,

    %% Register identity
    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, GpgFp, GpgPubArmor
    ),

    %% Verify it's verified_bootstrap
    {ok, verified_bootstrap} = cryptic_gpg_registry:verify_identity_status(
        DbRef, GpgFp
    ),

    %% Revoke it
    ?assertEqual(ok, cryptic_gpg_registry:revoke_identity(DbRef, GpgFp)),

    %% Verify it's revoked
    {ok, revoked} = cryptic_gpg_registry:verify_identity_status(DbRef, GpgFp).

test_revoke_nonexistent(DbRef) ->
    ?assertEqual(
        {error, not_found},
        cryptic_gpg_registry:revoke_identity(DbRef, <<"FP_NONEXISTENT">>)
    ).

%%====================================================================
%% Last Seen Update Tests
%%====================================================================

update_last_seen_test_() ->
    [
        {"Update last seen",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_update_last_seen(DbRef))
            end}}
    ].

test_update_last_seen(DbRef) ->
    GpgFp = <<"FP_LASTSEEN">>,
    GpgPubArmor =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----">>,

    %% Register identity
    ok = cryptic_gpg_registry:register_bootstrap_identity(
        DbRef, GpgFp, GpgPubArmor
    ),

    %% Get initial last_seen
    {ok, Identity1} = cryptic_gpg_registry:get_identity(DbRef, GpgFp),
    InitialLastSeen = Identity1#gpg_identity.last_seen,

    %% Wait at least 1 second (system_time is in seconds)
    timer:sleep(1100),

    %% Update last_seen
    ?assertEqual(ok, cryptic_gpg_registry:update_last_seen(DbRef, GpgFp)),

    %% Get updated last_seen
    {ok, Identity2} = cryptic_gpg_registry:get_identity(DbRef, GpgFp),
    UpdatedLastSeen = Identity2#gpg_identity.last_seen,

    %% Should be greater or equal (at least 1 second passed)
    ?assert(UpdatedLastSeen >= InitialLastSeen + 1).
