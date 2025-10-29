%% @doc Unit tests for cryptic_ca_store module
-module(cryptic_ca_store_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/cryptic_ca.hrl").

%%====================================================================
%% Test Fixtures
%%====================================================================

setup() ->
    %% Use a temporary database for testing
    DbFile =
        "/tmp/cryptic_ca_test_" ++
            integer_to_list(erlang:system_time(millisecond)) ++ ".db",
    {ok, DbRef} = cryptic_ca_store:init(DbFile),

    %% Create a default GPG identity for use as inviter (satisfies foreign key constraint)
    DefaultIdentity = #gpg_identity{
        gpg_fp = <<"ABCD1234">>,
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
%% Database Initialization Tests
%%====================================================================

init_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun({DbRef, _DbFile}) ->
        [
            %% esqlite3 returns a tuple reference, not a pid
            ?_assert(is_tuple(DbRef)),
            ?_assertEqual(ok, test_tables_exist(DbRef))
        ]
    end}.

test_tables_exist(DbRef) ->
    %% Check if all tables were created
    Tables = [<<"invites">>, <<"gpg_identities">>, <<"audit_log">>],
    lists:foreach(
        fun(Table) ->
            Sql =
                <<"SELECT name FROM sqlite_master WHERE type='table' AND name=?">>,
            case esqlite3:q(DbRef, Sql, [Table]) of
                [[Table]] -> ok;
                _ -> throw({table_not_found, Table})
            end
        end,
        Tables
    ),
    ok.

%%====================================================================
%% Invite CRUD Tests
%%====================================================================

invite_crud_test_() ->
    [
        {"Insert invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_insert_invite(DbRef))
            end}},
        {"Get invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_get_invite(DbRef))
            end}},
        {"Consume invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_consume_invite(DbRef))
            end}},
        {"List invites by inviter",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_list_invites_by_inviter(DbRef))
            end}},
        {"Revoke invite",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_revoke_invite(DbRef))
            end}},
        {"Delete expired invites",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_delete_expired_invites(DbRef))
            end}}
    ].

test_insert_invite(DbRef) ->
    Invite = #invite{
        invite_id = <<"inv-test-001">>,
        inviter_fp = <<"ABCD1234">>,
        issued_at = 1000000,
        expires_at = 2000000,
        consumed = 0,
        consumed_at = undefined,
        consumed_by_fp = undefined,
        meta = <<"{\"role\":\"user\"}">>
    },
    ?assertEqual(ok, cryptic_ca_store:insert_invite(DbRef, Invite)).

test_get_invite(DbRef) ->
    %% Insert first
    InviteId = <<"inv-test-002">>,
    Invite = #invite{
        invite_id = InviteId,
        inviter_fp = <<"ABCD1234">>,
        issued_at = 1000000,
        expires_at = 2000000,
        consumed = 0,
        consumed_at = undefined,
        consumed_by_fp = undefined,
        meta = undefined
    },
    ok = cryptic_ca_store:insert_invite(DbRef, Invite),

    %% Get it back
    {ok, Retrieved} = cryptic_ca_store:get_invite(DbRef, InviteId),
    ?assertEqual(InviteId, Retrieved#invite.invite_id),
    ?assertEqual(<<"ABCD1234">>, Retrieved#invite.inviter_fp),
    ?assertEqual(0, Retrieved#invite.consumed).

test_consume_invite(DbRef) ->
    InviteId = <<"inv-test-003">>,
    Invite = #invite{
        invite_id = InviteId,
        inviter_fp = <<"ABCD1234">>,
        issued_at = 1000000,
        expires_at = 2000000,
        consumed = 0,
        consumed_at = undefined,
        consumed_by_fp = undefined,
        meta = undefined
    },
    ok = cryptic_ca_store:insert_invite(DbRef, Invite),

    %% Consume it
    ConsumerFp = <<"EFGH5678">>,
    ?assertEqual(
        ok, cryptic_ca_store:consume_invite(DbRef, InviteId, ConsumerFp)
    ),

    %% Verify it's consumed
    {ok, Consumed} = cryptic_ca_store:get_invite(DbRef, InviteId),
    ?assertEqual(1, Consumed#invite.consumed),
    ?assertEqual(ConsumerFp, Consumed#invite.consumed_by_fp),
    ?assert(is_integer(Consumed#invite.consumed_at)),
    ?assert(Consumed#invite.consumed_at > 0).

test_list_invites_by_inviter(DbRef) ->
    %% Use the default inviter from setup
    InviterFp = <<"ABCD1234">>,

    %% Insert multiple invites
    lists:foreach(
        fun(N) ->
            Invite = #invite{
                invite_id = iolist_to_binary([
                    <<"inv-list-">>, integer_to_binary(N)
                ]),
                inviter_fp = InviterFp,
                issued_at = 1000000 + N,
                expires_at = 2000000 + N,
                consumed = 0,
                consumed_at = undefined,
                consumed_by_fp = undefined,
                meta = undefined
            },
            ok = cryptic_ca_store:insert_invite(DbRef, Invite)
        end,
        lists:seq(1, 5)
    ),

    %% List them
    {ok, Invites} = cryptic_ca_store:list_invites_by_inviter(DbRef, InviterFp),
    ?assertEqual(5, length(Invites)),
    ?assert(
        lists:all(fun(I) -> I#invite.inviter_fp =:= InviterFp end, Invites)
    ).

test_revoke_invite(DbRef) ->
    InviteId = <<"inv-test-revoke">>,
    Invite = #invite{
        invite_id = InviteId,
        inviter_fp = <<"ABCD1234">>,
        issued_at = 1000000,
        expires_at = 2000000,
        consumed = 0,
        consumed_at = undefined,
        consumed_by_fp = undefined,
        meta = undefined
    },
    ok = cryptic_ca_store:insert_invite(DbRef, Invite),

    %% Revoke it
    ?assertEqual(ok, cryptic_ca_store:revoke_invite(DbRef, InviteId)),

    %% Should still be retrievable but marked as consumed (soft delete)
    {ok, Revoked} = cryptic_ca_store:get_invite(DbRef, InviteId),
    ?assertEqual(1, Revoked#invite.consumed).

test_delete_expired_invites(DbRef) ->
    Now = erlang:system_time(second),

    %% Insert expired invite
    ExpiredInvite = #invite{
        invite_id = <<"inv-expired">>,
        inviter_fp = <<"ABCD1234">>,
        issued_at = Now - 10000,
        expires_at = Now - 5000,
        consumed = 0,
        consumed_at = undefined,
        consumed_by_fp = undefined,
        meta = undefined
    },
    ok = cryptic_ca_store:insert_invite(DbRef, ExpiredInvite),

    %% Insert non-expired invite
    ValidInvite = #invite{
        invite_id = <<"inv-valid">>,
        inviter_fp = <<"ABCD1234">>,
        issued_at = Now - 1000,
        expires_at = Now + 10000,
        consumed = 0,
        consumed_at = undefined,
        consumed_by_fp = undefined,
        meta = undefined
    },
    ok = cryptic_ca_store:insert_invite(DbRef, ValidInvite),

    %% Delete expired
    {ok, Count} = cryptic_ca_store:delete_expired_invites(DbRef),
    ?assert(Count >= 1),

    %% Expired should be gone
    ?assertEqual(
        {error, not_found},
        cryptic_ca_store:get_invite(DbRef, <<"inv-expired">>)
    ),

    %% Valid should still exist
    ?assertMatch({ok, _}, cryptic_ca_store:get_invite(DbRef, <<"inv-valid">>)).

%%====================================================================
%% GPG Identity CRUD Tests
%%====================================================================

gpg_identity_crud_test_() ->
    [
        {"Insert GPG identity",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_insert_gpg_identity(DbRef))
            end}},
        {"Get GPG identity",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_get_gpg_identity(DbRef))
            end}},
        {"Update last seen",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_update_last_seen(DbRef))
            end}},
        {"List GPG identities",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_list_gpg_identities(DbRef))
            end}}
    ].

test_insert_gpg_identity(DbRef) ->
    Identity = #gpg_identity{
        gpg_fp = <<"FP123456">>,
        gpg_pub_armor = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
        status = <<"verified_via_invite">>,
        %% Use the default inviter from setup
        inviter_fp = <<"ABCD1234">>,
        registered_at = 1000000,
        last_seen = 1000000,
        %% No specific invite needed for this test
        invite_id = undefined
    },
    ?assertEqual(ok, cryptic_ca_store:insert_gpg_identity(DbRef, Identity)).

test_get_gpg_identity(DbRef) ->
    GpgFp = <<"FP654321">>,
    Identity = #gpg_identity{
        gpg_fp = GpgFp,
        gpg_pub_armor = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
        status = <<"verified_bootstrap">>,
        inviter_fp = undefined,
        registered_at = 1000000,
        last_seen = 1000000,
        invite_id = undefined
    },
    ok = cryptic_ca_store:insert_gpg_identity(DbRef, Identity),

    %% Get it back
    {ok, Retrieved} = cryptic_ca_store:get_gpg_identity(DbRef, GpgFp),
    ?assertEqual(GpgFp, Retrieved#gpg_identity.gpg_fp),
    ?assertEqual(<<"verified_bootstrap">>, Retrieved#gpg_identity.status),
    ?assertEqual(undefined, Retrieved#gpg_identity.inviter_fp).

test_update_last_seen(DbRef) ->
    GpgFp = <<"FP_LASTSEEN">>,
    Identity = #gpg_identity{
        gpg_fp = GpgFp,
        gpg_pub_armor = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
        status = <<"verified_via_invite">>,
        %% Use the default inviter from setup
        inviter_fp = <<"ABCD1234">>,
        registered_at = 1000000,
        last_seen = 1000000,
        %% No specific invite needed
        invite_id = undefined
    },
    ok = cryptic_ca_store:insert_gpg_identity(DbRef, Identity),

    %% Wait a moment and update
    timer:sleep(10),
    ?assertEqual(ok, cryptic_ca_store:update_last_seen(DbRef, GpgFp)),

    %% Verify it changed
    {ok, Updated} = cryptic_ca_store:get_gpg_identity(DbRef, GpgFp),
    ?assert(Updated#gpg_identity.last_seen > 1000000).

test_list_gpg_identities(DbRef) ->
    %% Insert multiple identities
    lists:foreach(
        fun(N) ->
            Identity = #gpg_identity{
                gpg_fp = iolist_to_binary([<<"FP_LIST_">>, integer_to_binary(N)]),
                gpg_pub_armor = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
                status = <<"verified_via_invite">>,
                %% Use the default inviter from setup
                inviter_fp = <<"ABCD1234">>,
                registered_at = 1000000 + N,
                last_seen = 1000000 + N,
                %% No specific invite needed
                invite_id = undefined
            },
            ok = cryptic_ca_store:insert_gpg_identity(DbRef, Identity)
        end,
        lists:seq(1, 3)
    ),

    %% List them
    {ok, Identities} = cryptic_ca_store:list_gpg_identities(DbRef),
    ?assert(length(Identities) >= 3).

%%====================================================================
%% Audit Log Tests
%%====================================================================

audit_log_test_() ->
    [
        {"Insert audit log",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_insert_audit_log(DbRef))
            end}},
        {"Get audit logs",
            {setup, fun setup/0, fun cleanup/1, fun({DbRef, _}) ->
                ?_test(test_get_audit_logs(DbRef))
            end}}
    ].

test_insert_audit_log(DbRef) ->
    AuditLog = #audit_log{
        timestamp = 1000000,
        event_type = <<"invite_created">>,
        gpg_fp = <<"FP123">>,
        invite_id = <<"inv-001">>,
        details = <<"{\"meta\":\"data\"}">>,
        ip_address = <<"192.168.1.1">>
    },
    ?assertEqual(ok, cryptic_ca_store:insert_audit_log(DbRef, AuditLog)).

test_get_audit_logs(DbRef) ->
    %% Insert multiple audit logs with different timestamps
    lists:foreach(
        fun(N) ->
            AuditLog = #audit_log{
                timestamp = 1000000 + N,
                event_type = <<"test_event">>,
                gpg_fp = <<"FP123">>,
                invite_id = undefined,
                details = undefined,
                ip_address = undefined
            },
            ok = cryptic_ca_store:insert_audit_log(DbRef, AuditLog)
        end,
        lists:seq(1, 10)
    ),

    %% Get logs within a time range
    {ok, Logs} = cryptic_ca_store:get_audit_logs(DbRef, 1000001, 1000005),
    ?assertEqual(5, length(Logs)),

    %% Get logs in a different time range
    {ok, Logs2} = cryptic_ca_store:get_audit_logs(DbRef, 1000006, 1000010),
    ?assertEqual(5, length(Logs2)),

    %% Verify they're different
    ?assertNotEqual(Logs, Logs2).
