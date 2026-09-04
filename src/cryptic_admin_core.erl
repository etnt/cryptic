%%%-------------------------------------------------------------------
%%% @doc Transport-agnostic administration core.
%%%
%%% Shared business logic for administering Cryptic users, certificates,
%%% mobile enrollments, the audit log and server status. Extracted from
%%% {@link cryptic_mcp_admin_handler} so that both the (localhost) MCP
%%% endpoint and the web administration console operate on a single
%%% source of truth.
%%%
%%% Functions here take a database reference plus plain values and return
%%% `{ok, Data}' / `{error, Reason}'. They contain no Cowboy/HTTP concerns:
%%% response shaping and authentication live in the respective handlers.
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_admin_core).

-include("cryptic_server.hrl").
-include("cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

%% Read operations
-export([
    list_users/2,
    get_user_info/2,
    list_certificates/2,
    list_enrollments/2,
    get_enrollment_info/2,
    get_audit_log/3,
    server_status/1
]).

%% User status mutations (transport-neutral; caller supplies actor + IP)
-export([
    suspend_user/5,
    revoke_user/5,
    reactivate_user/4,
    delete_user/4
]).

%% Shared helpers reused by cryptic_mcp_admin_handler
-export([
    encode_user/2,
    maybe_attach_metadata/2,
    coalesce/2,
    parse_details/1,
    is_online/1
]).

%%%===================================================================
%%% Users
%%%===================================================================

%% @doc List all users, optionally filtered by status.
%%
%% Users are backed by mobile enrollment identities: an active enrollment is
%% a pending invite, a consumed enrollment is a user who has completed
%% enrollment and holds a certificate.
-spec list_users(term(), binary() | undefined) ->
    {ok, [map()]} | {error, term()}.
list_users(DbRef, Filter) ->
    case cryptic_ca_store:list_enrollment_identities(DbRef) of
        {ok, Identities} ->
            Filtered = filter_by_status(
                Identities, Filter, #enrollment_identity.status),
            {ok, [encode_user(DbRef, I) || I <- Filtered]};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Fetch a single user's detail record (by enrollment fingerprint).
-spec get_user_info(term(), binary()) -> {ok, map()} | {error, term()}.
get_user_info(DbRef, EnrollmentFp) ->
    case cryptic_ca_store:get_enrollment_identity(DbRef, EnrollmentFp) of
        {ok, #enrollment_identity{} = Identity} ->
            {ok, encode_user(DbRef, Identity)};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc List the certificates issued to a user (keyed by enrollment
%% fingerprint, which mobile certificates are stored under).
-spec list_certificates(term(), binary()) -> {ok, [map()]} | {error, term()}.
list_certificates(DbRef, EnrollmentFp) ->
    case cryptic_ca_store:list_certificates_by_user(DbRef, EnrollmentFp) of
        {ok, Certs} ->
            {ok, [encode_certificate(C) || C <- Certs]};
        {error, Reason} ->
            {error, Reason}
    end.

encode_certificate(Cert) ->
    #{
        serial => Cert#certificate.serial,
        issued_at => Cert#certificate.issued_at,
        expires_at => Cert#certificate.expires_at,
        status => Cert#certificate.status,
        revoked_at => coalesce(Cert#certificate.revoked_at, null),
        revoked_by => coalesce(Cert#certificate.revoked_by, null),
        revoked_reason => coalesce(Cert#certificate.revoked_reason, null)
    }.

%%%===================================================================
%%% User status mutations
%%%===================================================================

%% @doc Suspend a user. Records an audit entry attributed to `ActorId'.
-spec suspend_user(term(), binary(), binary(), binary(), binary()) ->
    {ok, map()} | {error, term()}.
suspend_user(DbRef, EnrollmentFp, ActorId, Reason, Ip) ->
    case cryptic_ca_store:update_enrollment_status(
           DbRef, EnrollmentFp, <<"suspended">>) of
        ok ->
            Now = erlang:system_time(second),
            write_audit(DbRef, <<"user_suspended">>, EnrollmentFp,
                        #{suspended_by => ActorId, reason => Reason}, Ip, Now),
            {ok, #{enrollment_fp => EnrollmentFp,
                   new_status => <<"suspended">>, at => Now}};
        {error, Reason2} ->
            {error, Reason2}
    end.

%% @doc Revoke a user. Records an audit entry attributed to `ActorId'.
-spec revoke_user(term(), binary(), binary(), binary(), binary()) ->
    {ok, map()} | {error, term()}.
revoke_user(DbRef, EnrollmentFp, ActorId, Reason, Ip) ->
    case cryptic_ca_store:update_enrollment_status(
           DbRef, EnrollmentFp, <<"revoked">>) of
        ok ->
            Now = erlang:system_time(second),
            write_audit(DbRef, <<"user_revoked">>, EnrollmentFp,
                        #{revoked_by => ActorId, reason => Reason}, Ip, Now),
            {ok, #{enrollment_fp => EnrollmentFp,
                   new_status => <<"revoked">>, at => Now}};
        {error, Reason2} ->
            {error, Reason2}
    end.

%% @doc Reactivate a suspended user.
%%
%% Returns `{error, cannot_reactivate_revoked}' for revoked users and
%% `{ok, #{changed => false}}' when the user is already active/consumed.
%%
%% A suspended user is restored to `consumed' if a certificate has already
%% been issued for the enrollment (so the one-time enrollment key stays
%% spent), otherwise to `active' so a pending invite can still be used.
-spec reactivate_user(term(), binary(), binary(), binary()) ->
    {ok, map()} | {error, term()}.
reactivate_user(DbRef, EnrollmentFp, ActorId, Ip) ->
    case cryptic_ca_store:get_enrollment_identity(DbRef, EnrollmentFp) of
        {ok, #enrollment_identity{status = <<"revoked">>}} ->
            {error, cannot_reactivate_revoked};
        {ok, #enrollment_identity{status = <<"active">>}} ->
            {ok, #{enrollment_fp => EnrollmentFp,
                   new_status => <<"active">>, changed => false}};
        {ok, #enrollment_identity{status = <<"consumed">>}} ->
            {ok, #{enrollment_fp => EnrollmentFp,
                   new_status => <<"consumed">>, changed => false}};
        {ok, _Identity} ->
            NewStatus = case cryptic_ca_store:list_certificates_by_user(
                               DbRef, EnrollmentFp) of
                {ok, [_ | _]} -> <<"consumed">>;
                _ -> <<"active">>
            end,
            case cryptic_ca_store:update_enrollment_status(
                   DbRef, EnrollmentFp, NewStatus) of
                ok ->
                    Now = erlang:system_time(second),
                    write_audit(DbRef, <<"user_reactivated">>, EnrollmentFp,
                                #{reactivated_by => ActorId}, Ip, Now),
                    {ok, #{enrollment_fp => EnrollmentFp,
                           new_status => NewStatus,
                           changed => true, at => Now}};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason2} ->
            {error, Reason2}
    end.

%% @doc Permanently delete an enrollment identity (and its DB row).
%%
%% Unlike {@link revoke_user/5}, which flags the identity as `revoked' but
%% keeps the row for audit, this removes the enrollment entirely so a
%% username can be cleaned up or re-enrolled from scratch. Records a
%% `user_deleted' audit entry attributed to `ActorId'.
-spec delete_user(term(), binary(), binary(), binary()) ->
    {ok, map()} | {error, term()}.
delete_user(DbRef, EnrollmentFp, ActorId, Ip) ->
    case cryptic_ca_store:get_enrollment_identity(DbRef, EnrollmentFp) of
        {ok, #enrollment_identity{username = Username}} ->
            case cryptic_ca_store:delete_enrollment_identity(
                   DbRef, EnrollmentFp) of
                ok ->
                    Now = erlang:system_time(second),
                    write_audit(DbRef, <<"user_deleted">>, EnrollmentFp,
                                #{deleted_by => ActorId,
                                  username => Username}, Ip, Now),
                    {ok, #{enrollment_fp => EnrollmentFp,
                           username => Username, deleted => true, at => Now}};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason2} ->
            {error, Reason2}
    end.

%%%===================================================================
%%% Enrollments
%%%===================================================================

%% @doc List mobile enrollment identities, optionally filtered by status.
-spec list_enrollments(term(), binary() | undefined) ->
    {ok, [map()]} | {error, term()}.
list_enrollments(DbRef, Filter) ->
    case cryptic_ca_store:list_enrollment_identities(DbRef) of
        {ok, Identities} ->
            Filtered = filter_by_status(
                Identities, Filter, #enrollment_identity.status),
            {ok, [encode_enrollment(I) || I <- Filtered]};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Fetch a single enrollment identity.
-spec get_enrollment_info(term(), binary()) -> {ok, map()} | {error, term()}.
get_enrollment_info(DbRef, EnrollmentFp) ->
    case cryptic_ca_store:get_enrollment_identity(DbRef, EnrollmentFp) of
        {ok, I} ->
            {ok, encode_enrollment(I)};
        {error, Reason} ->
            {error, Reason}
    end.

encode_enrollment(I) ->
    E = #{
        enrollment_fp => I#enrollment_identity.enrollment_fp,
        username => I#enrollment_identity.username,
        status => I#enrollment_identity.status,
        registered_by => coalesce(I#enrollment_identity.registered_by, null),
        registered_at => I#enrollment_identity.registered_at,
        consumed_at => coalesce(I#enrollment_identity.consumed_at, null),
        last_seen => coalesce(I#enrollment_identity.last_seen, null)
    },
    maybe_attach_metadata(E, I#enrollment_identity.metadata).

%%%===================================================================
%%% Audit log
%%%===================================================================

%% @doc Return the most recent audit log entries.
-spec get_audit_log(term(), non_neg_integer(), non_neg_integer()) ->
    {ok, [map()]} | {error, term()}.
get_audit_log(DbRef, Limit, Offset) ->
    case cryptic_ca_store:get_audit_logs(DbRef, Limit, Offset) of
        {ok, Logs} ->
            {ok, [encode_audit(Log) || Log <- Logs]};
        {error, Reason} ->
            {error, Reason}
    end.

encode_audit(Log) ->
    #{
        timestamp => Log#audit_log.timestamp,
        event_type => Log#audit_log.event_type,
        gpg_fp => coalesce(Log#audit_log.gpg_fp, null),
        invite_id => coalesce(Log#audit_log.invite_id, null),
        details => parse_details(Log#audit_log.details),
        ip_address => coalesce(Log#audit_log.ip_address, null)
    }.

%%%===================================================================
%%% Server status
%%%===================================================================

%% @doc Summarise listener, ETS table and CA identity status.
-spec server_status(term()) -> {ok, map()}.
server_status(DbRef) ->
    {ok, #{
        listener => listener_status(),
        ets_tables => ets_table_status(),
        ca => ca_status(DbRef)
    }}.

listener_status() ->
    try ranch:info(cryptic_ws_listener) of
        Info when is_map(Info) ->
            Port = maps:get(port, Info, null),
            ActiveConns = ranch:procs(cryptic_ws_listener, connections),
            #{status => <<"running">>, port => Port,
              active_connections => length(ActiveConns)};
        _ ->
            #{status => <<"not_running">>}
    catch
        _:_ -> #{status => <<"not_running">>}
    end.

ets_table_status() ->
    Tables = [
        {?CONNECTION_TABLE, <<"connections">>},
        {?USER_TABLE, <<"registered_users">>},
        {?MESSAGE_TABLE, <<"pending_messages">>},
        {?PREKEY_TABLE, <<"prekey_entries">>}
    ],
    [begin
         Size = case ets:info(Table, size) of
             undefined -> null;
             S -> S
         end,
         #{name => Label, size => Size}
     end || {Table, Label} <- Tables].

ca_status(DbRef) ->
    case cryptic_ca_store:list_gpg_identities(DbRef) of
        {ok, Identities} ->
            Count = fun(St) ->
                length([I || I <- Identities, I#gpg_identity.status =:= St])
            end,
            #{status => <<"connected">>,
              active => Count(<<"active">>),
              suspended => Count(<<"suspended">>),
              revoked => Count(<<"revoked">>)};
        {error, _} ->
            #{status => <<"error">>}
    end.

%%%===================================================================
%%% Shared helpers (also used by cryptic_mcp_admin_handler)
%%%===================================================================

filter_by_status(Items, undefined, _StatusPos) -> Items;
filter_by_status(Items, <<>>, _StatusPos) -> Items;
filter_by_status(Items, Status, StatusPos) ->
    [I || I <- Items, element(StatusPos, I) =:= Status].

%% @doc Encode an enrollment_identity record into a user map, including its
%% online status (resolved from the enrollment username, which is the chat
%% username carried in the issued certificate's CN/SAN).
encode_user(_DbRef, #enrollment_identity{username = Username} = Identity) ->
    Online = case Username of
        undefined -> false;
        <<>> -> false;
        U -> is_online(U)
    end,
    (encode_enrollment(Identity))#{online => Online}.

%% @doc Whether a chat username currently has a live connection.
is_online(User) ->
    case find_user_connection(User) of
        {ok, _Pid} -> true;
        not_found -> false
    end.

find_user_connection(User) when is_binary(User) ->
    find_user_connection(binary_to_list(User));
find_user_connection(User) when is_list(User) ->
    case ets:lookup(?CONNECTION_TABLE, User) of
        [{User, Pid}] when is_pid(Pid) ->
            case is_process_alive(Pid) of
                true -> {ok, Pid};
                false -> not_found
            end;
        _ ->
            not_found
    end.

%% @doc Merge decoded JSON metadata into a map under the `metadata' key.
maybe_attach_metadata(Map, undefined) ->
    Map;
maybe_attach_metadata(Map, Meta) ->
    try
        MetaMap = jsx:decode(Meta, [return_maps]),
        Map#{metadata => MetaMap}
    catch
        _:_ -> Map
    end.

%% @doc Return `Default' for `undefined', otherwise the value.
coalesce(undefined, Default) -> Default;
coalesce(Value, _Default) -> Value.

%% @doc Decode a JSON audit `details' blob, falling back to the raw value.
parse_details(undefined) -> null;
parse_details(Details) ->
    try jsx:decode(Details, [return_maps])
    catch _:_ -> Details
    end.

%%%===================================================================
%%% Internal
%%%===================================================================

write_audit(DbRef, EventType, GpgFp, DetailsMap, Ip, Timestamp) ->
    AuditLog = #audit_log{
        timestamp = Timestamp,
        event_type = EventType,
        gpg_fp = GpgFp,
        invite_id = undefined,
        details = jsx:encode(DetailsMap),
        ip_address = Ip
    },
    Result = cryptic_ca_store:insert_audit_log(DbRef, AuditLog),
    log_audit_result(Result, EventType, GpgFp).

log_audit_result(ok, _EventType, _GpgFp) ->
    ok;
log_audit_result({error, Reason}, EventType, GpgFp) ->
    ?warning("Failed to write audit log for ~s on ~s: ~p",
             [EventType, GpgFp, Reason]),
    ok;
log_audit_result(Other, EventType, GpgFp) ->
    ?warning("Unexpected audit log result for ~s on ~s: ~p",
             [EventType, GpgFp, Other]),
    ok.
