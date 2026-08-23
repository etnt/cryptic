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
    reactivate_user/4
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
-spec list_users(term(), binary() | undefined) ->
    {ok, [map()]} | {error, term()}.
list_users(DbRef, Filter) ->
    case cryptic_ca_store:list_gpg_identities(DbRef) of
        {ok, Identities} ->
            Filtered = filter_by_status(
                Identities, Filter, #gpg_identity.status),
            {ok, [encode_user(DbRef, I) || I <- Filtered]};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Fetch a single user's detail record.
-spec get_user_info(term(), binary()) -> {ok, map()} | {error, term()}.
get_user_info(DbRef, GpgFp) ->
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{
                status = Status,
                registered_by = RegBy,
                registered_at = RegAt,
                last_seen = LastSeen,
                metadata = Meta
               }} ->
            Info = maybe_attach_metadata(#{
                gpg_fp => GpgFp,
                status => Status,
                registered_by => coalesce(RegBy, null),
                registered_at => RegAt,
                last_seen => coalesce(LastSeen, null)
            }, Meta),
            {ok, Info};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc List the certificates issued to a user.
-spec list_certificates(term(), binary()) -> {ok, [map()]} | {error, term()}.
list_certificates(DbRef, GpgFp) ->
    case cryptic_ca_store:list_certificates_by_user(DbRef, GpgFp) of
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
suspend_user(DbRef, GpgFp, ActorId, Reason, Ip) ->
    case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"suspended">>) of
        ok ->
            Now = erlang:system_time(second),
            write_audit(DbRef, <<"user_suspended">>, GpgFp,
                        #{suspended_by => ActorId, reason => Reason}, Ip, Now),
            {ok, #{gpg_fp => GpgFp, new_status => <<"suspended">>, at => Now}};
        {error, Reason2} ->
            {error, Reason2}
    end.

%% @doc Revoke a user. Records an audit entry attributed to `ActorId'.
-spec revoke_user(term(), binary(), binary(), binary(), binary()) ->
    {ok, map()} | {error, term()}.
revoke_user(DbRef, GpgFp, ActorId, Reason, Ip) ->
    case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"revoked">>) of
        ok ->
            Now = erlang:system_time(second),
            write_audit(DbRef, <<"user_revoked">>, GpgFp,
                        #{revoked_by => ActorId, reason => Reason}, Ip, Now),
            {ok, #{gpg_fp => GpgFp, new_status => <<"revoked">>, at => Now}};
        {error, Reason2} ->
            {error, Reason2}
    end.

%% @doc Reactivate a suspended user.
%%
%% Returns `{error, cannot_reactivate_revoked}' for revoked users and
%% `{ok, #{changed => false}}' when the user is already active.
-spec reactivate_user(term(), binary(), binary(), binary()) ->
    {ok, map()} | {error, term()}.
reactivate_user(DbRef, GpgFp, ActorId, Ip) ->
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{status = <<"revoked">>}} ->
            {error, cannot_reactivate_revoked};
        {ok, #gpg_identity{status = <<"active">>}} ->
            {ok, #{gpg_fp => GpgFp, new_status => <<"active">>, changed => false}};
        {ok, _Identity} ->
            case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"active">>) of
                ok ->
                    Now = erlang:system_time(second),
                    write_audit(DbRef, <<"user_reactivated">>, GpgFp,
                                #{reactivated_by => ActorId}, Ip, Now),
                    {ok, #{gpg_fp => GpgFp, new_status => <<"active">>,
                           changed => true, at => Now}};
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

%% @doc Encode a gpg_identity record into a user map, resolving a display
%% name and online status.
encode_user(DbRef, #gpg_identity{
    gpg_fp = Fp,
    status = Status,
    registered_by = RegBy,
    registered_at = RegAt,
    last_seen = LastSeen,
    metadata = Meta
}) ->
    DisplayName = case get_username_for_gpg(DbRef, Fp) of
        {ok, Name} -> to_binary(Name);
        undefined -> <<"unknown">>
    end,
    ChatUsername = get_chat_username_from_cert(DbRef, Fp),
    Online = case ChatUsername of
        undefined -> false;
        U -> is_online(U)
    end,
    UserMap = #{
        gpg_fp => Fp,
        username => DisplayName,
        status => Status,
        registered_by => coalesce(RegBy, null),
        registered_at => RegAt,
        last_seen => coalesce(LastSeen, null),
        online => Online
    },
    maybe_attach_metadata(UserMap, Meta).

%% @private Resolve a display name for a GPG fingerprint.
get_username_for_gpg(DbRef, GpgFp) ->
    case get_name_from_gpg_key(DbRef, GpgFp) of
        {ok, _} = Ok -> Ok;
        undefined ->
            case get_cn_from_cert(DbRef, GpgFp) of
                undefined -> undefined;
                CN -> {ok, CN}
            end
    end.

%% @private Extract the human name from the GPG key's user ID.
get_name_from_gpg_key(DbRef, GpgFp) ->
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{gpg_pub_armor = PubArmor}}
          when is_binary(PubArmor), byte_size(PubArmor) > 0 ->
            try
                case erl_gpg_api:get_key_info(PubArmor, "") of
                    {ok, KeyInfo} ->
                        UIDs = maps:get(user_ids, KeyInfo, []),
                        extract_name_from_uids(UIDs);
                    _ ->
                        undefined
                end
            catch
                _:_ -> undefined
            end;
        _ ->
            undefined
    end.

extract_name_from_uids([]) -> undefined;
extract_name_from_uids([UID | Rest]) ->
    case extract_name_from_uid(UID) of
        {ok, _} = Ok -> Ok;
        undefined -> extract_name_from_uids(Rest)
    end.

extract_name_from_uid(UID) when is_binary(UID) ->
    S = unicode:characters_to_list(UID),
    case string:split(S, "<") of
        [S] ->
            case string:trim(S) of
                [] -> undefined;
                Trimmed -> {ok, Trimmed}
            end;
        [Before, _] ->
            case string:trim(Before) of
                [] -> undefined;
                Name -> {ok, Name}
            end
    end;
extract_name_from_uid(_) -> undefined.

%% @private Extract the chat username from a stored certificate PEM.
get_chat_username_from_cert(DbRef, GpgFp) ->
    case cryptic_ca_store:list_certificates_by_user(DbRef, GpgFp) of
        {ok, [#certificate{cert_pem = CertPem} | _]} ->
            try
                [{'Certificate', CertDER, not_encrypted}] =
                    public_key:pem_decode(CertPem),
                Cert = public_key:pkix_decode_cert(CertDER, otp),
                TBSCert = Cert#'OTPCertificate'.tbsCertificate,
                case extract_username_from_san(TBSCert) of
                    {ok, Username} -> Username;
                    not_found ->
                        Subject = TBSCert#'OTPTBSCertificate'.subject,
                        extract_common_name(Subject)
                end
            catch
                _:_ -> undefined
            end;
        _ ->
            undefined
    end.

%% @private Extract username from cert SAN extension.
extract_username_from_san(TBSCert) ->
    case TBSCert#'OTPTBSCertificate'.extensions of
        asn1_NOVALUE -> not_found;
        Extensions ->
            case lists:keyfind(?'id-ce-subjectAltName',
                               #'Extension'.extnID, Extensions) of
                false -> not_found;
                #'Extension'{extnValue = GeneralNames}
                  when is_list(GeneralNames) ->
                    extract_username_from_san_names(GeneralNames);
                _ -> not_found
            end
    end.

extract_username_from_san_names([]) -> not_found;
extract_username_from_san_names([{otherName, {{1,3,6,1,4,1,99999,1}, Value}} | _]) ->
    case Value of
        {utf8String, U} when is_binary(U) -> {ok, binary_to_list(U)};
        {utf8String, U} when is_list(U) -> {ok, U};
        _ -> not_found
    end;
extract_username_from_san_names([{rfc822Name, Email} | Rest]) ->
    EmailStr = if is_binary(Email) -> binary_to_list(Email);
                  is_list(Email) -> Email end,
    case string:split(EmailStr, "@") of
        [Local, _] -> {ok, Local};
        _ -> extract_username_from_san_names(Rest)
    end;
extract_username_from_san_names([{dNSName, Name} | Rest]) ->
    NameStr = if is_binary(Name) -> binary_to_list(Name);
                 is_list(Name) -> Name end,
    case string:find(NameStr, ".") of
        nomatch -> {ok, NameStr};
        _ -> extract_username_from_san_names(Rest)
    end;
extract_username_from_san_names([_ | Rest]) ->
    extract_username_from_san_names(Rest).

%% @private Extract CN from the user's certificate.
get_cn_from_cert(DbRef, GpgFp) ->
    case cryptic_ca_store:list_certificates_by_user(DbRef, GpgFp) of
        {ok, [#certificate{cert_pem = CertPem} | _]} ->
            try
                [{'Certificate', CertDER, not_encrypted}] =
                    public_key:pem_decode(CertPem),
                Cert = public_key:pkix_decode_cert(CertDER, otp),
                TBSCert = Cert#'OTPCertificate'.tbsCertificate,
                Subject = TBSCert#'OTPTBSCertificate'.subject,
                extract_common_name(Subject)
            catch
                _:_ -> undefined
            end;
        _ ->
            undefined
    end.

extract_common_name({rdnSequence, RDNSeq}) ->
    lists:foldl(fun
        (_, Found) when is_list(Found) -> Found;
        (RDNSet, undefined) ->
            lists:foldl(fun
                (_, Found) when is_list(Found) -> Found;
                (#'AttributeTypeAndValue'{
                    type = ?'id-at-commonName',
                    value = {utf8String, CN}}, _) ->
                    binary_to_list(CN);
                (#'AttributeTypeAndValue'{
                    type = ?'id-at-commonName',
                    value = CN}, _) when is_list(CN) ->
                    CN;
                (_, Acc) -> Acc
            end, undefined, RDNSet)
    end, undefined, RDNSeq);
extract_common_name(_) ->
    undefined.

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

to_binary(V) when is_binary(V) -> V;
to_binary(V) when is_list(V) -> list_to_binary(V).

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
