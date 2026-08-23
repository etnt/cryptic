-module(cryptic_mcp_admin_handler).

-export([init/2]).

-include("cryptic_server.hrl").
-include("cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

init(Req0, State) ->
    Method = cowboy_req:method(Req0),
    Response =
        try
            handle_request(Method, Req0, State)
        catch
            _:Reason ->
                ?error("MCP admin handler crashed: ~p", [Reason]),
                {500, #{
                    type => <<"error">>,
                    status => <<"error">>,
                    message => <<"internal_server_error">>
                }, Req0}
        end,
    reply_json(Response, State).

reply_json({StatusCode, BodyMap, Req}, State) ->
    Body = jsx:encode(BodyMap),
    Req2 = cowboy_req:reply(
        StatusCode,
        #{<<"content-type">> => <<"application/json">>},
        Body,
        Req
    ),
    {ok, Req2, State}.

handle_request(<<"GET">>, Req0, State) ->
    Operation = maps:get(operation, State, undefined),
    case Operation of
        <<"list_users">> ->
            with_admin(
                Req0,
                fun(AdminFp, DbRef, Req1) ->
                    Filter = query_value(<<"filter">>, Req1),
                    list_users(DbRef, AdminFp, Filter, Req1)
                end
            );
        <<"get_user_info">> ->
            with_admin(
                Req0,
                fun(_AdminFp, DbRef, Req1) ->
                    case cowboy_req:binding(gpg_fp, Req1) of
                        undefined ->
                            bad_request(<<"missing_gpg_fp">>, Req1);
                        GpgFp ->
                            get_user_info(DbRef, GpgFp, Req1)
                    end
                end
            );
        <<"list_certificates">> ->
            with_admin(
                Req0,
                fun(_AdminFp, DbRef, Req1) ->
                    case cowboy_req:binding(gpg_fp, Req1) of
                        undefined ->
                            bad_request(<<"missing_gpg_fp">>, Req1);
                        GpgFp ->
                            list_certificates(DbRef, GpgFp, Req1)
                    end
                end
            );
        <<"status">> ->
            with_admin(
                Req0,
                fun(_AdminFp, DbRef, Req1) ->
                    get_server_status(DbRef, Req1)
                end
            );
        <<"online">> ->
            with_admin(
                Req0,
                fun(_AdminFp, _DbRef, Req1) ->
                    get_online_users(Req1)
                end
            );
        <<"connections">> ->
            with_admin(
                Req0,
                fun(_AdminFp, _DbRef, Req1) ->
                    get_connections(Req1)
                end
            );
        <<"pending">> ->
            with_admin(
                Req0,
                fun(_AdminFp, _DbRef, Req1) ->
                    get_pending_messages(Req1)
                end
            );
        <<"pending_for_user">> ->
            with_admin(
                Req0,
                fun(_AdminFp, _DbRef, Req1) ->
                    case cowboy_req:binding(user, Req1) of
                        undefined ->
                            bad_request(<<"missing_user">>, Req1);
                        User ->
                            get_pending_messages_for_user(User, Req1)
                    end
                end
            );
        <<"keys">> ->
            with_admin(
                Req0,
                fun(_AdminFp, _DbRef, Req1) ->
                    get_key_bundles(Req1)
                end
            );
        <<"keys_for_user">> ->
            with_admin(
                Req0,
                fun(_AdminFp, _DbRef, Req1) ->
                    case cowboy_req:binding(user, Req1) of
                        undefined ->
                            bad_request(<<"missing_user">>, Req1);
                        User ->
                            get_key_bundle_for_user(User, Req1)
                    end
                end
            );
        <<"audit">> ->
            with_admin(
                Req0,
                fun(_AdminFp, DbRef, Req1) ->
                    LimitBin = query_value(<<"limit">>, Req1),
                    Limit = case LimitBin of
                        undefined -> 20;
                        <<>> -> 20;
                        _ ->
                            try binary_to_integer(LimitBin)
                            catch _:_ -> 20
                            end
                    end,
                    get_audit_log(DbRef, Limit, Req1)
                end
            );
        <<"list_enrollments">> ->
            with_admin(
                Req0,
                fun(_AdminFp, DbRef, Req1) ->
                    Filter = query_value(<<"filter">>, Req1),
                    list_enrollments(DbRef, Filter, Req1)
                end
            );
        <<"get_enrollment_info">> ->
            with_admin(
                Req0,
                fun(_AdminFp, DbRef, Req1) ->
                    case cowboy_req:binding(enrollment_fp, Req1) of
                        undefined ->
                            bad_request(<<"missing_enrollment_fp">>, Req1);
                        Fp ->
                            get_enrollment_info(DbRef, Fp, Req1)
                    end
                end
            );
        <<"server_log">> ->
            with_admin(
                Req0,
                fun(_AdminFp, _DbRef, Req1) ->
                    LinesBin = query_value(<<"lines">>, Req1),
                    Lines = case LinesBin of
                        undefined -> 50;
                        <<>> -> 50;
                        _ ->
                            try
                                N = binary_to_integer(LinesBin),
                                min(max(N, 1), 1000)
                            catch _:_ -> 50
                            end
                    end,
                    get_server_log_tail(Lines, Req1)
                end
            );
        _ ->
            {404, #{
                type => <<"error">>,
                status => <<"error">>,
                message => <<"not_found">>
            }, Req0}
    end;
handle_request(<<"POST">>, Req0, State) ->
    {ok, RawBody, Req1} = cowboy_req:read_body(Req0),
    case decode_json_body(RawBody) of
        {error, Reason} ->
            bad_request(Reason, Req1);
        {ok, BodyMap} ->
            Operation = maps:get(operation, State, undefined),
            with_admin(
                Req1,
                BodyMap,
                fun(AdminFp, DbRef, Req2) ->
                    handle_post_operation(Operation, BodyMap, AdminFp, DbRef, Req2)
                end
            )
    end;
handle_request(_, Req0, _State) ->
    {405, #{
        type => <<"error">>,
        status => <<"error">>,
        message => <<"method_not_allowed">>
    }, Req0}.

handle_post_operation(<<"register_user">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"gpg_fp">>, <<"gpg_pub">>],
        fun() ->
            GpgFp = maps:get(<<"gpg_fp">>, BodyMap),
            GpgPub = maps:get(<<"gpg_pub">>, BodyMap),
            Metadata = maps:get(<<"metadata">>, BodyMap, null),
            case cryptic_ca_store:register_user(DbRef, GpgFp, GpgPub, AdminFp, Metadata) of
                ok ->
                    {200, #{
                        type => <<"user_registered">>,
                        status => <<"success">>,
                        gpg_fp => GpgFp,
                        registered_by => AdminFp
                    }, Req};
                {error, Reason} ->
                    error_response(400, Reason, Req)
            end
        end,
        Req
    );
handle_post_operation(<<"suspend_user">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"gpg_fp">>],
        fun() ->
            GpgFp = maps:get(<<"gpg_fp">>, BodyMap),
            Reason = maps:get(<<"reason">>, BodyMap, <<"No reason provided">>),
            case cryptic_admin_core:suspend_user(
                   DbRef, GpgFp, AdminFp, Reason, peer_ip(Req)) of
                {ok, #{at := Now}} ->
                    {200, #{
                        type => <<"suspend_user_response">>,
                        status => <<"success">>,
                        gpg_fp => GpgFp,
                        new_status => <<"suspended">>,
                        suspended_by => AdminFp,
                        suspended_at => Now
                    }, Req};
                {error, Reason2} ->
                    error_response(400, Reason2, Req)
            end
        end,
        Req
    );
handle_post_operation(<<"revoke_user">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"gpg_fp">>],
        fun() ->
            GpgFp = maps:get(<<"gpg_fp">>, BodyMap),
            Reason = maps:get(<<"reason">>, BodyMap, <<"No reason provided">>),
            case cryptic_admin_core:revoke_user(
                   DbRef, GpgFp, AdminFp, Reason, peer_ip(Req)) of
                {ok, #{at := Now}} ->
                    {200, #{
                        type => <<"revoke_user_response">>,
                        status => <<"success">>,
                        gpg_fp => GpgFp,
                        new_status => <<"revoked">>,
                        revoked_by => AdminFp,
                        revoked_at => Now
                    }, Req};
                {error, Reason2} ->
                    error_response(400, Reason2, Req)
            end
        end,
        Req
    );
handle_post_operation(<<"reactivate_user">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"gpg_fp">>],
        fun() ->
            GpgFp = maps:get(<<"gpg_fp">>, BodyMap),
            case cryptic_admin_core:reactivate_user(
                   DbRef, GpgFp, AdminFp, peer_ip(Req)) of
                {ok, #{changed := false}} ->
                    {200, #{
                        type => <<"reactivate_user_response">>,
                        status => <<"success">>,
                        gpg_fp => GpgFp,
                        message => <<"User already active">>
                    }, Req};
                {ok, #{at := Now}} ->
                    {200, #{
                        type => <<"reactivate_user_response">>,
                        status => <<"success">>,
                        gpg_fp => GpgFp,
                        new_status => <<"active">>,
                        reactivated_by => AdminFp,
                        reactivated_at => Now
                    }, Req};
                {error, cannot_reactivate_revoked} ->
                    {400, #{
                        type => <<"reactivate_user_response">>,
                        status => <<"error">>,
                        error => <<"cannot_reactivate_revoked">>,
                        message => <<"Revoked users cannot be reactivated">>
                    }, Req};
                {error, Reason2} ->
                    error_response(404, Reason2, Req)
            end
        end,
        Req
    );
handle_post_operation(<<"revoke_certificate">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"serial">>, <<"reason">>],
        fun() ->
            Serial = maps:get(<<"serial">>, BodyMap),
            Reason = maps:get(<<"reason">>, BodyMap),
            case cryptic_ca_store:revoke_certificate(DbRef, Serial, AdminFp, Reason) of
                ok ->
                    {200, #{
                        type => <<"revoke_certificate_response">>,
                        status => <<"success">>,
                        serial => Serial,
                        reason => Reason
                    }, Req};
                {error, Reason2} ->
                    error_response(400, Reason2, Req)
            end
        end,
        Req
    );
handle_post_operation(<<"register_enrollment">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"enrollment_fp">>, <<"enrollment_pub">>, <<"username">>],
        fun() ->
            EnrollmentFp = maps:get(<<"enrollment_fp">>, BodyMap),
            EnrollmentPubB64 = maps:get(<<"enrollment_pub">>, BodyMap),
            Username = maps:get(<<"username">>, BodyMap),
            Metadata = maps:get(<<"metadata">>, BodyMap, undefined),
            case base64:decode(EnrollmentPubB64) of
                EnrollmentPub when byte_size(EnrollmentPub) =:= 32 ->
                    Now = erlang:system_time(second),
                    Identity = #enrollment_identity{
                        enrollment_fp = EnrollmentFp,
                        enrollment_pub = EnrollmentPub,
                        username = Username,
                        status = <<"active">>,
                        registered_by = AdminFp,
                        registered_at = Now,
                        metadata = Metadata
                    },
                    case cryptic_ca_store:insert_enrollment_identity(DbRef, Identity) of
                        ok ->
                            AuditResult = log_audit(DbRef, <<"enrollment_registered">>,
                                EnrollmentFp, #{registered_by => AdminFp, username => Username},
                                Req, Now),
                            log_audit_result(AuditResult, <<"enrollment_registered">>, EnrollmentFp),
                            {200, #{
                                type => <<"register_enrollment_response">>,
                                status => <<"success">>,
                                enrollment_fp => EnrollmentFp,
                                username => Username,
                                registered_by => AdminFp
                            }, Req};
                        {error, Reason} ->
                            error_response(400, Reason, Req)
                    end;
                _ ->
                    bad_request(<<"invalid_public_key_must_be_32_bytes_ed25519">>, Req)
            end
        end,
        Req
    );
handle_post_operation(<<"suspend_enrollment">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"enrollment_fp">>],
        fun() ->
            EnrollmentFp = maps:get(<<"enrollment_fp">>, BodyMap),
            Reason = maps:get(<<"reason">>, BodyMap, <<"No reason provided">>),
            case cryptic_ca_store:update_enrollment_status(DbRef, EnrollmentFp, <<"suspended">>) of
                ok ->
                    Now = erlang:system_time(second),
                    AuditResult = log_audit(DbRef, <<"enrollment_suspended">>, EnrollmentFp, #{
                        suspended_by => AdminFp, reason => Reason
                    }, Req, Now),
                    log_audit_result(AuditResult, <<"enrollment_suspended">>, EnrollmentFp),
                    {200, #{
                        type => <<"suspend_enrollment_response">>,
                        status => <<"success">>,
                        enrollment_fp => EnrollmentFp,
                        new_status => <<"suspended">>,
                        suspended_by => AdminFp
                    }, Req};
                {error, Reason2} ->
                    error_response(400, Reason2, Req)
            end
        end,
        Req
    );
handle_post_operation(<<"revoke_enrollment">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"enrollment_fp">>],
        fun() ->
            EnrollmentFp = maps:get(<<"enrollment_fp">>, BodyMap),
            Reason = maps:get(<<"reason">>, BodyMap, <<"No reason provided">>),
            case cryptic_ca_store:update_enrollment_status(DbRef, EnrollmentFp, <<"revoked">>) of
                ok ->
                    Now = erlang:system_time(second),
                    AuditResult = log_audit(DbRef, <<"enrollment_revoked">>, EnrollmentFp, #{
                        revoked_by => AdminFp, reason => Reason
                    }, Req, Now),
                    log_audit_result(AuditResult, <<"enrollment_revoked">>, EnrollmentFp),
                    {200, #{
                        type => <<"revoke_enrollment_response">>,
                        status => <<"success">>,
                        enrollment_fp => EnrollmentFp,
                        new_status => <<"revoked">>,
                        revoked_by => AdminFp
                    }, Req};
                {error, Reason2} ->
                    error_response(400, Reason2, Req)
            end
        end,
        Req
    );
handle_post_operation(<<"reactivate_enrollment">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"enrollment_fp">>],
        fun() ->
            EnrollmentFp = maps:get(<<"enrollment_fp">>, BodyMap),
            case cryptic_ca_store:get_enrollment_identity(DbRef, EnrollmentFp) of
                {ok, #enrollment_identity{status = <<"revoked">>}} ->
                    {400, #{
                        type => <<"reactivate_enrollment_response">>,
                        status => <<"error">>,
                        error => <<"cannot_reactivate_revoked">>,
                        message => <<"Revoked enrollments cannot be reactivated">>
                    }, Req};
                {ok, #enrollment_identity{status = <<"active">>}} ->
                    {200, #{
                        type => <<"reactivate_enrollment_response">>,
                        status => <<"success">>,
                        enrollment_fp => EnrollmentFp,
                        message => <<"Enrollment already active">>
                    }, Req};
                {ok, _} ->
                    case cryptic_ca_store:update_enrollment_status(DbRef, EnrollmentFp, <<"active">>) of
                        ok ->
                            Now = erlang:system_time(second),
                            AuditResult = log_audit(DbRef, <<"enrollment_reactivated">>,
                                EnrollmentFp, #{reactivated_by => AdminFp}, Req, Now),
                            log_audit_result(AuditResult, <<"enrollment_reactivated">>, EnrollmentFp),
                            {200, #{
                                type => <<"reactivate_enrollment_response">>,
                                status => <<"success">>,
                                enrollment_fp => EnrollmentFp,
                                new_status => <<"active">>,
                                reactivated_by => AdminFp
                            }, Req};
                        {error, Reason} ->
                            error_response(400, Reason, Req)
                    end;
                {error, Reason2} ->
                    error_response(404, Reason2, Req)
            end
        end,
        Req
    );
handle_post_operation(<<"delete_enrollment">>, BodyMap, AdminFp, DbRef, Req) ->
    with_required_fields(
        BodyMap,
        [<<"enrollment_fp">>],
        fun() ->
            EnrollmentFp = maps:get(<<"enrollment_fp">>, BodyMap),
            case cryptic_ca_store:delete_enrollment_identity(DbRef, EnrollmentFp) of
                ok ->
                    Now = erlang:system_time(second),
                    AuditResult = log_audit(DbRef, <<"enrollment_deleted">>,
                        EnrollmentFp, #{deleted_by => AdminFp}, Req, Now),
                    log_audit_result(AuditResult, <<"enrollment_deleted">>, EnrollmentFp),
                    {200, #{
                        type => <<"delete_enrollment_response">>,
                        status => <<"success">>,
                        enrollment_fp => EnrollmentFp,
                        deleted_by => AdminFp
                    }, Req};
                {error, Reason} ->
                    error_response(400, Reason, Req)
            end
        end,
        Req
    );
handle_post_operation(_Unknown, _BodyMap, _AdminFp, _DbRef, Req) ->
    {404, #{
        type => <<"error">>,
        status => <<"error">>,
        message => <<"not_found">>
    }, Req}.

with_required_fields(Map, Keys, Fun, Req) ->
    Missing = [K || K <- Keys, not maps:is_key(K, Map)],
    case Missing of
        [] -> Fun();
        _ ->
            {400, #{
                type => <<"error">>,
                status => <<"error">>,
                message => <<"missing_required_fields">>,
                missing => Missing
            }, Req}
    end.

decode_json_body(<<>>) ->
    {ok, #{}};
decode_json_body(RawBody) ->
    try
        {ok, jsx:decode(RawBody, [return_maps])}
    catch
        _:_ ->
            {error, <<"invalid_json">>}
    end.

query_value(Key, Req) ->
    proplists:get_value(Key, cowboy_req:parse_qs(Req)).

with_admin(Req, Fun) ->
    with_admin(Req, #{}, Fun).

with_admin(Req, BodyMap, Fun) ->
    case get_db_ref() of
        {error, Reason} ->
            ?error("MCP admin handler missing DB ref: ~p", [Reason]),
            {500, #{
                type => <<"error">>,
                status => <<"error">>,
                message => <<"internal_server_error">>
            }, Req};
        {ok, DbRef} ->
            AdminFp = get_admin_fingerprint(Req, BodyMap),
            case is_admin(AdminFp, DbRef) of
                true ->
                    Fun(AdminFp, DbRef, Req);
                false ->
                    {403, #{
                        type => <<"error">>,
                        status => <<"error">>,
                        message => <<"admin_privileges_required">>
                    }, Req}
            end
    end.

get_db_ref() ->
    case application:get_env(cryptic, ca_db_ref) of
        {ok, DbRef} ->
            {ok, DbRef};
        _ ->
            {error, ca_db_ref_not_configured}
    end.

get_admin_fingerprint(Req, BodyMap) ->
    %% Priority order: explicit header, then JSON body.
    case cowboy_req:header(<<"x-admin-gpg-fp">>, Req) of
        undefined ->
            case maps:get(<<"admin_gpg_fp">>, BodyMap, undefined) of
                undefined ->
                    undefined;
                Fp ->
                    Fp
            end;
        Fp ->
            Fp
    end.

is_admin(undefined, _DbRef) ->
    false;
is_admin(GpgFp, DbRef) ->
    %% Bootstrap/root admins are identities with no registered_by owner.
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{registered_by = undefined}} -> true;
        _ -> false
    end.

list_users(DbRef, _AdminFp, Filter, Req) ->
    case cryptic_admin_core:list_users(DbRef, Filter) of
        {ok, Users} ->
            {200, #{
                type => <<"list_users_response">>,
                status => <<"success">>,
                count => length(Users),
                users => Users
            }, Req};
        {error, Reason} ->
            error_response(500, Reason, Req)
    end.

get_user_info(DbRef, GpgFp, Req) ->
    case cryptic_admin_core:get_user_info(DbRef, GpgFp) of
        {ok, UserInfo} ->
            {200, #{
                type => <<"get_user_info_response">>,
                status => <<"success">>,
                user => UserInfo
            }, Req};
        {error, Reason} ->
            error_response(404, Reason, Req)
    end.

list_certificates(DbRef, GpgFp, Req) ->
    case cryptic_admin_core:list_certificates(DbRef, GpgFp) of
        {ok, CertList} ->
            {200, #{
                type => <<"list_certificates_response">>,
                status => <<"success">>,
                gpg_fp => GpgFp,
                certificates => CertList,
                count => length(CertList)
            }, Req};
        {error, Reason} ->
            error_response(404, Reason, Req)
    end.

log_audit(DbRef, EventType, GpgFp, DetailsMap, Req, Timestamp) ->
    IpAddress = peer_ip(Req),
    AuditLog = #audit_log{
        timestamp = Timestamp,
        event_type = EventType,
        gpg_fp = GpgFp,
        invite_id = undefined,
        details = jsx:encode(DetailsMap),
        ip_address = IpAddress
    },
    cryptic_ca_store:insert_audit_log(DbRef, AuditLog).

peer_ip(Req) ->
    case cowboy_req:peer(Req) of
        {{A, B, C, D}, _Port} ->
            iolist_to_binary(io_lib:format("~b.~b.~b.~b", [A, B, C, D]));
        {Addr, _Port} when is_tuple(Addr) ->
            case inet:ntoa(Addr) of
                Ip when is_list(Ip) ->
                    iolist_to_binary(Ip);
                _ ->
                    <<"unknown">>
            end;
        _ ->
            <<"unknown">>
    end.

log_audit_result(ok, _EventType, _GpgFp) ->
    ok;
log_audit_result({error, Reason}, EventType, GpgFp) ->
    ?warning("Failed to write audit log for ~s on ~s: ~p", [EventType, GpgFp, Reason]),
    ok;
log_audit_result(Other, EventType, GpgFp) ->
    ?warning("Unexpected audit log result for ~s on ~s: ~p", [EventType, GpgFp, Other]),
    ok.

bad_request(Reason, Req) ->
    {400, #{
        type => <<"error">>,
        status => <<"error">>,
        message => Reason
    }, Req}.

error_response(StatusCode, Reason, Req) ->
    ?error("MCP admin operation failed: ~p", [Reason]),
    {StatusCode, #{
        type => <<"error">>,
        status => <<"error">>,
        message => <<"operation_failed">>
    }, Req}.

%%%===================================================================
%%% Server Status
%%%===================================================================

get_server_status(DbRef, Req) ->
    {ok, Status} = cryptic_admin_core:server_status(DbRef),
    {200, Status#{
        type => <<"status_response">>,
        status => <<"success">>
    }, Req}.

%%%===================================================================
%%% Online Users
%%%===================================================================

get_online_users(Req) ->
    Connections = ets:tab2list(?CONNECTION_TABLE),
    Users = lists:map(fun({Username, _Pid}) ->
        UsernameB = if is_list(Username) -> list_to_binary(Username);
                       is_binary(Username) -> Username;
                       true -> list_to_binary(io_lib:format("~p", [Username]))
                    end,
        #{username => UsernameB}
    end, lists:sort(Connections)),
    {200, #{
        type => <<"online_response">>,
        status => <<"success">>,
        count => length(Users),
        users => Users
    }, Req}.

%%%===================================================================
%%% Connections
%%%===================================================================

get_connections(Req) ->
    Connections = ets:tab2list(?CONNECTION_TABLE),
    ConnList = lists:map(fun({Username, Pid}) ->
        UsernameB = if is_list(Username) -> list_to_binary(Username);
                       is_binary(Username) -> Username;
                       true -> list_to_binary(io_lib:format("~p", [Username]))
                    end,
        Alive = is_process_alive(Pid),
        ProcInfo = case Alive of
            true ->
                case erlang:process_info(Pid, [message_queue_len, memory, reductions]) of
                    undefined ->
                        #{alive => true};
                    Props ->
                        MsgQ = proplists:get_value(message_queue_len, Props, 0),
                        Mem = proplists:get_value(memory, Props, 0),
                        Reds = proplists:get_value(reductions, Props, 0),
                        #{alive => true, message_queue_len => MsgQ,
                          memory_bytes => Mem, reductions => Reds}
                end;
            false ->
                #{alive => false}
        end,
        ProcInfo#{username => UsernameB, pid => list_to_binary(pid_to_list(Pid))}
    end, lists:sort(Connections)),
    {200, #{
        type => <<"connections_response">>,
        status => <<"success">>,
        count => length(ConnList),
        connections => ConnList
    }, Req}.

%%%===================================================================
%%% Pending Messages
%%%===================================================================

get_pending_messages(Req) ->
    Messages = ets:tab2list(?MESSAGE_TABLE),
    Grouped = lists:foldl(fun({_Id, ToUser, _Blob}, Acc) ->
        ToUserB = if is_list(ToUser) -> list_to_binary(ToUser);
                     is_binary(ToUser) -> ToUser;
                     true -> list_to_binary(io_lib:format("~p", [ToUser]))
                  end,
        maps:update_with(ToUserB, fun(V) -> V + 1 end, 1, Acc)
    end, #{}, Messages),
    PerUser = maps:fold(fun(User, Count, Acc) ->
        [#{user => User, count => Count} | Acc]
    end, [], Grouped),
    {200, #{
        type => <<"pending_response">>,
        status => <<"success">>,
        total => length(Messages),
        per_user => PerUser
    }, Req}.

get_pending_messages_for_user(User, Req) ->
    UserStr = binary_to_list(User),
    Messages = [{From, Type, Ts} ||
        {_Id, ToUser, Blob} <- ets:tab2list(?MESSAGE_TABLE),
        ToUser =:= UserStr,
        From <- [maps:get(<<"from_user">>, Blob, <<"?">>)],
        Type <- [maps:get(<<"message_type">>, Blob,
                 maps:get(<<"type">>, Blob, <<"unknown">>))],
        Ts <- [maps:get(<<"server_timestamp">>, Blob, 0)]
    ],
    MsgList = lists:map(fun({From, Type, Ts}) ->
        #{from => From, message_type => Type, timestamp => Ts}
    end, Messages),
    {200, #{
        type => <<"pending_for_user_response">>,
        status => <<"success">>,
        user => User,
        count => length(MsgList),
        messages => MsgList
    }, Req}.

%%%===================================================================
%%% Key Bundles
%%%===================================================================

get_key_bundles(Req) ->
    AllPrekeys = ets:tab2list(?PREKEY_TABLE),
    UserSet = lists:foldl(fun
        ({{Username, identity}, _}, Acc) -> sets:add_element(Username, Acc);
        ({{Username, signed_prekey, _}, _}, Acc) -> sets:add_element(Username, Acc);
        ({{Username, one_time_prekey, _}, _}, Acc) -> sets:add_element(Username, Acc);
        (_, Acc) -> Acc
    end, sets:new(), AllPrekeys),
    Users = lists:sort(sets:to_list(UserSet)),
    Bundles = lists:map(fun(Username) ->
        HasIdentity = ets:member(?PREKEY_TABLE, {Username, identity}),
        OtpkCount = length([ok || {{U, one_time_prekey, _}, _} <- AllPrekeys,
                                   U =:= Username]),
        UsernameB = if is_list(Username) -> list_to_binary(Username);
                       is_binary(Username) -> Username;
                       true -> list_to_binary(io_lib:format("~p", [Username]))
                    end,
        #{username => UsernameB,
          has_identity_keys => HasIdentity,
          one_time_prekey_count => OtpkCount}
    end, Users),
    {200, #{
        type => <<"keys_response">>,
        status => <<"success">>,
        count => length(Bundles),
        key_bundles => Bundles
    }, Req}.

get_key_bundle_for_user(User, Req) ->
    UserStr = binary_to_list(User),
    HasIdentity = ets:member(?PREKEY_TABLE, {UserStr, identity}),
    IdentityFields = case ets:lookup(?PREKEY_TABLE, {UserStr, identity}) of
        [{_, Data}] when is_map(Data) -> maps:keys(Data);
        [{_, _}] -> [<<"binary_data">>];
        [] -> []
    end,
    AllPrekeys = ets:tab2list(?PREKEY_TABLE),
    OtpkIds = lists:sort([Id || {{U, one_time_prekey, Id}, _} <- AllPrekeys,
                                 U =:= UserStr]),
    FieldsBin = [if is_atom(F) -> atom_to_binary(F, utf8);
                    is_binary(F) -> F;
                    true -> list_to_binary(io_lib:format("~p", [F]))
                 end || F <- IdentityFields],
    {200, #{
        type => <<"keys_for_user_response">>,
        status => <<"success">>,
        user => User,
        has_identity_keys => HasIdentity,
        identity_key_fields => FieldsBin,
        one_time_prekey_count => length(OtpkIds),
        one_time_prekey_ids => OtpkIds
    }, Req}.

%%%===================================================================
%%% Audit Log
%%%===================================================================

get_audit_log(DbRef, Limit, Req) ->
    case cryptic_admin_core:get_audit_log(DbRef, Limit, 0) of
        {ok, LogList} ->
            {200, #{
                type => <<"audit_response">>,
                status => <<"success">>,
                count => length(LogList),
                limit => Limit,
                entries => LogList
            }, Req};
        {error, Reason} ->
            error_response(500, Reason, Req)
    end.

%%%===================================================================
%%% Server Log
%%%===================================================================

get_server_log_tail(Lines, Req) ->
    LogFile = case whereis(cryptic_event_manager) of
        undefined -> "logs/server.log";
        _ ->
            try gen_event:call(cryptic_event_manager, cryptic_file_logger, get_log_file)
            catch _:_ -> "logs/server.log"
            end
    end,
    case file:read_file(LogFile) of
        {ok, Content} ->
            AllLines = binary:split(Content, <<"\n">>, [global]),
            %% Remove trailing empty line from split
            NonEmpty = lists:reverse(
                lists:dropwhile(fun(L) -> L =:= <<>> end,
                                lists:reverse(AllLines))),
            TailLines = lists:nthtail(
                max(0, length(NonEmpty) - Lines), NonEmpty),
            {200, #{
                type => <<"server_log_response">>,
                status => <<"success">>,
                log_file => list_to_binary(LogFile),
                total_lines => length(NonEmpty),
                returned_lines => length(TailLines),
                lines => TailLines
            }, Req};
        {error, Reason} ->
            error_response(500, Reason, Req)
    end.

%%%===================================================================
%%% Enrollment Identities
%%%===================================================================

list_enrollments(DbRef, Filter, Req) ->
    case cryptic_admin_core:list_enrollments(DbRef, Filter) of
        {ok, Enrollments} ->
            {200, #{
                type => <<"list_enrollments_response">>,
                status => <<"success">>,
                count => length(Enrollments),
                enrollments => Enrollments
            }, Req};
        {error, Reason} ->
            error_response(500, Reason, Req)
    end.

get_enrollment_info(DbRef, EnrollmentFp, Req) ->
    case cryptic_admin_core:get_enrollment_info(DbRef, EnrollmentFp) of
        {ok, InfoWithMeta} ->
            {200, #{
                type => <<"get_enrollment_info_response">>,
                status => <<"success">>,
                enrollment => InfoWithMeta
            }, Req};
        {error, Reason} ->
            error_response(404, Reason, Req)
    end.
