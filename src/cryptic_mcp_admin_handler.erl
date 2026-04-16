-module(cryptic_mcp_admin_handler).

-export([init/2]).

-include("cryptic.hrl").
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
            case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"suspended">>) of
                ok ->
                    Now = erlang:system_time(second),
                    AuditResult = log_audit(DbRef, <<"user_suspended">>, GpgFp, #{
                        suspended_by => AdminFp,
                        reason => Reason
                    }, Req, Now),
                    log_audit_result(AuditResult, <<"user_suspended">>, GpgFp),
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
            case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"revoked">>) of
                ok ->
                    Now = erlang:system_time(second),
                    AuditResult = log_audit(DbRef, <<"user_revoked">>, GpgFp, #{
                        revoked_by => AdminFp,
                        reason => Reason
                    }, Req, Now),
                    log_audit_result(AuditResult, <<"user_revoked">>, GpgFp),
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
            case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
                {ok, #gpg_identity{status = <<"revoked">>}} ->
                    {400, #{
                        type => <<"reactivate_user_response">>,
                        status => <<"error">>,
                        error => <<"cannot_reactivate_revoked">>,
                        message => <<"Revoked users cannot be reactivated">>
                    }, Req};
                {ok, #gpg_identity{status = <<"active">>}} ->
                    {200, #{
                        type => <<"reactivate_user_response">>,
                        status => <<"success">>,
                        gpg_fp => GpgFp,
                        message => <<"User already active">>
                    }, Req};
                {ok, _Identity} ->
                    case cryptic_ca_store:update_user_status(DbRef, GpgFp, <<"active">>) of
                        ok ->
                            Now = erlang:system_time(second),
                            AuditResult = log_audit(DbRef, <<"user_reactivated">>, GpgFp, #{
                                reactivated_by => AdminFp
                            }, Req, Now),
                            log_audit_result(AuditResult, <<"user_reactivated">>, GpgFp),
                            {200, #{
                                type => <<"reactivate_user_response">>,
                                status => <<"success">>,
                                gpg_fp => GpgFp,
                                new_status => <<"active">>,
                                reactivated_by => AdminFp,
                                reactivated_at => Now
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
    case cryptic_ca_store:list_gpg_identities(DbRef) of
        {ok, Identities} ->
            FilteredIdentities =
                case Filter of
                    undefined -> Identities;
                    <<>> -> Identities;
                    FilterStatus ->
                        lists:filter(
                            fun(#gpg_identity{status = S}) ->
                                S =:= FilterStatus
                            end,
                            Identities
                        )
                end,
            Users = [
                encode_user(DbRef, Identity)
                || Identity <- FilteredIdentities
            ],
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
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{
                status = Status,
                registered_by = RegBy,
                registered_at = RegAt,
                last_seen = LastSeen,
                metadata = Meta
               }} ->
            UserInfo = maybe_attach_metadata(#{
                gpg_fp => GpgFp,
                status => Status,
                registered_by => RegBy,
                registered_at => RegAt,
                last_seen => LastSeen
            }, Meta),
            {200, #{
                type => <<"get_user_info_response">>,
                status => <<"success">>,
                user => UserInfo
            }, Req};
        {error, Reason} ->
            error_response(404, Reason, Req)
    end.

list_certificates(DbRef, GpgFp, Req) ->
    case cryptic_ca_store:list_certificates_by_user(DbRef, GpgFp) of
        {ok, Certs} ->
            CertList = lists:map(
                fun(Cert) ->
                    #{
                        serial => Cert#certificate.serial,
                        issued_at => Cert#certificate.issued_at,
                        expires_at => Cert#certificate.expires_at,
                        status => Cert#certificate.status,
                        revoked_at => Cert#certificate.revoked_at,
                        revoked_by => Cert#certificate.revoked_by,
                        revoked_reason => Cert#certificate.revoked_reason
                    }
                end,
                Certs
            ),
            {200, #{
                type => <<"list_certificates_response">>,
                status => <<"success">>,
                gpg_fp => GpgFp,
                certificates => CertList,
                count => length(Certs)
            }, Req};
        {error, Reason} ->
            error_response(404, Reason, Req)
    end.

encode_user(DbRef, #gpg_identity{
    gpg_fp = Fp,
    status = Status,
    registered_by = RegBy,
    registered_at = RegAt,
    last_seen = LastSeen,
    metadata = Meta
}) ->
    Username = case get_username_from_gpg_fp(DbRef, Fp) of
        {ok, Name} -> list_to_binary(Name);
        {error, _Reason} -> <<"unknown">>
    end,
    UserMap = #{
        gpg_fp => Fp,
        username => Username,
        status => Status,
        registered_by => RegBy,
        registered_at => RegAt,
        last_seen => LastSeen,
        online => is_online(Username)
    },
    maybe_attach_metadata(UserMap, Meta).

maybe_attach_metadata(UserMap, undefined) ->
    UserMap;
maybe_attach_metadata(UserMap, Meta) ->
    try
        MetaMap = jsx:decode(Meta, [return_maps]),
        UserMap#{metadata => MetaMap}
    catch
        _:_ -> UserMap
    end.

get_username_from_gpg_fp(DbRef, GpgFp) ->
    case cryptic_ca_store:list_certificates_by_user(DbRef, GpgFp) of
        {ok, []} ->
            {error, not_found};
        {ok, [LatestCert | _]} ->
            extract_username_from_cert_pem(LatestCert#certificate.cert_pem);
        {error, Reason} ->
            {error, Reason}
    end.

extract_username_from_cert_pem(CertPem) ->
    try
        [DecodedEntry | _] = public_key:pem_decode(CertPem),
        CertDer = public_key:pem_entry_decode(DecodedEntry),
        Cert = public_key:pkix_decode_cert(CertDer, otp),
        TBSCert = Cert#'OTPCertificate'.tbsCertificate,
        Subject = TBSCert#'OTPTBSCertificate'.subject,
        case extract_common_name(Subject) of
            {ok, CN} -> {ok, CN};
            _ -> {error, no_cn}
        end
    catch
        _:_ ->
            {error, cert_decode_failed}
    end.

extract_common_name({rdnSequence, RDNs}) ->
    extract_cn_from_rdns(RDNs).

extract_cn_from_rdns([]) ->
    {error, no_cn_found};
extract_cn_from_rdns([RDN | Rest]) ->
    case extract_cn_from_rdn(RDN) of
        {ok, CN} -> {ok, CN};
        not_found -> extract_cn_from_rdns(Rest)
    end.

extract_cn_from_rdn([]) ->
    not_found;
extract_cn_from_rdn([#'AttributeTypeAndValue'{
    type = {2, 5, 4, 3},
    value = {_Type, Value}
} | _]) ->
    {ok, Value};
extract_cn_from_rdn([_ | Rest]) ->
    extract_cn_from_rdn(Rest).

find_user_connection(User) when is_binary(User) ->
    find_user_connection(binary_to_list(User));
find_user_connection(User) when is_list(User) ->
    case ets:lookup(user_connections, User) of
        [{User, Pid}] when is_pid(Pid) ->
            case is_process_alive(Pid) of
                true -> {ok, Pid};
                false -> not_found
            end;
        _ ->
            not_found
    end.

is_online(User) ->
    case find_user_connection(User) of
        {ok, _Pid} -> true;
        not_found -> false
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
