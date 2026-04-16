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

%%%===================================================================
%%% Server Status
%%%===================================================================

get_server_status(DbRef, Req) ->
    %% Listener info
    Listener = try ranch:info(cryptic_ws_listener) of
        Info when is_map(Info) ->
            Port = maps:get(port, Info, null),
            ActiveConns = ranch:procs(cryptic_ws_listener, connections),
            #{status => <<"running">>, port => Port,
              active_connections => length(ActiveConns)};
        _ ->
            #{status => <<"not_running">>}
    catch
        _:_ -> #{status => <<"not_running">>}
    end,

    %% ETS table sizes
    Tables = [
        {?CONNECTION_TABLE, <<"connections">>},
        {?USER_TABLE, <<"registered_users">>},
        {?MESSAGE_TABLE, <<"pending_messages">>},
        {?PREKEY_TABLE, <<"prekey_entries">>}
    ],
    EtsTables = lists:map(fun({Table, Label}) ->
        Size = case ets:info(Table, size) of
            undefined -> null;
            S -> S
        end,
        #{name => Label, size => Size}
    end, Tables),

    %% CA status
    CaStatus = case cryptic_ca_store:list_gpg_identities(DbRef) of
        {ok, Identities} ->
            Active = length([I || I <- Identities,
                                  I#gpg_identity.status =:= <<"active">>]),
            Suspended = length([I || I <- Identities,
                                     I#gpg_identity.status =:= <<"suspended">>]),
            Revoked = length([I || I <- Identities,
                                   I#gpg_identity.status =:= <<"revoked">>]),
            #{status => <<"connected">>,
              active => Active, suspended => Suspended, revoked => Revoked};
        {error, _} ->
            #{status => <<"error">>}
    end,

    {200, #{
        type => <<"status_response">>,
        status => <<"success">>,
        listener => Listener,
        ets_tables => EtsTables,
        ca => CaStatus
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
    case cryptic_ca_store:get_audit_logs(DbRef, Limit, 0) of
        {ok, Logs} ->
            LogList = lists:map(fun(Log) ->
                #{
                    timestamp => Log#audit_log.timestamp,
                    event_type => Log#audit_log.event_type,
                    gpg_fp => coalesce(Log#audit_log.gpg_fp, null),
                    invite_id => coalesce(Log#audit_log.invite_id, null),
                    details => parse_details(Log#audit_log.details),
                    ip_address => coalesce(Log#audit_log.ip_address, null)
                }
            end, Logs),
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

coalesce(undefined, Default) -> Default;
coalesce(Value, _Default) -> Value.

parse_details(undefined) -> null;
parse_details(Details) ->
    try jsx:decode(Details, [return_maps])
    catch _:_ -> Details
    end.

%%%===================================================================
%%% Enrollment Identities
%%%===================================================================

list_enrollments(DbRef, Filter, Req) ->
    case cryptic_ca_store:list_enrollment_identities(DbRef) of
        {ok, Identities} ->
            Filtered = case Filter of
                undefined -> Identities;
                <<>> -> Identities;
                FilterStatus ->
                    [I || I <- Identities,
                          I#enrollment_identity.status =:= FilterStatus]
            end,
            Enrollments = lists:map(fun(I) ->
                E = #{
                    enrollment_fp => I#enrollment_identity.enrollment_fp,
                    username => I#enrollment_identity.username,
                    status => I#enrollment_identity.status,
                    registered_by => coalesce(I#enrollment_identity.registered_by, null),
                    registered_at => I#enrollment_identity.registered_at,
                    consumed_at => coalesce(I#enrollment_identity.consumed_at, null),
                    last_seen => coalesce(I#enrollment_identity.last_seen, null)
                },
                maybe_attach_metadata(E, I#enrollment_identity.metadata)
            end, Filtered),
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
    case cryptic_ca_store:get_enrollment_identity(DbRef, EnrollmentFp) of
        {ok, I} ->
            Info = #{
                enrollment_fp => I#enrollment_identity.enrollment_fp,
                username => I#enrollment_identity.username,
                status => I#enrollment_identity.status,
                registered_by => coalesce(I#enrollment_identity.registered_by, null),
                registered_at => I#enrollment_identity.registered_at,
                consumed_at => coalesce(I#enrollment_identity.consumed_at, null),
                last_seen => coalesce(I#enrollment_identity.last_seen, null)
            },
            InfoWithMeta = maybe_attach_metadata(Info, I#enrollment_identity.metadata),
            {200, #{
                type => <<"get_enrollment_info_response">>,
                status => <<"success">>,
                enrollment => InfoWithMeta
            }, Req};
        {error, Reason} ->
            error_response(404, Reason, Req)
    end.
