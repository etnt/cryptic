%% @doc REST API handler for mobile enrollment certificate requests
%%
%% Handles Ed25519-authenticated CSR submissions from mobile clients
%% that were enrolled via QR code + passphrase flow.
%%
%% Endpoint:
%% - POST /ca/v1/mobile-csr: Submit certificate signing request
%%
%% @author Cryptic Development Team
%% @since November 2025
-module(cryptic_ca_mobile_handler).

-export([
    init/2,
    allowed_methods/2,
    content_types_accepted/2,
    content_types_provided/2,
    handle_post/2,
    handle_get/2
]).

-include("cryptic_server.hrl").
-include("../include/cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

%%====================================================================
%% Cowboy REST Callbacks
%%====================================================================

init(Req, State) ->
    {cowboy_rest, Req, State}.

allowed_methods(Req, State) ->
    {[<<"POST">>, <<"OPTIONS">>], Req, State}.

content_types_accepted(Req, State) ->
    {
        [
            {{<<"application">>, <<"json">>, '*'}, handle_post}
        ],
        Req,
        State
    }.

content_types_provided(Req, State) ->
    {
        [
            {{<<"application">>, <<"json">>, []}, handle_get}
        ],
        Req,
        State
    }.

handle_get(Req, State) ->
    ErrorBody = jsx:encode(#{
        error => <<"method_not_allowed">>,
        message => <<"Use POST to submit a mobile CSR">>
    }),
    {ErrorBody, Req, State}.

%%====================================================================
%% POST Handler
%%====================================================================

handle_post(Req, State) ->
    try
        {ok, Body, Req2} = cowboy_req:read_body(Req),
        Decoded = jsx:decode(Body, [return_maps]),

        CsrPem = maps:get(<<"csr_pem">>, Decoded),
        EnrollmentFp = maps:get(<<"enrollment_fp">>, Decoded),
        EnrollmentSigB64 = maps:get(<<"enrollment_sig_b64">>, Decoded),

        %% Rate limit per enrollment fingerprint
        case cryptic_ca_rate_limiter:check_limit(EnrollmentFp, mobile_csr, 1) of
            {ok, _Remaining} ->
                mobile_csr_impl(Req2, State, CsrPem, EnrollmentFp, EnrollmentSigB64);
            {error, rate_limited, RetryAfter} ->
                ?warning(
                    "Rate limit exceeded for mobile CSR from ~s, retry after ~p seconds",
                    [EnrollmentFp, RetryAfter]
                ),
                rate_limit_response(RetryAfter, Req2, State)
        end
    catch
        Error:CatchReason:Stack ->
            ?error(
                "Error processing mobile CSR: ~p:~p~nStack: ~p",
                [Error, CatchReason, Stack]
            ),
            error_response(<<"invalid_request">>, CatchReason, Req, State)
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

%% @private Process mobile CSR after rate limit check
mobile_csr_impl(Req, State, CsrPem, EnrollmentFp, EnrollmentSigB64) ->
    {ok, DbRef} = application:get_env(cryptic, ca_db_ref),

    %% Look up enrollment identity
    case cryptic_ca_store:get_enrollment_identity(DbRef, EnrollmentFp) of
        {ok, Identity} ->
            case Identity#enrollment_identity.status of
                <<"active">> ->
                    verify_and_issue(Req, State, DbRef, CsrPem, EnrollmentFp,
                                     EnrollmentSigB64, Identity);
                <<"consumed">> ->
                    ?warning("Mobile CSR from consumed enrollment: ~s", [EnrollmentFp]),
                    error_response(
                        <<"identity_consumed">>,
                        <<"This enrollment key has already been used.">>,
                        Req, State
                    );
                <<"suspended">> ->
                    ?warning("Mobile CSR from suspended enrollment: ~s", [EnrollmentFp]),
                    error_response(
                        <<"identity_suspended">>,
                        <<"This enrollment has been suspended. Contact an administrator.">>,
                        Req, State
                    );
                <<"revoked">> ->
                    ?warning("Mobile CSR from revoked enrollment: ~s", [EnrollmentFp]),
                    error_response(
                        <<"identity_revoked">>,
                        <<"This enrollment has been revoked. Contact an administrator.">>,
                        Req, State
                    );
                OtherStatus ->
                    ?warning("Mobile CSR from enrollment with invalid status ~s: ~s",
                             [OtherStatus, EnrollmentFp]),
                    error_response(
                        <<"invalid_status">>,
                        iolist_to_binary(io_lib:format("Status: ~p", [OtherStatus])),
                        Req, State
                    )
            end;
        {error, not_found} ->
            ?warning("Mobile CSR for unregistered enrollment: ~s", [EnrollmentFp]),
            error_response(
                <<"identity_not_found">>,
                <<"Enrollment fingerprint not registered. Contact an administrator.">>,
                Req, State
            );
        {error, Reason} ->
            ?error("Database error looking up enrollment ~s: ~p", [EnrollmentFp, Reason]),
            error_response(<<"internal_error">>, <<"Database error">>, Req, State)
    end.

%% @private Verify Ed25519 signature and issue certificate
verify_and_issue(Req, State, DbRef, CsrPem, EnrollmentFp, EnrollmentSigB64, Identity) ->
    %% Get the 32-byte Ed25519 public key
    PubKeyBytes = Identity#enrollment_identity.enrollment_pub,
    EnrollmentSig = base64:decode(EnrollmentSigB64),

    %% Verify Ed25519 signature over the CSR PEM bytes
    PubKey = {ed_pub, ed25519, PubKeyBytes},
    case public_key:verify(CsrPem, none, EnrollmentSig, PubKey) of
        true ->
            %% Signature valid — validate CSR PEM structure
            case validate_csr(CsrPem) of
                ok ->
                    ?info("Mobile CSR signature verified for ~s, issuing certificate",
                          [EnrollmentFp]),
                    issue_certificate(Req, State, DbRef, CsrPem, EnrollmentFp, Identity);
                {error, Reason} ->
                    ?warning("Mobile CSR validation failed for ~s: ~p",
                             [EnrollmentFp, Reason]),
                    error_response(
                        <<"csr_invalid">>,
                        iolist_to_binary(io_lib:format("~p", [Reason])),
                        Req, State
                    )
            end;
        false ->
            ?warning("Ed25519 signature verification failed for ~s", [EnrollmentFp]),
            error_response(
                <<"signature_invalid">>,
                <<"Ed25519 signature verification failed.">>,
                Req, State
            )
    end.

%% @private Validate CSR PEM structure
validate_csr(CsrPem) ->
    try
        [_CsrEntry] = public_key:pem_decode(CsrPem),
        ok
    catch
        _:CatchReason ->
            ?error("Failed to decode CSR PEM: ~p", [CatchReason]),
            {error, {invalid_csr_pem, CatchReason}}
    end.

%% @private Issue certificate and update database
issue_certificate(Req, State, DbRef, CsrPem, EnrollmentFp, Identity) ->
    Username = Identity#enrollment_identity.username,

    %% Issue certificate — use username as the identity, 150-day validity for mobile
    ValidityDays = application:get_env(cryptic, mobile_cert_lifetime_days, 150),
    case cryptic_ca_cert:issue_from_csr(CsrPem, EnrollmentFp, Username, ValidityDays) of
        {ok, CertPem} ->
            Now = erlang:system_time(second),
            ExpiresAt = Now + (ValidityDays * 24 * 3600),
            Serial = extract_serial_from_cert(CertPem),

            ?info("Mobile certificate ~s issued for ~s (enrollment ~s), expires in ~p days",
                  [Serial, Username, EnrollmentFp, ValidityDays]),

            %% Store certificate in database
            CertRecord = #certificate{
                serial = Serial,
                gpg_fp = EnrollmentFp,
                issued_at = Now,
                expires_at = ExpiresAt,
                status = <<"active">>,
                cert_pem = CertPem
            },
            case cryptic_ca_store:insert_certificate(DbRef, CertRecord) of
                ok -> ok;
                {error, CertReason} ->
                    ?error("Failed to insert mobile certificate ~s: ~p", [Serial, CertReason]),
                    error({cert_insert_failed, CertReason})
            end,

            %% Mark enrollment as consumed
            ok = cryptic_ca_store:update_enrollment_status(DbRef, EnrollmentFp, <<"consumed">>),
            ok = cryptic_ca_store:update_enrollment_last_seen(DbRef, EnrollmentFp),

            %% Audit log
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"mobile_certificate_issued">>,
                gpg_fp = EnrollmentFp,
                invite_id = undefined,
                details = jsx:encode(#{
                    serial => Serial,
                    username => Username,
                    validity_days => ValidityDays,
                    expires_at => ExpiresAt
                }),
                ip_address = get_ip_address(Req)
            },
            ok = cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            %% Return certificate to client
            RespBody = jsx:encode(#{
                status => <<"issued">>,
                cert_pem => CertPem,
                serial => Serial,
                expires_at => ExpiresAt,
                issued_at => Now,
                validity_days => ValidityDays
            }),
            Req2 = cowboy_req:set_resp_body(RespBody, Req),
            Req3 = cowboy_req:set_resp_header(
                <<"content-type">>, <<"application/json">>, Req2
            ),
            {true, Req3, State};

        {error, Reason} ->
            ?error("Mobile certificate issuance failed for ~s: ~p", [EnrollmentFp, Reason]),
            error_response(
                <<"issuance_failed">>,
                iolist_to_binary(io_lib:format("~p", [Reason])),
                Req, State
            )
    end.

%%====================================================================
%% Utility Functions
%%====================================================================

error_response(ErrorType, Reason, Req, State) ->
    ErrorBody = jsx:encode(#{
        error => ErrorType,
        message => format_error(Reason)
    }),
    Req2 = cowboy_req:set_resp_body(ErrorBody, Req),
    Req3 = cowboy_req:set_resp_header(
        <<"content-type">>, <<"application/json">>, Req2
    ),
    {false, Req3, State}.

format_error(Reason) when is_binary(Reason) -> Reason;
format_error(Reason) when is_atom(Reason) -> atom_to_binary(Reason, utf8);
format_error(Reason) -> iolist_to_binary(io_lib:format("~p", [Reason])).

rate_limit_response(RetryAfter, Req, State) ->
    ErrorBody = jsx:encode(#{
        error => <<"rate_limited">>,
        message => <<"Too many requests">>,
        retry_after => RetryAfter
    }),
    Req2 = cowboy_req:set_resp_body(ErrorBody, Req),
    Req3 = cowboy_req:set_resp_header(
        <<"content-type">>, <<"application/json">>, Req2
    ),
    Req4 = cowboy_req:set_resp_header(
        <<"retry-after">>, integer_to_binary(RetryAfter), Req3
    ),
    {false, Req4, State}.

get_ip_address(Req) ->
    {{A, B, C, D}, _Port} = cowboy_req:peer(Req),
    iolist_to_binary(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).

extract_serial_from_cert(CertPem) ->
    try
        [{'Certificate', DerCert, not_encrypted}] = public_key:pem_decode(CertPem),
        OtpCert = public_key:pkix_decode_cert(DerCert, otp),
        TbsCert = OtpCert#'OTPCertificate'.tbsCertificate,
        Serial = TbsCert#'OTPTBSCertificate'.serialNumber,
        list_to_binary(string:uppercase(integer_to_list(Serial, 16)))
    catch
        _:Error ->
            ?error("Failed to extract serial from certificate: ~p", [Error]),
            RandomBytes = crypto:strong_rand_bytes(16),
            list_to_binary(string:uppercase(
                lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(RandomBytes)])
            ))
    end.
