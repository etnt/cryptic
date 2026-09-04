%% @doc REST API handler for admin enrollment operations
%%
%% Handles admin-only operations for mobile enrollment management,
%% authenticated via mTLS client certificate.
%%
%% Endpoint:
%% - POST /ca/v1/admin/register-enrollment: Register a new enrollment key
%%
%% @author Cryptic Development Team
%% @since November 2025
-module(cryptic_ca_admin_handler).

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
        message => <<"Use POST to register an enrollment key">>
    }),
    {ErrorBody, Req, State}.

%%====================================================================
%% POST Handler
%%====================================================================

handle_post(Req, #{operation := register_enrollment} = State) ->
    %% Require mTLS client certificate for admin authentication
    case cowboy_req:cert(Req) of
        undefined ->
            ?warning("Admin register-enrollment attempt without client certificate from ~s",
                     [get_ip_address(Req)]),
            error_response(
                <<"authentication_required">>,
                <<"Admin mTLS client certificate required.">>,
                Req, State
            );
        PeerCertDer ->
            handle_register_enrollment(Req, State, PeerCertDer)
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

handle_register_enrollment(Req, State, PeerCertDer) ->
    try
        %% Extract admin identity from mTLS certificate
        AdminId = extract_cn_from_cert(PeerCertDer),
        ?info("Admin register-enrollment request from ~s (~s)",
              [AdminId, get_ip_address(Req)]),

        {ok, Body, Req2} = cowboy_req:read_body(Req),
        Decoded = jsx:decode(Body, [return_maps]),

        EnrollmentFp = maps:get(<<"enrollment_fp">>, Decoded),
        EnrollmentPubB64 = maps:get(<<"enrollment_pub_b64">>, Decoded),
        Username = maps:get(<<"username">>, Decoded),

        %% Decode and validate the Ed25519 public key (must be 32 bytes)
        EnrollmentPub = base64:decode(EnrollmentPubB64),
        case byte_size(EnrollmentPub) of
            32 ->
                register_enrollment_impl(Req2, State, EnrollmentFp,
                                         EnrollmentPub, Username, AdminId);
            Other ->
                ?warning("Invalid Ed25519 public key size: ~p bytes", [Other]),
                error_response(
                    <<"invalid_key">>,
                    <<"Ed25519 public key must be exactly 32 bytes.">>,
                    Req2, State
                )
        end
    catch
        Error:CatchReason:Stack ->
            ?error(
                "Error processing register-enrollment: ~p:~p~nStack: ~p",
                [Error, CatchReason, Stack]
            ),
            error_response(<<"invalid_request">>, CatchReason, Req, State)
    end.

register_enrollment_impl(Req, State, EnrollmentFp, EnrollmentPub, Username, AdminId) ->
    {ok, DbRef} = application:get_env(cryptic, ca_db_ref),
    Now = erlang:system_time(second),

    Identity = #enrollment_identity{
        enrollment_fp = EnrollmentFp,
        enrollment_pub = EnrollmentPub,
        username = Username,
        status = <<"active">>,
        registered_by = AdminId,
        registered_at = Now,
        consumed_at = undefined,
        last_seen = undefined,
        metadata = undefined
    },

    case cryptic_ca_store:insert_enrollment_identity(DbRef, Identity) of
        ok ->
            ?info("Enrollment identity registered: ~s for user ~s by admin ~s",
                  [EnrollmentFp, Username, AdminId]),

            %% Audit log
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"enrollment_registered">>,
                gpg_fp = EnrollmentFp,
                invite_id = undefined,
                details = jsx:encode(#{
                    username => Username,
                    registered_by => AdminId
                }),
                ip_address = get_ip_address(Req)
            },
            ok = cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            RespBody = jsx:encode(#{
                status => <<"registered">>,
                enrollment_fp => EnrollmentFp,
                username => Username
            }),
            Req2 = cowboy_req:set_resp_body(RespBody, Req),
            Req3 = cowboy_req:set_resp_header(
                <<"content-type">>, <<"application/json">>, Req2
            ),
            {true, Req3, State};

        {error, Reason} ->
            ?error("Failed to register enrollment identity ~s: ~p",
                   [EnrollmentFp, Reason]),
            error_response(
                <<"registration_failed">>,
                iolist_to_binary(io_lib:format("~p", [Reason])),
                Req, State
            )
    end.

%%====================================================================
%% Utility Functions
%%====================================================================

%% @private Extract Common Name from DER-encoded peer certificate
extract_cn_from_cert(CertDer) ->
    OtpCert = public_key:pkix_decode_cert(CertDer, otp),
    TbsCert = OtpCert#'OTPCertificate'.tbsCertificate,
    Subject = TbsCert#'OTPTBSCertificate'.subject,
    case Subject of
        {rdnSequence, RdnSeq} ->
            extract_cn_from_rdn(RdnSeq);
        _ ->
            <<"unknown">>
    end.

extract_cn_from_rdn([]) -> <<"unknown">>;
extract_cn_from_rdn([Rdn | Rest]) ->
    case lists:keyfind(?'id-at-commonName', #'AttributeTypeAndValue'.type, Rdn) of
        #'AttributeTypeAndValue'{value = {utf8String, CN}} -> CN;
        #'AttributeTypeAndValue'{value = {printableString, CN}} ->
            list_to_binary(CN);
        #'AttributeTypeAndValue'{value = CN} when is_binary(CN) -> CN;
        #'AttributeTypeAndValue'{value = CN} when is_list(CN) ->
            list_to_binary(CN);
        _ ->
            extract_cn_from_rdn(Rest)
    end.

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

get_ip_address(Req) ->
    {{A, B, C, D}, _Port} = cowboy_req:peer(Req),
    iolist_to_binary(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).
