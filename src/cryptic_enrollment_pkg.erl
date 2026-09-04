%% @doc Cryptic Web Admin - Mobile Enrollment Package Builder
%%
%% Erlang port of the `create-mobile-enrollment' command in
%% `bin/cryptic-onboard'. Given a username and a passphrase, this module:
%% <ol>
%%   <li>generates a fresh Ed25519 enrollment keypair;</li>
%%   <li>registers the corresponding `enrollment_identity' on the server
%%       (the same store path used by the mTLS
%%       `POST /ca/v1/admin/register-enrollment' endpoint);</li>
%%   <li>builds the v2 enrollment payload and encrypts it with
%%       Argon2id + AES-256-CBC + HMAC-SHA256;</li>
%%   <li>returns the encrypted QR envelope so the browser can render the
%%       QR code client-side.</li>
%% </ol>
%%
%% == Wire format (v2) ==
%%
%% The returned `package' is a JSON object matching the format the mobile
%% client expects:
%% ```
%% {"v":2, "salt":<hex>, "iv":<hex>, "ct":<base64>, "hmac":<hex>}
%% '''
%% where the plaintext (before encryption) is the payload JSON:
%% ```
%% {"username", "server_host", "server_port", "ca_fingerprint",
%%  "enrollment_pub", "enrollment_sec", "issued_at", "expires_at",
%%  "full_name"?, "email"?}
%% '''
%%
%% == Cryptographic parameters ==
%%
%% These are fixed to match `bin/cryptic-onboard' exactly so packages remain
%% interchangeable:
%% <ul>
%%   <li>KDF: Argon2id v1.3, t=3, m=65536 KiB (64 MiB), p=4, 64-byte output.
%%       The salt fed to Argon2 is the lowercase-hex encoding of 16 random
%%       bytes (32 ASCII characters), which is also what is stored in the
%%       `salt' envelope field.</li>
%%   <li>The 64 derived bytes are split into a 32-byte AES-256 key and a
%%       32-byte HMAC-SHA256 key.</li>
%%   <li>Cipher: AES-256-CBC with PKCS#7 padding and a random 16-byte IV
%%       (stored hex-encoded in the `iv' field).</li>
%%   <li>MAC: HMAC-SHA256 over the base64 ciphertext string, hex-encoded.</li>
%% </ul>
%%
%% The passphrase is never logged and the encrypted package is returned once
%% (never persisted); only the public enrollment identity is stored.
%%
%% @author Cryptic Development Team
%% @since August 2026
-module(cryptic_enrollment_pkg).

-export([create/1, server_cert_sans/0]).

-include("cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

%% Argon2id parameters — must match bin/cryptic-onboard (`-id -t 3 -m 16 -p 4 -l 64').
-define(ARGON2_TIME_COST, 3).
-define(ARGON2_MEMORY_KIB, 65536).
-define(ARGON2_PARALLELISM, 4).
-define(ARGON2_HASH_LEN, 64).

-define(PAYLOAD_VERSION, 2).
-define(DEFAULT_EXPIRY_SECONDS, 31536000). %% 1 year
-define(MIN_EXPIRY_SECONDS, 3600). %% 1 hour
-define(MAX_EXPIRY_SECONDS, 63072000). %% 2 years

-type params() :: #{
    db_ref := term(),
    username := binary(),
    passphrase := binary(),
    actor_id := binary(),
    ip := binary(),
    expiry_seconds => pos_integer(),
    full_name => binary() | undefined,
    email => binary() | undefined,
    server_host => binary(),
    server_port => pos_integer()
}.

-type result() :: #{
    enrollment_fp := binary(),
    username := binary(),
    package := binary(),
    expires_at := pos_integer(),
    payload_version := pos_integer()
}.

%% @doc Generate, register, and package a mobile enrollment identity.
%%
%% Returns `{ok, Result}' on success or `{error, Reason}' if the enrollment
%% identity could not be stored. The `package' field of the result is the
%% JSON QR envelope described in the module docs.
-spec create(params()) -> {ok, result()} | {error, term()}.
create(#{db_ref := DbRef,
         username := Username,
         passphrase := Passphrase,
         actor_id := ActorId,
         ip := Ip} = Params) ->
    Expiry = clamp_expiry(maps:get(expiry_seconds, Params, ?DEFAULT_EXPIRY_SECONDS)),

    %% 0. The server_host baked into the package must be covered by a SAN on the
    %% messaging server certificate, or the mobile client's TLS handshake fails.
    case validate_server_host(server_host(Params)) of
        ok ->
            create_validated(DbRef, Username, Passphrase, ActorId, Ip, Expiry, Params);
        {error, _} = Err ->
            Err
    end.

create_validated(DbRef, Username, Passphrase, ActorId, Ip, Expiry, Params) ->
    %% 1. Fresh Ed25519 enrollment keypair.
    {PubRaw, SeedRaw} = crypto:generate_key(eddsa, ed25519),
    %% Store the secret as a PKCS#8 DER PrivateKeyInfo, byte-identical to what
    %% `openssl pkey -outform DER' produces in bin/cryptic-onboard. The 32-byte
    %% seed lives in the last 32 bytes of the DER; the mobile client extracts it
    %% and pairs it with enrollment_pub to sign.
    SecDer = ed25519_pkcs8_der(SeedRaw),
    Fp = hex(crypto:hash(sha256, PubRaw)),

    %% 2. Register the public enrollment identity server-side.
    case register_enrollment(DbRef, Fp, PubRaw, Username, ActorId, Ip) of
        ok ->
            Now = erlang:system_time(second),
            ExpiresAt = Now + Expiry,
            PayloadJson = build_payload(Username, PubRaw, SecDer, ca_fingerprint(),
                                        Now, ExpiresAt, Params),
            Package = encrypt_payload(PayloadJson, Passphrase),
            {ok, #{
                enrollment_fp => Fp,
                username => Username,
                package => Package,
                expires_at => ExpiresAt,
                payload_version => ?PAYLOAD_VERSION
            }};
        {error, Reason} ->
            {error, Reason}
    end.

%%====================================================================
%% Internal: server-side registration
%%====================================================================

-spec register_enrollment(term(), binary(), binary(), binary(), binary(), binary()) ->
    ok | {error, term()}.
register_enrollment(DbRef, Fp, PubRaw, Username, ActorId, Ip) ->
    Now = erlang:system_time(second),
    Identity = #enrollment_identity{
        enrollment_fp = Fp,
        enrollment_pub = PubRaw,
        username = Username,
        status = <<"active">>,
        registered_by = ActorId,
        registered_at = Now,
        consumed_at = undefined,
        last_seen = undefined,
        metadata = undefined
    },
    case cryptic_ca_store:insert_enrollment_identity(DbRef, Identity) of
        ok ->
            Audit = #audit_log{
                timestamp = Now,
                event_type = <<"enrollment_registered">>,
                gpg_fp = Fp,
                invite_id = undefined,
                details = jsx:encode(#{
                    username => Username,
                    registered_by => ActorId,
                    via => <<"webadmin">>
                }),
                ip_address = Ip
            },
            _ = cryptic_ca_store:insert_audit_log(DbRef, Audit),
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

%%====================================================================
%% Internal: payload + encryption
%%====================================================================

-spec build_payload(binary(), binary(), binary(), binary() | null,
                    pos_integer(), pos_integer(), params()) -> binary().
build_payload(Username, PubRaw, SecRaw, CaFp, IssuedAt, ExpiresAt, Params) ->
    Base = #{
        <<"username">> => Username,
        <<"server_host">> => server_host(Params),
        <<"server_port">> => server_port(Params),
        <<"ca_fingerprint">> => CaFp,
        <<"enrollment_pub">> => base64:encode(PubRaw),
        <<"enrollment_sec">> => base64:encode(SecRaw),
        <<"issued_at">> => IssuedAt,
        <<"expires_at">> => ExpiresAt
    },
    WithName = maybe_put(<<"full_name">>, maps:get(full_name, Params, undefined), Base),
    WithEmail = maybe_put(<<"email">>, maps:get(email, Params, undefined), WithName),
    jsx:encode(WithEmail).

-spec encrypt_payload(binary(), binary()) -> binary().
encrypt_payload(PayloadJson, Passphrase) ->
    %% The salt fed to Argon2 is the 32-char hex string (its ASCII bytes),
    %% which is also what gets stored in the envelope. This matches the
    %% `argon2 "$SALT"' invocation in bin/cryptic-onboard.
    SaltHex = hex(crypto:strong_rand_bytes(16)),
    IvBytes = crypto:strong_rand_bytes(16),
    IvHex = hex(IvBytes),

    Derived = cryptic_nif:argon2id_raw(Passphrase, SaltHex,
                                       ?ARGON2_TIME_COST, ?ARGON2_MEMORY_KIB,
                                       ?ARGON2_PARALLELISM, ?ARGON2_HASH_LEN),
    <<EncKey:32/binary, HmacKey:32/binary>> = Derived,

    Cipher = crypto:crypto_one_time(aes_256_cbc, EncKey, IvBytes, PayloadJson,
                                    [{encrypt, true}, {padding, pkcs_padding}]),
    CtB64 = base64:encode(Cipher),
    Hmac = hex(crypto:mac(hmac, sha256, HmacKey, CtB64)),

    jsx:encode(#{
        <<"v">> => ?PAYLOAD_VERSION,
        <<"salt">> => SaltHex,
        <<"iv">> => IvHex,
        <<"ct">> => CtB64,
        <<"hmac">> => Hmac
    }).

%%====================================================================
%% Internal: helpers
%%====================================================================

-spec ca_fingerprint() -> binary() | null.
ca_fingerprint() ->
    case application:get_env(cryptic, ca_cert) of
        {ok, CaCert} ->
            try
                Der = public_key:pkix_encode('OTPCertificate', CaCert, otp),
                hex(crypto:hash(sha256, Der))
            catch
                _:_ -> null
            end;
        _ ->
            null
    end.

-spec server_host(params()) -> binary().
server_host(Params) ->
    case maps:get(server_host, Params, undefined) of
        Host when is_binary(Host), Host =/= <<>> ->
            Host;
        _ ->
            case os:getenv("CRYPTIC_PUBLIC_HOST") of
                false -> <<"localhost">>;
                "" -> <<"localhost">>;
                Env -> list_to_binary(Env)
            end
    end.

-spec server_port(params()) -> pos_integer().
server_port(Params) ->
    case maps:get(server_port, Params, undefined) of
        Port when is_integer(Port), Port > 0 ->
            Port;
        _ ->
            case os:getenv("CRYPTIC_SERVER_PORT") of
                false -> 8443;
                "" -> 8443;
                Env ->
                    try list_to_integer(Env) of
                        N when N > 0 -> N;
                        _ -> 8443
                    catch
                        _:_ -> 8443
                    end
            end
    end.

%%====================================================================
%% Internal: server certificate SAN validation
%%====================================================================

%% @doc Return the Subject Alternative Names on the messaging server
%% certificate as a list of binaries (DNS names and IP literals). Used both to
%% validate enrollment `server_host' values and to populate the web-admin host
%% picker. Returns `{error, Reason}' if the certificate cannot be read/parsed.
-spec server_cert_sans() -> {ok, [binary()]} | {error, term()}.
server_cert_sans() ->
    case cryptic_lib:get_server_file("CRYPTIC_SERVER_CERT", server_cert_file) of
        undefined ->
            {error, no_server_cert};
        File ->
            case file:read_file(File) of
                {ok, Pem} ->
                    parse_cert_sans(Pem);
                {error, Reason} ->
                    {error, {read_failed, Reason}}
            end
    end.

-spec parse_cert_sans(binary()) -> {ok, [binary()]} | {error, term()}.
parse_cert_sans(Pem) ->
    try
        case public_key:pem_decode(Pem) of
            [{'Certificate', Der, _} | _] ->
                OTPCert = public_key:pkix_decode_cert(Der, otp),
                {ok, extract_sans(OTPCert)};
            _ ->
                {error, no_certificate_in_pem}
        end
    catch
        _:CatchReason ->
            {error, {cert_parse_failed, CatchReason}}
    end.

-spec extract_sans(#'OTPCertificate'{}) -> [binary()].
extract_sans(#'OTPCertificate'{tbsCertificate = TBS}) ->
    Exts = case TBS#'OTPTBSCertificate'.extensions of
               asn1_NOVALUE -> [];
               Es when is_list(Es) -> Es;
               _ -> []
           end,
    case lists:filter(fun(#'Extension'{extnID = ?'id-ce-subjectAltName'}) -> true;
                         (_) -> false
                      end, Exts) of
        [#'Extension'{extnValue = GeneralNames} | _] when is_list(GeneralNames) ->
            lists:filtermap(fun san_to_binary/1, GeneralNames);
        _ ->
            []
    end.

-spec san_to_binary(term()) -> {true, binary()} | false.
san_to_binary({dNSName, Name}) ->
    {true, to_bin(Name)};
san_to_binary({iPAddress, Ip}) ->
    case format_ip(iolist_to_binary([Ip])) of
        <<>> -> false;
        Bin -> {true, Bin}
    end;
san_to_binary(_) ->
    false.

-spec format_ip(binary()) -> binary().
format_ip(Bin) when byte_size(Bin) =:= 4 ->
    <<A, B, C, D>> = Bin,
    list_to_binary(inet:ntoa({A, B, C, D}));
format_ip(Bin) when byte_size(Bin) =:= 16 ->
    Groups = [G || <<G:16>> <= Bin],
    list_to_binary(inet:ntoa(list_to_tuple(Groups)));
format_ip(_) ->
    <<>>.

-spec to_bin(binary() | list()) -> binary().
to_bin(V) when is_binary(V) -> V;
to_bin(V) when is_list(V) -> list_to_binary(V).

%% @doc Ensure the requested `server_host' is covered by a certificate SAN.
%% If the certificate cannot be read we allow the enrollment (fail-open) so a
%% missing/unreadable cert never blocks provisioning, but log the reason.
-spec validate_server_host(binary()) -> ok | {error, term()}.
validate_server_host(Host) ->
    case server_cert_sans() of
        {ok, Sans} ->
            case host_matches_sans(Host, Sans) of
                true ->
                    ok;
                false ->
                    {error, {server_host_not_in_cert, Host, Sans}}
            end;
        {error, Reason} ->
            error_logger:warning_msg(
                "cryptic_enrollment_pkg: skipping server_host SAN check "
                "(cert unavailable: ~p)~n", [Reason]),
            ok
    end.

-spec host_matches_sans(binary(), [binary()]) -> boolean().
host_matches_sans(Host, Sans) ->
    Lower = string:lowercase(Host),
    lists:any(fun(San) -> san_matches(Lower, string:lowercase(San)) end, Sans).

%% Exact match, or wildcard SAN (`*.example.com') matching a single label.
-spec san_matches(binary(), binary()) -> boolean().
san_matches(Host, Host) ->
    true;
san_matches(Host, <<"*.", Suffix/binary>>) ->
    case binary:split(Host, <<".">>) of
        [_Label, Rest] -> Rest =:= Suffix;
        _ -> false
    end;
san_matches(_, _) ->
    false.


clamp_expiry(Seconds) when is_integer(Seconds), Seconds >= ?MIN_EXPIRY_SECONDS,
                           Seconds =< ?MAX_EXPIRY_SECONDS ->
    Seconds;
clamp_expiry(Seconds) when is_integer(Seconds), Seconds > ?MAX_EXPIRY_SECONDS ->
    ?MAX_EXPIRY_SECONDS;
clamp_expiry(Seconds) when is_integer(Seconds), Seconds > 0, Seconds < ?MIN_EXPIRY_SECONDS ->
    ?MIN_EXPIRY_SECONDS;
clamp_expiry(_) ->
    ?DEFAULT_EXPIRY_SECONDS.

-spec maybe_put(binary(), binary() | undefined, map()) -> map().
maybe_put(_Key, undefined, Map) -> Map;
maybe_put(_Key, <<>>, Map) -> Map;
maybe_put(Key, Value, Map) when is_binary(Value) -> Map#{Key => Value}.

-spec hex(binary()) -> binary().
hex(Bin) ->
    binary:encode_hex(Bin, lowercase).

%% @doc Wrap a raw 32-byte Ed25519 seed in a PKCS#8 PrivateKeyInfo (DER).
%%
%% The structure is fixed for Ed25519, so a constant 16-byte ASN.1 prefix
%% followed by the seed reproduces exactly what `openssl pkey -outform DER'
%% emits (see bin/cryptic-onboard). The seed is the trailing 32 bytes.
-spec ed25519_pkcs8_der(binary()) -> binary().
ed25519_pkcs8_der(Seed) when byte_size(Seed) =:= 32 ->
    %% SEQUENCE(0x2e) { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTETSTRING { OCTETSTRING(0x20) seed } }
    Prefix = <<16#30, 16#2e, 16#02, 16#01, 16#00, 16#30, 16#05,
               16#06, 16#03, 16#2b, 16#65, 16#70, 16#04, 16#22,
               16#04, 16#20>>,
    <<Prefix/binary, Seed/binary>>.
