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

-export([create/1]).

-include("cryptic_ca.hrl").

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

    %% 1. Fresh Ed25519 enrollment keypair.
    {PubRaw, SeedRaw} = crypto:generate_key(eddsa, ed25519),
    %% Store the secret as seed||public (libsodium 64-byte secret key layout)
    %% so the mobile client can sign directly.
    SecRaw = <<SeedRaw/binary, PubRaw/binary>>,
    Fp = hex(crypto:hash(sha256, PubRaw)),

    %% 2. Register the public enrollment identity server-side.
    case register_enrollment(DbRef, Fp, PubRaw, Username, ActorId, Ip) of
        ok ->
            Now = erlang:system_time(second),
            ExpiresAt = Now + Expiry,
            PayloadJson = build_payload(Username, PubRaw, SecRaw, ca_fingerprint(),
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

-spec clamp_expiry(term()) -> pos_integer().
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
