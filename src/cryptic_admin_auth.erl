%% @doc Cryptic Web Admin - Password Authentication
%%
%% Password hashing and verification for web administration accounts.
%% Uses PBKDF2-HMAC-SHA256 (built into OTP `crypto', no extra dependencies)
%% with a per-account random salt and a constant-time hash comparison.
%%
%% Account records are persisted via {@link cryptic_ca_store} in the
%% `admin_accounts' table. The database reference is resolved from the
%% `cryptic' application environment key `ca_db_ref' (same mechanism as the
%% MCP admin handler).
%%
%% == Stored password material ==
%% <ul>
%%   <li>`pw_algo'   - `<<"pbkdf2_hmac_sha256">>'</li>
%%   <li>`pw_salt'   - 16 random bytes</li>
%%   <li>`pw_hash'   - 32-byte derived key</li>
%%   <li>`kdf_params'- JSON, e.g. `{"iterations":210000,"dklen":32,"hash":"sha256"}'</li>
%% </ul>
%%
%% @author Cryptic Development Team
%% @since August 2026
-module(cryptic_admin_auth).

-include("cryptic_ca.hrl").
-include("cryptic_server.hrl").

-export([
    create_account/2,
    create_account/3,
    verify_password/2,
    set_password/2,
    hash_password/1
]).

%% PBKDF2 parameters.
-define(PW_ALGO, <<"pbkdf2_hmac_sha256">>).
-define(PBKDF2_ITERATIONS, 210000).
-define(PBKDF2_DKLEN, 32).
-define(PBKDF2_HASH, sha256).
-define(SALT_BYTES, 16).

%%====================================================================
%% API
%%====================================================================

%% @doc Create a new admin account with the given plaintext password.
%%
%% Equivalent to `create_account/3' with an empty options map.
-spec create_account(binary(), binary()) -> ok | {error, term()}.
create_account(Username, Password) ->
    create_account(Username, Password, #{}).

%% @doc Create a new admin account.
%%
%% Options:
%% <ul>
%%   <li>`must_change_password' - `boolean()' (default `false'). When `true'
%%       the account is flagged so the UI can force a password change on first
%%       login (used for bootstrap accounts seeded from a plaintext secret).</li>
%% </ul>
-spec create_account(binary(), binary(), map()) -> ok | {error, term()}.
create_account(Username, Password, Opts) when
    is_binary(Username), is_binary(Password), is_map(Opts)
->
    case validate_password(Password) of
        ok ->
            with_db(fun(DbRef) ->
                case cryptic_ca_store:get_admin_account(DbRef, Username) of
                    {ok, #admin_account{}} ->
                        {error, already_exists};
                    {error, not_found} ->
                        {Salt, Hash, KdfParams} = hash_password(Password),
                        MustChange =
                            case maps:get(must_change_password, Opts, false) of
                                true -> 1;
                                _ -> 0
                            end,
                        Account = #admin_account{
                            username = Username,
                            pw_hash = Hash,
                            pw_salt = Salt,
                            pw_algo = ?PW_ALGO,
                            kdf_params = KdfParams,
                            status = <<"active">>,
                            must_change_password = MustChange,
                            created_at = erlang:system_time(second),
                            last_login = undefined
                        },
                        cryptic_ca_store:insert_admin_account(DbRef, Account);
                    {error, _} = Error ->
                        Error
                end
            end);
        {error, _} = Error ->
            Error
    end.

%% @doc Verify a plaintext password against a stored admin account.
%%
%% Returns the account record on success so callers can inspect
%% `must_change_password' and update `last_login'. Suspended accounts are
%% rejected regardless of password correctness.
-spec verify_password(binary(), binary()) ->
    {ok, #admin_account{}} | {error, invalid_credentials | suspended | term()}.
verify_password(Username, Password) when is_binary(Username), is_binary(Password) ->
    with_db(fun(DbRef) ->
        case cryptic_ca_store:get_admin_account(DbRef, Username) of
            {ok, #admin_account{status = <<"suspended">>}} ->
                {error, suspended};
            {ok, #admin_account{} = Account} ->
                case check_password(Account, Password) of
                    true -> {ok, Account};
                    false -> {error, invalid_credentials}
                end;
            {error, not_found} ->
                %% Perform a dummy derivation to keep timing roughly uniform
                %% whether or not the username exists.
                _ = hash_password(Password),
                {error, invalid_credentials};
            {error, _} = Error ->
                Error
        end
    end).

%% @doc Replace an existing account's password. Clears `must_change_password'.
-spec set_password(binary(), binary()) -> ok | {error, term()}.
set_password(Username, NewPassword) when is_binary(Username), is_binary(NewPassword) ->
    case validate_password(NewPassword) of
        ok ->
            with_db(fun(DbRef) ->
                case cryptic_ca_store:get_admin_account(DbRef, Username) of
                    {ok, #admin_account{}} ->
                        {Salt, Hash, KdfParams} = hash_password(NewPassword),
                        cryptic_ca_store:update_admin_password(
                            DbRef, Username, Hash, Salt, KdfParams
                        );
                    {error, not_found} ->
                        {error, not_found};
                    {error, _} = Error ->
                        Error
                end
            end);
        {error, _} = Error ->
            Error
    end.

%% @doc Derive password material from a plaintext password.
%%
%% Returns `{Salt, Hash, KdfParamsJson}' using a fresh random salt.
-spec hash_password(binary()) -> {binary(), binary(), binary()}.
hash_password(Password) when is_binary(Password) ->
    Salt = crypto:strong_rand_bytes(?SALT_BYTES),
    Hash = derive(Password, Salt, ?PBKDF2_ITERATIONS, ?PBKDF2_DKLEN),
    {Salt, Hash, kdf_params_json(?PBKDF2_ITERATIONS, ?PBKDF2_DKLEN)}.

%%====================================================================
%% Internal
%%====================================================================

%% @doc Recompute the stored account's hash and compare in constant time.
-spec check_password(#admin_account{}, binary()) -> boolean().
check_password(#admin_account{pw_hash = StoredHash, pw_salt = Salt, kdf_params = KdfJson}, Password) ->
    {Iterations, DkLen} = parse_kdf_params(KdfJson),
    Candidate = derive(Password, Salt, Iterations, DkLen),
    constant_time_equal(Candidate, StoredHash).

-spec derive(binary(), binary(), pos_integer(), pos_integer()) -> binary().
derive(Password, Salt, Iterations, DkLen) ->
    crypto:pbkdf2_hmac(?PBKDF2_HASH, Password, Salt, Iterations, DkLen).

-spec kdf_params_json(pos_integer(), pos_integer()) -> binary().
kdf_params_json(Iterations, DkLen) ->
    jsx:encode(#{
        <<"iterations">> => Iterations,
        <<"dklen">> => DkLen,
        <<"hash">> => <<"sha256">>
    }).

-spec parse_kdf_params(binary()) -> {pos_integer(), pos_integer()}.
parse_kdf_params(KdfJson) ->
    try jsx:decode(KdfJson, [return_maps]) of
        Map when is_map(Map) ->
            Iterations = maps:get(<<"iterations">>, Map, ?PBKDF2_ITERATIONS),
            DkLen = maps:get(<<"dklen">>, Map, ?PBKDF2_DKLEN),
            {Iterations, DkLen}
    catch
        _:_ ->
            {?PBKDF2_ITERATIONS, ?PBKDF2_DKLEN}
    end.

%% @doc Constant-time comparison of two binaries of equal length.
%% Length is not secret here (derived keys have a fixed size).
-spec constant_time_equal(binary(), binary()) -> boolean().
constant_time_equal(A, B) when is_binary(A), is_binary(B), byte_size(A) =:= byte_size(B) ->
    0 =:=
        lists:foldl(
            fun({X, Y}, Acc) -> Acc bor (X bxor Y) end,
            0,
            lists:zip(binary_to_list(A), binary_to_list(B))
        );
constant_time_equal(_, _) ->
    false.

-spec validate_password(binary()) -> ok | {error, term()}.
validate_password(Password) when is_binary(Password) ->
    case byte_size(Password) of
        N when N < 12 -> {error, password_too_short};
        N when N > 1024 -> {error, password_too_long};
        _ -> ok
    end.

%% @doc Resolve the CA database reference and run Fun with it.
-spec with_db(fun((term()) -> Result)) -> Result | {error, ca_db_ref_not_configured}.
with_db(Fun) ->
    case application:get_env(cryptic, ca_db_ref) of
        {ok, DbRef} ->
            Fun(DbRef);
        _ ->
            ?error("cryptic_admin_auth: ca_db_ref not configured", []),
            {error, ca_db_ref_not_configured}
    end.
