-module(cryptic_nif).

-export([
    init/0,
    gen_keypair/0,
    scalarmult/2,
    aead_encrypt/3,
    aead_decrypt/4,
    rand_bytes/1
]).

-on_load(init/0).

-define(APPNAME, cryptic).
-define(LIBNAME, cryptic_nif).

init() ->
    SoName =
        case code:priv_dir(?APPNAME) of
            {error, bad_name} ->
                case filelib:is_dir(filename:join(["..", priv])) of
                    true ->
                        filename:join(["..", priv, ?LIBNAME]);
                    _ ->
                        filename:join([priv, ?LIBNAME])
                end;
            Dir ->
                filename:join(Dir, ?LIBNAME)
        end,
    erlang:load_nif(SoName, 0).

%% NIF stubs - these will be replaced by the actual NIF implementations
gen_keypair() ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

scalarmult(_SecretKey, _PublicKey) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

aead_encrypt(_Plaintext, _Key, _AAD) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

aead_decrypt(_Ciphertext, _Key, _Nonce, _AAD) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).

rand_bytes(_Size) ->
    erlang:nif_error({nif_not_loaded, ?MODULE}).
