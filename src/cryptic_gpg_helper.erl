%% @doc Cryptic GPG Helper - Client-side GPG key management
%%
%% This module provides helper functions for managing GPG keys on the
%% client side, particularly for Docker container environments where
%% GPG keys need to be imported from the cryptic data directory.
%%
%% == Purpose ==
%% When running the Cryptic client in a Docker container, the container
%% has its own isolated GPG keyring (empty by default). For certificate
%% auto-renewal to work, the user's GPG secret key must be imported.
%%
%% During onboarding, the GPG secret key is exported to:
%% `~/.cryptic/<username>/<server>_<port>/gpg_secret_key.asc`
%%
%% This module provides functions to import that key into the container's
%% GPG keyring.
%%
%% == Integration with erl_gpg ==
%% All GPG operations are delegated to the `erl_gpg_api' module, which
%% handles the actual interaction with the GPG command-line tool.
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since December 2025
-module(cryptic_gpg_helper).

-export([
    import_secret_key/1,
    import_secret_key/3,
    check_secret_key_available/1,
    get_secret_key_path/3,
    list_secret_keys/0
]).

-include("cryptic.hrl").

%%====================================================================
%% API Functions
%%====================================================================

%% @doc Import GPG secret key from a file.
%%
%% Imports a GPG secret key (ASCII-armored format) into the local
%% GPG keyring. This is typically used at container startup to
%% enable certificate auto-renewal.
%%
%% @param KeyFile Path to the ASCII-armored GPG secret key file
%% @returns `{ok, Fingerprint}' on success, `{error, Reason}' on failure
-spec import_secret_key(string() | binary()) -> 
    {ok, binary()} | {error, term()}.
import_secret_key(KeyFile) when is_binary(KeyFile) ->
    import_secret_key(binary_to_list(KeyFile));
import_secret_key(KeyFile) when is_list(KeyFile) ->
    case file:read_file(KeyFile) of
        {ok, KeyData} ->
            import_secret_key_data(KeyData);
        {error, Reason} ->
            ?error("Failed to read GPG secret key file ~s: ~p", [KeyFile, Reason]),
            {error, {read_failed, Reason}}
    end.

%% @doc Import GPG secret key using cryptic directory structure.
%%
%% Constructs the path to the GPG secret key file based on the
%% standard cryptic directory layout and imports it.
%%
%% @param Username The user's username
%% @param ServerHost The server hostname
%% @param ServerPort The server port
%% @returns `{ok, Fingerprint}' on success, `{error, Reason}' on failure
-spec import_secret_key(binary(), binary(), integer()) ->
    {ok, binary()} | {error, term()}.
import_secret_key(Username, ServerHost, ServerPort) ->
    KeyFile = get_secret_key_path(Username, ServerHost, ServerPort),
    case filelib:is_file(KeyFile) of
        true ->
            import_secret_key(KeyFile);
        false ->
            ?warning("GPG secret key file not found: ~s", [KeyFile]),
            {error, key_file_not_found}
    end.

%% @doc Check if a secret key with the given fingerprint is available.
%%
%% Uses `erl_gpg_api:has_secret_key/1' to check the GPG keyring.
%%
%% @param Fingerprint The GPG key fingerprint to check
%% @returns `true' if the key is in the keyring, `false' otherwise
-spec check_secret_key_available(binary() | string()) -> boolean().
check_secret_key_available(Fingerprint) ->
    erl_gpg_api:has_secret_key(Fingerprint).

%% @doc Get the path to the GPG secret key file in cryptic data directory.
%%
%% @param Username The user's username
%% @param ServerHost The server hostname  
%% @param ServerPort The server port
%% @returns The full path to the GPG secret key file
-spec get_secret_key_path(binary(), binary(), integer()) -> string().
get_secret_key_path(Username, ServerHost, ServerPort) ->
    Home = os:getenv("HOME", "/home/cryptic"),
    filename:join([
        Home,
        ".cryptic",
        binary_to_list(Username),
        lists:flatten(io_lib:format("~s_~p", [binary_to_list(ServerHost), ServerPort])),
        "gpg_secret_key.asc"
    ]).

%% @doc List all secret keys in the local GPG keyring.
%%
%% Delegates to `erl_gpg_api:list_secret_keys/0'.
%%
%% @returns `{ok, Result}' where Result is the erl_gpg result map,
%%          or `{error, Reason}' on failure
-spec list_secret_keys() -> {ok, map()} | {error, term()}.
list_secret_keys() ->
    erl_gpg_api:list_secret_keys().

%%====================================================================
%% Internal Functions
%%====================================================================

%% @private
%% @doc Import GPG secret key data directly.
%%
%% Uses `erl_gpg_api:import_key/2' to import the key.
-spec import_secret_key_data(binary()) -> {ok, binary()} | {error, term()}.
import_secret_key_data(KeyData) ->
    try
        case erl_gpg_api:import_key(KeyData, "") of
            {ok, Result} ->
                %% Try to extract fingerprint from the colon data
                ColonData = maps:get(colon, Result, []),
                case extract_fingerprint_from_colon(ColonData) of
                    {ok, Fingerprint} ->
                        ?info("GPG secret key imported successfully: ~s", [Fingerprint]),
                        {ok, Fingerprint};
                    error ->
                        %% Try to get fingerprint from stdout
                        Stdout = maps:get(stdout, Result, <<>>),
                        case extract_fingerprint_from_stdout(Stdout) of
                            {ok, Fingerprint} ->
                                ?info("GPG secret key imported successfully: ~s", [Fingerprint]),
                                {ok, Fingerprint};
                            error ->
                                %% Import succeeded but couldn't parse fingerprint
                                ?info("GPG secret key imported (fingerprint unknown)", []),
                                {ok, <<"unknown">>}
                        end
                end;
            {error, Reason} ->
                ?error("Failed to import GPG secret key: ~p", [Reason]),
                {error, {import_failed, Reason}}
        end
    catch
        Class:Error:Stack ->
            ?error("Exception importing GPG secret key: ~p:~p~n~p", 
                   [Class, Error, Stack]),
            {error, {exception, Error}}
    end.

%% @private
%% @doc Extract fingerprint from GPG colon-separated output.
-spec extract_fingerprint_from_colon(list()) -> {ok, binary()} | error.
extract_fingerprint_from_colon([]) ->
    error;
extract_fingerprint_from_colon([#{type := <<"fpr">>, fields := Fields} | _]) ->
    %% Fingerprint is typically in field 10
    case lists:nth(10, Fields) of
        Fp when is_binary(Fp), byte_size(Fp) > 0 ->
            {ok, Fp};
        _ ->
            error
    end;
extract_fingerprint_from_colon([_ | Rest]) ->
    extract_fingerprint_from_colon(Rest).

%% @private
%% @doc Extract fingerprint from GPG stdout output.
-spec extract_fingerprint_from_stdout(binary()) -> {ok, binary()} | error.
extract_fingerprint_from_stdout(Output) ->
    %% GPG import output typically contains lines like:
    %% gpg: key ABCD1234: secret key imported
    %% Try to extract the key ID
    case re:run(Output, "key ([A-Fa-f0-9]+):", [{capture, [1], binary}]) of
        {match, [KeyId]} ->
            {ok, KeyId};
        nomatch ->
            error
    end.
