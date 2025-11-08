# Proposed erl_gpg_api Additions

## Functions to Add to erl_gpg_api.erl

### 1. compute_fingerprint/1,2

```erlang
%%% @doc Compute fingerprint from a public key.
%%%
%%% Imports the key temporarily (or checks if already imported) and
%%% extracts its fingerprint. This is useful for verifying key identity
%%% without needing to parse the key format manually.
%%%
%%% == Example ==
%%%
%%% ```
%%% PublicKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%% {ok, Fingerprint} = erl_gpg_api:compute_fingerprint(PublicKey),
%%% %% Fingerprint is a binary like <<"1234567890ABCDEF1234567890ABCDEF12345678">>
%%% '''
%%%
%%% @param KeyData The PGP public key (binary, ASCII-armored format)
%%% @returns `{ok, Fingerprint}' where Fingerprint is a 40-character hex binary,
%%%          or `{error, Reason}' on failure
%%% @end
-spec compute_fingerprint(binary()) -> {ok, binary()} | {error, term()}.
compute_fingerprint(KeyData) ->
    compute_fingerprint(KeyData, "").

%%% @doc Compute fingerprint from a public key with GPG home directory.
%%%
%%% @param KeyData The PGP public key (binary, ASCII-armored format)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @returns `{ok, Fingerprint}' where Fingerprint is a 40-character hex binary
%%% @see compute_fingerprint/1
%%% @end
-spec compute_fingerprint(binary(), string()) -> {ok, binary()} | {error, term()}.
compute_fingerprint(KeyData, GnupgDir) when is_binary(KeyData) ->
    %% Implementation approach:
    %% 1. Import the key temporarily (or check if exists)
    %% 2. List keys to get fingerprint
    %% 3. Extract fingerprint from the colon-formatted output
    %% 4. Return as binary
    case import_key(KeyData, GnupgDir) of
        {ok, _ImportResult} ->
            case list_keys(GnupgDir, [{key_type, public}]) of
                {ok, Result} ->
                    %% Parse colon data to extract fingerprint
                    ColonData = maps:get(colon, Result, []),
                    case extract_fingerprint_from_colon(ColonData) of
                        {ok, FP} -> {ok, FP};
                        error -> {error, fingerprint_not_found}
                    end;
                {error, E} -> {error, E}
            end;
        {error, E} -> {error, {import_failed, E}}
    end.

%% Helper to extract fingerprint from colon-formatted GPG output
extract_fingerprint_from_colon([]) ->
    error;
extract_fingerprint_from_colon([#{type := <<"fpr">>, fields := Fields} | _]) ->
    %% Fingerprint is in field 10 (index 9, 0-based)
    case lists:nth(10, Fields) of
        <<>> -> error;
        FP -> {ok, FP}
    end;
extract_fingerprint_from_colon([_ | Rest]) ->
    extract_fingerprint_from_colon(Rest).
```

### 2. get_key_info/1,2

An alternative/complementary function that returns both the fingerprint and other key metadata:

```erlang
%%% @doc Get key information from a public key block.
%%%
%%% Imports the key and extracts useful metadata including fingerprint,
%%% key ID, creation date, and user IDs.
%%%
%%% == Example ==
%%%
%%% ```
%%% PublicKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%% {ok, KeyInfo} = erl_gpg_api:get_key_info(PublicKey),
%%% Fingerprint = maps:get(fingerprint, KeyInfo),
%%% KeyID = maps:get(key_id, KeyInfo),
%%% UserIDs = maps:get(user_ids, KeyInfo).
%%% '''
%%%
%%% @param KeyData The PGP public key (binary, ASCII-armored format)
%%% @returns `{ok, KeyInfo}' where KeyInfo is a map with keys:
%%%          - `fingerprint' - 40-char hex binary
%%%          - `key_id' - Short key ID
%%%          - `algorithm' - Key algorithm (rsa, dsa, etc.)
%%%          - `key_length' - Key length in bits
%%%          - `creation_date' - Unix timestamp
%%%          - `user_ids' - List of user ID binaries
%%%          or `{error, Reason}' on failure
%%% @end
-spec get_key_info(binary()) -> {ok, map()} | {error, term()}.
get_key_info(KeyData) ->
    get_key_info(KeyData, "").

-spec get_key_info(binary(), string()) -> {ok, map()} | {error, term()}.
get_key_info(KeyData, GnupgDir) when is_binary(KeyData) ->
    %% Implementation: Import key, list keys, parse colon output
    %% to extract all relevant fields into a map
    ...
```

## Integration with cryptic_ca_gpg

Once these are added to erl_gpg_api, update cryptic_ca_gpg.erl:

```erlang
compute_fingerprint(PublicKey) ->
    try
        case erl_gpg_api:compute_fingerprint(PublicKey, "") of
            {ok, Fingerprint} ->
                ?LOG_DEBUG("Computed GPG fingerprint: ~s", [Fingerprint]),
                {ok, Fingerprint};
            {error, Reason} = Error ->
                ?LOG_ERROR("Failed to compute GPG fingerprint: ~p", [Reason]),
                Error
        end
    catch
        ErrorType:ErrorReason:Stack ->
            ?LOG_ERROR(
                "Exception during fingerprint computation: ~p:~p~nStack: ~p",
                [ErrorType, ErrorReason, Stack]
            ),
            {error, {fingerprint_computation_exception, ErrorReason}}
    end.

extract_public_key(KeyBlock) ->
    %% For now, this might just validate and return the key as-is
    %% Or use get_key_info to validate it's a valid key
    try
        case erl_gpg_api:get_key_info(KeyBlock, "") of
            {ok, _KeyInfo} ->
                ?LOG_DEBUG("Validated and extracted primary public key"),
                {ok, KeyBlock};  % Return the original key block
            {error, Reason} = Error ->
                ?LOG_ERROR("Failed to extract public key: ~p", [Reason]),
                Error
        end
    catch
        ErrorType:ErrorReason:Stack ->
            ?LOG_ERROR(
                "Exception during key extraction: ~p:~p~nStack: ~p",
                [ErrorType, ErrorReason, Stack]
            ),
            {error, {key_extraction_exception, ErrorReason}}
    end.
```

## Next Steps

1. Add `compute_fingerprint/1,2` to erl_gpg_api.erl
2. Add `get_key_info/1,2` (optional but useful)
3. Update erl_gpg tests
4. Push changes to erl_gpg repo
5. Update cryptic's rebar.lock to pull latest erl_gpg
6. Update cryptic_ca_gpg.erl to use the new functions
7. Update cryptic_ca_gpg tests with real test cases
