%% @doc Cryptic CA GPG Module - Wrapper around erl_gpg library
%%
%% This module provides GPG operations for the Certificate Authority,
%% including signature verification and fingerprint computation using
%% the erl_gpg library.
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since October 2025
-module(cryptic_ca_gpg).

-export([
    verify_signature/2,
    verify_detached_signature/3,
    compute_fingerprint/1,
    extract_public_key/1,
    extract_email_from_key/1
]).

-include("cryptic_server.hrl").

-type gpg_fingerprint() :: binary().
-type gpg_public_key() :: binary().
-type signed_data() :: binary().

%%====================================================================
%% API
%%====================================================================

%% @doc Verify a GPG signature and extract the plaintext data.
%%
%% This function verifies that the signed data was indeed signed by the
%% holder of the private key corresponding to the provided public key.
%% On successful verification, it returns the decrypted plaintext content.
%%
%% == Use Cases ==
%% <ul>
%%   <li>Verify invite tokens signed by the inviter</li>
%%   <li>Authenticate user registration requests</li>
%%   <li>Validate signed messages during onboarding</li>
%%   <li>Ensure data integrity and authenticity</li>
%% </ul>
%%
%% == Security Notes ==
%% <ul>
%%   <li>Both inputs must be ASCII-armored GPG format</li>
%%   <li>The function validates cryptographic signatures using erl_gpg</li>
%%   <li>Verification failure indicates tampering or wrong key</li>
%%   <li>All exceptions are caught and logged for security auditing</li>
%% </ul>
%%
%% == Example ==
%% ```
%% %% Verify an invite token signed by the inviter
%% SignedInvite = <<"-----BEGIN PGP SIGNED MESSAGE-----\n...">>,
%% InviterPubKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%
%% case cryptic_ca_gpg:verify_signature(SignedInvite, InviterPubKey) of
%%     {ok, PlaintextToken} ->
%%         %% Signature valid, use the plaintext token
%%         process_invite_token(PlaintextToken);
%%     {error, invalid_signature} ->
%%         {error, tampered_invite};
%%     {error, Reason} ->
%%         ?error("Signature verification failed: ~p", [Reason]),
%%         {error, verification_failed}
%% end.
%% '''
%%
%% @param SignedData The GPG-signed message (ASCII-armored format)
%% @param PublicKey The GPG public key to verify against (ASCII-armored format)
%% @returns `{ok, PlaintextData}' on successful verification with decrypted content,
%%          or `{error, Reason}' where Reason can be `invalid_signature', `malformed_data',
%%          `{gpg_verification_exception, Details}', etc.
-spec verify_signature(signed_data(), gpg_public_key()) ->
    {ok, binary()} | {error, term()}.
verify_signature(SignedData, PublicKey) ->
    try
        %% Use erl_gpg_api to verify the signature
        case erl_gpg_api:verify(SignedData, PublicKey) of
            {ok, Plaintext} ->
                ?debug("GPG signature verified successfully", []),
                {ok, Plaintext};
            {error, Reason} = Error ->
                ?warning("GPG signature verification failed: ~p", [Reason]),
                Error
        end
    catch
        ErrorType:ErrorReason:Stack ->
            ?error(
                "Exception during GPG verification: ~p:~p~nStack: ~p",
                [ErrorType, ErrorReason, Stack]
            ),
            {error, {gpg_verification_exception, ErrorReason}}
    end.

%% @doc Verify a detached GPG signature over data.
%%
%% This function verifies a detached signature (separate from the data)
%% using a provided GPG public key. This is commonly used for CSR signing
%% where the signature is sent separately from the CSR data.
%%
%% == Use Cases ==
%% <ul>
%%   <li>Verify CSR signed by user's GPG private key</li>
%%   <li>Authenticate certificate requests</li>
%%   <li>Validate proof-of-possession of GPG private key</li>
%% </ul>
%%
%% == Example ==
%% ```
%% %% Verify CSR signature during certificate issuance
%% CSR_PEM = <<"-----BEGIN CERTIFICATE REQUEST-----\n...">>,
%% GpgSignature = <<"-----BEGIN PGP SIGNATURE-----\n...">>,
%% GpgPubKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%
%% case cryptic_ca_gpg:verify_detached_signature(CSR_PEM, GpgSignature, GpgPubKey) of
%%     ok ->
%%         %% Signature valid, proceed with certificate issuance
%%         issue_certificate(CSR_PEM);
%%     {error, invalid_signature} ->
%%         {error, unauthorized_csr_request};
%%     {error, Reason} ->
%%         ?error("CSR signature verification failed: ~p", [Reason]),
%%         {error, verification_failed}
%% end.
%% '''
%%
%% @param Data The data that was signed (e.g., CSR in PEM format)
%% @param DetachedSignature The GPG signature (ASCII-armored format)
%% @param PublicKey The GPG public key to verify against (ASCII-armored format)
%% @returns `ok' on successful verification, or `{error, Reason}'
-spec verify_detached_signature(binary(), binary(), gpg_public_key()) ->
    ok | {error, term()}.
verify_detached_signature(Data, DetachedSignature, PublicKey) ->
    try
        %% First import the public key temporarily
        case erl_gpg_api:import_key(PublicKey, "") of
            {ok, _ImportResult} ->
                %% Now verify the detached signature
                case erl_gpg_api:verify_detached(Data, DetachedSignature, "") of
                    {ok, _VerifyResult} ->
                        ?debug("GPG detached signature verified successfully", []),
                        ok;
                    {error, Reason} = Error ->
                        ?warning("GPG detached signature verification failed: ~p", [Reason]),
                        Error
                end;
            {error, Reason} = Error ->
                ?error("Failed to import public key for verification: ~p", [Reason]),
                Error
        end
    catch
        ErrorType:ErrorReason:Stack ->
            ?error(
                "Exception during GPG detached signature verification: ~p:~p~nStack: ~p",
                [ErrorType, ErrorReason, Stack]
            ),
            {error, {gpg_detached_verification_exception, ErrorReason}}
    end.

%% @doc Compute the GPG fingerprint from a public key.
%%
%% Extracts the unique cryptographic fingerprint (hash) of a GPG public key.
%% The fingerprint serves as a compact identifier for the key and is used
%% throughout the system as the primary key for identity lookups.
%%
%% == Fingerprint Format ==
%% Returns a 40-character hexadecimal string (for GPG v4 keys) representing
%% the SHA-1 hash of the key material. This is the standard GPG fingerprint
%% format used by tools like `gpg --fingerprint`.
%%
%% == Use Cases ==
%% <ul>
%%   <li>Generate identity identifiers during onboarding</li>
%%   <li>Validate key fingerprints match expected values</li>
%%   <li>Create database lookup keys for GPG identities</li>
%%   <li>Display human-readable key identifiers in UI</li>
%% </ul>
%%
%% == Integration with erl_gpg ==
%% This function wraps `erl_gpg_api:compute_fingerprint/2', which uses
%% GPG's native fingerprint computation. The empty string parameter is
%% the passphrase (not needed for public keys).
%%
%% == Example ==
%% ```
%% %% Extract fingerprint during user registration
%% PublicKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%
%% case cryptic_ca_gpg:compute_fingerprint(PublicKey) of
%%     {ok, Fingerprint} ->
%%         %% Fingerprint: <<"ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234">>
%%         io:format("User fingerprint: ~s~n", [Fingerprint]),
%%         register_identity(Fingerprint, PublicKey);
%%     {error, invalid_key_format} ->
%%         {error, malformed_public_key};
%%     {error, Reason} ->
%%         ?error("Fingerprint computation failed: ~p", [Reason]),
%%         {error, cannot_compute_fingerprint}
%% end.
%% '''
%%
%% @param PublicKey The GPG public key in ASCII-armored format
%% @returns `{ok, Fingerprint}' where Fingerprint is a binary hex string,
%%          or `{error, Reason}' where Reason can be `invalid_key_format',
%%          `{fingerprint_computation_exception, Details}', etc.
-spec compute_fingerprint(gpg_public_key()) ->
    {ok, gpg_fingerprint()} | {error, term()}.
compute_fingerprint(PublicKey) ->
    try
        %% Use erl_gpg_api to compute fingerprint
        case erl_gpg_api:compute_fingerprint(PublicKey, "") of
            {ok, Fingerprint} ->
                ?debug("Computed GPG fingerprint: ~s", [Fingerprint]),
                {ok, Fingerprint};
            {error, Reason} = Error ->
                ?error("Failed to compute GPG fingerprint: ~p", [Reason]),
                Error
        end
    catch
        ErrorType:ErrorReason:Stack ->
            ?error(
                "Exception during fingerprint computation: ~p:~p~nStack: ~p",
                [ErrorType, ErrorReason, Stack]
            ),
            {error, {fingerprint_computation_exception, ErrorReason}}
    end.

%% @doc Extract and validate a public key from a GPG key block.
%%
%% Validates that the provided key block contains a valid GPG public key
%% by importing it and reading its metadata. If validation succeeds,
%% returns the original key block for storage or further processing.
%%
%% == Validation Process ==
%% <ol>
%%   <li>Import the key block into GPG's keyring (temporary)</li>
%%   <li>Read key metadata to confirm it's valid and accessible</li>
%%   <li>Return the original key block if validation succeeds</li>
%% </ol>
%%
%% == Why Validate? ==
%% Users may provide malformed or corrupted key blocks during onboarding.
%% This function catches such issues early, preventing invalid keys from
%% being stored in the database or used in cryptographic operations.
%%
%% == Use Cases ==
%% <ul>
%%   <li>Validate user-provided public keys during registration</li>
%%   <li>Ensure key blocks are well-formed before storage</li>
%%   <li>Detect corrupted keys from file uploads or paste operations</li>
%%   <li>Pre-flight check before attempting cryptographic operations</li>
%% </ul>
%%
%% == Integration with erl_gpg ==
%% Uses `erl_gpg_api:get_key_info/2' which imports the key and reads
%% its metadata. The empty string parameter is the passphrase (not
%% needed for public keys).
%%
%% == Example ==
%% ```
%% %% Validate a user-provided public key during onboarding
%% UserProvidedKey = get_key_from_form(),
%%
%% case cryptic_ca_gpg:extract_public_key(UserProvidedKey) of
%%     {ok, ValidatedKey} ->
%%         %% Key is valid, safe to store
%%         cryptic_ca_store:insert_gpg_identity(DbRef, #{
%%             gpg_fp => Fingerprint,
%%             public_key => ValidatedKey,
%%             status => <<"pending">>
%%         });
%%     {error, invalid_key_data} ->
%%         {error, <<"Please provide a valid GPG public key">>};
%%     {error, Reason} ->
%%         ?error("Key validation failed: ~p", [Reason]),
%%         {error, <<"Key validation failed">>}
%% end.
%% '''
%%
%% @param KeyBlock The GPG key block to validate (ASCII-armored format, may contain multiple keys)
%% @returns `{ok, PublicKey}' with the validated key block on success,
%%          or `{error, Reason}' where Reason can be `invalid_key_data',
%%          `malformed_armor', `{key_extraction_exception, Details}', etc.
-spec extract_public_key(binary()) ->
    {ok, gpg_public_key()} | {error, term()}.
extract_public_key(KeyBlock) ->
    try
        %% Use erl_gpg_api to validate the key and return it
        %% get_key_info validates the key by importing and reading it
        case erl_gpg_api:get_key_info(KeyBlock, "") of
            {ok, _KeyInfo} ->
                ?debug("Validated and extracted primary public key", []),
                %% Return the original key block
                {ok, KeyBlock};
            {error, Reason} = Error ->
                ?error("Failed to extract public key: ~p", [Reason]),
                Error
        end
    catch
        ErrorType:ErrorReason:Stack ->
            ?error(
                "Exception during key extraction: ~p:~p~nStack: ~p",
                [ErrorType, ErrorReason, Stack]
            ),
            {error, {key_extraction_exception, ErrorReason}}
    end.

%% @doc Extract email address from GPG public key user ID.
%%
%% Parses the GPG public key to extract the email address from the first
%% user ID. GPG user IDs typically follow the format "Name &lt;email@example.com>".
%%
%% == Use Cases ==
%% <ul>
%%   <li>Extract email for certificate SAN extension</li>
%%   <li>Map GPG fingerprints to human-readable usernames</li>
%%   <li>Enable messaging between users by name</li>
%% </ul>
%%
%% == Example ==
%% ```
%% %% Extract email during certificate issuance
%% case cryptic_ca_gpg:extract_email_from_key(GpgPubKey) of
%%     {ok, Email} ->
%%         %% Use email in certificate SAN
%%         build_client_cert(Subject, PubKey, GpgFp, Email, ValidityDays);
%%     {error, no_email_found} ->
%%         %% Fall back to GPG fingerprint only
%%         build_client_cert(Subject, PubKey, GpgFp, undefined, ValidityDays)
%% end.
%% '''
%%
%% @param KeyBlock The GPG public key in ASCII-armored format
%% @returns `{ok, Email}' where Email is a binary like &lt;&lt;"bob@smith.org">>,
%%          or `{error, no_email_found}' if no valid email in user IDs
-spec extract_email_from_key(binary()) -> {ok, binary()} | {error, term()}.
extract_email_from_key(KeyBlock) ->
    try
        case erl_gpg_api:get_key_info(KeyBlock, "") of
            {ok, KeyInfo} ->
                ?debug("GPG key info: ~p", [KeyInfo]),
                %% Extract user_ids from key info
                UserIDs = maps:get(user_ids, KeyInfo, []),
                ?debug("GPG user IDs: ~p", [UserIDs]),
                case extract_email_from_uids(UserIDs) of
                    {ok, Email} ->
                        ?debug("Extracted email from GPG key: ~s", [Email]),
                        {ok, Email};
                    {error, _} = Error ->
                        ?warning("No email found in GPG key user IDs: ~p", [UserIDs]),
                        Error
                end;
            {error, Reason} = Error ->
                ?error("Failed to get key info for email extraction: ~p", [Reason]),
                Error
        end
    catch
        ErrorType:ErrorReason:Stack ->
            ?error(
                "Exception during email extraction: ~p:~p~nStack: ~p",
                [ErrorType, ErrorReason, Stack]
            ),
            {error, {email_extraction_exception, ErrorReason}}
    end.

%%====================================================================
%% Internal functions
%%====================================================================

%% @private
%% @doc Extract email address from GPG user ID list.
%%
%% Parses user IDs in the format "Name &lt;email@example.com>" or "email@example.com"
%% and extracts the email address from the first user ID that contains one.
%%
%% @param UserIDs List of user ID binaries from GPG key
%% @returns `{ok, Email}' or `{error, no_email_found}'
-spec extract_email_from_uids([binary()]) -> {ok, binary()} | {error, no_email_found}.
extract_email_from_uids([]) ->
    {error, no_email_found};
extract_email_from_uids([UID | Rest]) ->
    case extract_email_from_uid(UID) of
        {ok, Email} -> {ok, Email};
        {error, _} -> extract_email_from_uids(Rest)
    end.

%% @private
%% @doc Extract email from a single user ID string.
%%
%% Handles formats:
%% - "Name &lt;email@example.com>" → "email@example.com"
%% - "email@example.com" → "email@example.com"
%% - "Name (comment) &lt;email@example.com>" → "email@example.com"
%%
%% @param UID User ID binary
%% @returns `{ok, Email}' or `{error, no_email_found}'
-spec extract_email_from_uid(binary()) -> {ok, binary()} | {error, no_email_found}.
extract_email_from_uid(UID) when is_binary(UID) ->
    %% Try to extract email from "<email>" format first
    case binary:split(UID, [<<"<">>, <<">">>], [global]) of
        [_, Email, _] ->
            %% Found email between < and >
            {ok, string:trim(Email)};
        _ ->
            %% No angle brackets, check if the whole UID is an email
            case is_email(UID) of
                true -> {ok, string:trim(UID)};
                false -> {error, no_email_found}
            end
    end.

%% @private
%% @doc Simple email validation - checks for @ sign.
%%
%% @param Binary Potential email address
%% @returns true if looks like an email, false otherwise
-spec is_email(binary()) -> boolean().
is_email(Binary) when is_binary(Binary) ->
    case binary:match(Binary, <<"@">>) of
        {_, _} -> true;
        nomatch -> false
    end.
