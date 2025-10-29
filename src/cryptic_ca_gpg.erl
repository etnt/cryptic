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
    compute_fingerprint/1,
    extract_public_key/1
]).

-include_lib("kernel/include/logger.hrl").

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
%%         ?LOG_ERROR("Signature verification failed: ~p", [Reason]),
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
                ?LOG_DEBUG("GPG signature verified successfully"),
                {ok, Plaintext};
            {error, Reason} = Error ->
                ?LOG_WARNING("GPG signature verification failed: ~p", [Reason]),
                Error
        end
    catch
        ErrorType:ErrorReason:Stack ->
            ?LOG_ERROR(
                "Exception during GPG verification: ~p:~p~nStack: ~p",
                [ErrorType, ErrorReason, Stack]
            ),
            {error, {gpg_verification_exception, ErrorReason}}
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
%%         ?LOG_ERROR("Fingerprint computation failed: ~p", [Reason]),
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
%%         ?LOG_ERROR("Key validation failed: ~p", [Reason]),
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
                ?LOG_DEBUG("Validated and extracted primary public key"),
                %% Return the original key block
                {ok, KeyBlock};
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

%%====================================================================
%% Internal functions
%%====================================================================
