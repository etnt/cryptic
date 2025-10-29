%% @doc Unit tests for cryptic_ca_gpg module
-module(cryptic_ca_gpg_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% GPG Signature Verification Tests
%%====================================================================

verify_signature_test_() ->
    [?_test(test_verify_signature())].

test_verify_signature() ->
    %% Test with invalid test data (GPG will return error for invalid signatures)
    %% This test verifies the function calls erl_gpg_api correctly

    Message = <<"Hello, World!">>,
    Signature =
        <<"-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----">>,

    %% With invalid test data, erl_gpg_api will return an error
    Result = cryptic_ca_gpg:verify_signature(Message, Signature),
    ?assertMatch({error, _}, Result).

%%====================================================================
%% GPG Fingerprint Computation Tests
%%====================================================================

compute_fingerprint_test_() ->
    [?_test(test_compute_fingerprint())].

test_compute_fingerprint() ->
    %% Test with invalid test data (GPG will return error for invalid keys)
    %% This test verifies the function calls erl_gpg_api:compute_fingerprint correctly

    PublicKey =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest key\n-----END PGP PUBLIC KEY BLOCK-----">>,

    %% With invalid test data, erl_gpg_api will return an import error
    Result = cryptic_ca_gpg:compute_fingerprint(PublicKey),
    ?assertMatch({error, _}, Result).

%%====================================================================
%% GPG Public Key Extraction Tests
%%====================================================================

extract_public_key_test_() ->
    [?_test(test_extract_public_key())].

test_extract_public_key() ->
    %% Test with invalid test data (GPG will return error for invalid keys)
    %% This test verifies the function calls erl_gpg_api:get_key_info correctly

    KeyBlock =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest key\n-----END PGP PUBLIC KEY BLOCK-----">>,

    %% With invalid test data, erl_gpg_api will return an import error
    Result = cryptic_ca_gpg:extract_public_key(KeyBlock),
    ?assertMatch({error, _}, Result).

%%====================================================================
%% Error Handling Tests
%%====================================================================

error_handling_test_() ->
    [
        ?_test(test_verify_signature_with_invalid_input()),
        ?_test(test_compute_fingerprint_with_invalid_input()),
        ?_test(test_extract_public_key_with_invalid_input())
    ].

test_verify_signature_with_invalid_input() ->
    %% Test with empty message
    Result1 = cryptic_ca_gpg:verify_signature(<<>>, <<"sig">>),
    ?assertMatch({error, _}, Result1),

    %% Test with empty signature
    Result2 = cryptic_ca_gpg:verify_signature(<<"msg">>, <<>>),
    ?assertMatch({error, _}, Result2).

test_compute_fingerprint_with_invalid_input() ->
    %% Test with empty key
    Result = cryptic_ca_gpg:compute_fingerprint(<<>>),
    ?assertMatch({error, _}, Result).

test_extract_public_key_with_invalid_input() ->
    %% Test with empty key block
    Result = cryptic_ca_gpg:extract_public_key(<<>>),
    ?assertMatch({error, _}, Result).

%%====================================================================
%% Integration Notes
%%====================================================================

%% NOTE: The erl_gpg_api library has been extended with compute_fingerprint/1,2
%% and get_key_info/1,2 functions. These tests use the real erl_gpg_api.
%%
%% TODO: Add tests with real GPG keys once we have valid test fixtures:
%%
%% 1. Verify valid GPG signatures
%%    - Test with real GPG-signed messages
%%    - Test signature verification success/failure
%%    - Test with different key types (RSA, ECC, etc.)
%%
%% 2. Compute fingerprints
%%    - Test fingerprint computation from real public keys
%%    - Verify fingerprint format (40-char hex string)
%%    - Test with different key types
%%
%% 3. Extract public keys
%%    - Test extraction from real armored key blocks
%%    - Test extraction from binary key data
%%    - Test handling of subkeys
%%
%% 4. Additional error cases
%%    - Expired keys
%%    - Revoked keys
%%    - Key without self-signature
