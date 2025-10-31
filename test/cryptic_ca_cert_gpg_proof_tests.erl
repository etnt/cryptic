%%%-------------------------------------------------------------------
%%% @doc Tests for GPG signature verification on CSR requests
%%%
%%% Tests the complete certificate issuance flow with GPG proof:
%%% 1. Bob signs CSR with his GPG private key
%%% 2. CA verifies signature using Bob's stored GPG public key
%%% 3. CA issues certificate only if signature is valid
%%%
%%% Uses meck to mock database and GPG operations for isolated unit testing.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_ca_cert_gpg_proof_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("../include/cryptic_ca.hrl").

%%%===================================================================
%%% Test Setup
%%%===================================================================

setup() ->
    %% Start event manager (required by logging macros)
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _Pid} -> ok;
        {error, {already_started, _Pid}} -> ok
    end,

    %% Start required applications
    application:ensure_all_started(asn1),
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),

    %% Set up CA configuration
    application:set_env(cryptic_ca, ca_cert_file, "CA/certs/ca.crt"),
    application:set_env(cryptic_ca, ca_key_file, "CA/private/ca.key"),
    application:set_env(cryptic_ca, cert_default_lifetime_days, 7),

    %% Initialize CA environment
    ok = cryptic_ca_store:init_ca_environment(),

    %% Initialize serial number manager
    case cryptic_ca_serial:start_link() of
        {ok, _Pid1} -> ok;
        {error, {already_started, _Pid2}} -> ok
    end,

    %% Mock database reference
    MockDbRef = make_ref(),
    application:set_env(cryptic, ca_db_ref, MockDbRef),

    %% Start meck mocking
    meck:new(cryptic_gpg_registry, [passthrough]),
    meck:new(cryptic_ca_gpg, [passthrough]),

    MockDbRef.

cleanup(_MockDbRef) ->
    %% Unload mocks
    meck:unload(cryptic_gpg_registry),
    meck:unload(cryptic_ca_gpg),
    
    application:unset_env(cryptic, ca_db_ref),
    application:stop(public_key),
    application:stop(crypto),
    application:stop(asn1),
    ok.

%%%===================================================================
%%% Helper Functions
%%%===================================================================

%% @doc Generate a test CSR using OpenSSL
generate_test_csr() ->
    %% Create temporary key file
    KeyFile = "/tmp/test_key_" ++ integer_to_list(erlang:system_time(millisecond)) ++ ".pem",
    CsrFile = "/tmp/test_csr_" ++ integer_to_list(erlang:system_time(millisecond)) ++ ".pem",
    
    %% Generate key
    Cmd1 = io_lib:format(
        "openssl ecparam -genkey -name secp384r1 -out ~s 2>/dev/null",
        [KeyFile]
    ),
    os:cmd(Cmd1),
    
    %% Generate CSR
    Cmd2 = io_lib:format(
        "openssl req -new -key ~s -out ~s "
        "-subj '/CN=test@cryptic.example.org' 2>/dev/null",
        [KeyFile, CsrFile]
    ),
    os:cmd(Cmd2),
    
    %% Read CSR
    {ok, CsrPem} = file:read_file(CsrFile),
    
    %% Cleanup
    file:delete(KeyFile),
    file:delete(CsrFile),
    
    {ok, CsrPem}.

%% @doc Mock a verified GPG identity
mock_verified_identity(DbRef, GpgFp, Status) ->
    GpgPubKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                  "mocked_public_key_data_for_testing\n"
                  "-----END PGP PUBLIC KEY BLOCK-----">>,
    
    %% Create identity as a map (like the real cryptic_gpg_registry:get_identity returns)
    Identity = #{
        gpg_fp => GpgFp,
        gpg_pub_armor => GpgPubKey,
        status => Status,
        inviter_fp => undefined,
        registered_at => erlang:system_time(second),
        last_seen => erlang:system_time(second),
        invite_id => undefined
    },
    
    %% Mock get_identity to return this identity
    meck:expect(cryptic_gpg_registry, get_identity,
                fun(MockDbRef, MockGpgFp) when MockDbRef =:= DbRef,
                                                MockGpgFp =:= GpgFp ->
                    {ok, Identity}
                end),
    
    GpgPubKey.

%% @doc Mock successful GPG signature verification
mock_gpg_verify_success() ->
    meck:expect(cryptic_ca_gpg, verify_detached_signature,
                fun(_Data, _Signature, _PubKey) -> ok end).

%% @doc Mock failed GPG signature verification
mock_gpg_verify_failure(Reason) ->
    meck:expect(cryptic_ca_gpg, verify_detached_signature,
                fun(_Data, _Signature, _PubKey) -> {error, Reason} end).

%% @doc Reset meck call history to avoid cross-test contamination
reset_meck_history() ->
    meck:reset(cryptic_gpg_registry),
    meck:reset(cryptic_ca_gpg).

%%%===================================================================
%%% Tests: GPG Identity Verification
%%%===================================================================

gpg_identity_verification_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(DbRef) ->
         [
          ?_test(test_verified_via_invite_identity(DbRef)),
          ?_test(test_verified_bootstrap_identity(DbRef)),
          ?_test(test_pending_identity_rejected(DbRef)),
          ?_test(test_revoked_identity_rejected(DbRef)),
          ?_test(test_unregistered_identity_rejected(DbRef))
         ]
     end}.

test_verified_via_invite_identity(DbRef) ->
    %% Mock verified identity
    GpgFp = <<"VERIFIED1234567890ABCD1234567890ABCD1234">>,
    _GpgPubKey = mock_verified_identity(DbRef, GpgFp, <<"verified_via_invite">>),
    
    %% Mock successful GPG signature verification
    mock_gpg_verify_success(),
    
    %% Should be able to issue certificate with this identity
    {ok, CsrPem} = generate_test_csr(),
    GpgSig = <<"-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----">>,
    
    %% Should succeed
    Result = cryptic_ca_cert:issue_from_csr_with_gpg_proof(CsrPem, GpgFp, GpgSig),
    ?assertMatch({ok, _CertPem}, Result),
    
    %% Verify meck was called correctly
    ?assert(meck:called(cryptic_gpg_registry, get_identity, [DbRef, GpgFp])),
    ?assert(meck:called(cryptic_ca_gpg, verify_detached_signature, '_')),
    ok.

test_verified_bootstrap_identity(DbRef) ->
    %% Mock bootstrap verified identity
    GpgFp = <<"BOOTSTRAP1234567890ABCD1234567890ABCD12">>,
    _GpgPubKey = mock_verified_identity(DbRef, GpgFp, <<"verified_bootstrap">>),
    
    %% Mock successful GPG signature verification
    mock_gpg_verify_success(),
    
    %% Should be able to issue certificate with this identity
    {ok, CsrPem} = generate_test_csr(),
    GpgSig = <<"-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----">>,
    
    %% Should succeed
    Result = cryptic_ca_cert:issue_from_csr_with_gpg_proof(CsrPem, GpgFp, GpgSig),
    ?assertMatch({ok, _CertPem}, Result),
    
    ?assert(meck:called(cryptic_gpg_registry, get_identity, [DbRef, GpgFp])),
    ok.

test_pending_identity_rejected(DbRef) ->
    %% Mock pending identity
    GpgFp = <<"PENDING1234567890ABCD1234567890ABCD123456">>,
    _GpgPubKey = mock_verified_identity(DbRef, GpgFp, <<"pending">>),
    
    %% Try to issue certificate
    {ok, CsrPem} = generate_test_csr(),
    GpgSig = <<"-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----">>,
    
    %% Should be rejected with pending verification error
    Result = cryptic_ca_cert:issue_from_csr_with_gpg_proof(CsrPem, GpgFp, GpgSig),
    ?assertMatch({error, gpg_identity_pending_verification}, Result),
    
    %% Should check identity but not proceed to signature verification
    ?assert(meck:called(cryptic_gpg_registry, get_identity, [DbRef, GpgFp])),
    ok.

test_revoked_identity_rejected(DbRef) ->
    %% Mock revoked identity
    GpgFp = <<"REVOKED1234567890ABCD1234567890ABCD123456">>,
    _GpgPubKey = mock_verified_identity(DbRef, GpgFp, <<"revoked">>),
    
    %% Try to issue certificate
    {ok, CsrPem} = generate_test_csr(),
    GpgSig = <<"-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----">>,
    
    %% Should be rejected with revoked error
    Result = cryptic_ca_cert:issue_from_csr_with_gpg_proof(CsrPem, GpgFp, GpgSig),
    ?assertMatch({error, gpg_identity_revoked}, Result),
    
    ?assert(meck:called(cryptic_gpg_registry, get_identity, [DbRef, GpgFp])),
    ok.

test_unregistered_identity_rejected(DbRef) ->
    %% Mock identity not found
    GpgFp = <<"NOTEXIST1234567890ABCD1234567890ABCD1234">>,
    
    meck:expect(cryptic_gpg_registry, get_identity,
                fun(MockDbRef, MockGpgFp) when MockDbRef =:= DbRef,
                                                MockGpgFp =:= GpgFp ->
                    {error, not_found}
                end),
    
    %% Try to issue certificate
    {ok, CsrPem} = generate_test_csr(),
    GpgSig = <<"-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----">>,
    
    %% Should be rejected with not registered error
    Result = cryptic_ca_cert:issue_from_csr_with_gpg_proof(CsrPem, GpgFp, GpgSig),
    ?assertMatch({error, gpg_fingerprint_not_registered}, Result),
    
    ?assert(meck:called(cryptic_gpg_registry, get_identity, [DbRef, GpgFp])),
    ok.

%%%===================================================================
%%% Tests: Complete Flow with Mocked GPG Operations
%%%===================================================================

complete_flow_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(DbRef) ->
         [
          ?_test(test_successful_certificate_issuance_with_valid_gpg_proof(DbRef)),
          ?_test(test_certificate_issuance_fails_with_invalid_gpg_signature(DbRef)),
          ?_test(test_certificate_issuance_requires_verified_identity(DbRef)),
          ?_test(test_certificate_issuance_checks_status(DbRef))
         ]
     end}.

test_successful_certificate_issuance_with_valid_gpg_proof(DbRef) ->
    %% Setup: Mock verified identity
    GpgFp = <<"VALIDUSER1234567890ABCD1234567890ABCD12">>,
    _GpgPubKey = mock_verified_identity(DbRef, GpgFp, <<"verified_via_invite">>),
    
    %% Mock successful GPG signature verification
    mock_gpg_verify_success(),
    
    %% Generate CSR and fake signature
    {ok, CsrPem} = generate_test_csr(),
    GpgSig = <<"-----BEGIN PGP SIGNATURE-----\nvalid_signature\n-----END PGP SIGNATURE-----">>,
    
    %% Should successfully issue certificate
    Result = cryptic_ca_cert:issue_from_csr_with_gpg_proof(CsrPem, GpgFp, GpgSig),
    ?assertMatch({ok, _CertPem}, Result),
    
    %% Verify the complete flow was executed
    ?assert(meck:called(cryptic_gpg_registry, get_identity, [DbRef, GpgFp])),
    ?assert(meck:called(cryptic_ca_gpg, verify_detached_signature, [CsrPem, GpgSig, '_'])),
    ok.

test_certificate_issuance_fails_with_invalid_gpg_signature(DbRef) ->
    %% Setup: Mock verified identity
    GpgFp = <<"BADSIG1234567890ABCD1234567890ABCD123456">>,
    _GpgPubKey = mock_verified_identity(DbRef, GpgFp, <<"verified_via_invite">>),
    
    %% Mock failed GPG signature verification
    mock_gpg_verify_failure(invalid_signature),
    
    %% Generate CSR and fake signature
    {ok, CsrPem} = generate_test_csr(),
    GpgSig = <<"-----BEGIN PGP SIGNATURE-----\ninvalid_signature\n-----END PGP SIGNATURE-----">>,
    
    %% Should fail with invalid GPG signature
    Result = cryptic_ca_cert:issue_from_csr_with_gpg_proof(CsrPem, GpgFp, GpgSig),
    ?assertMatch({error, {invalid_gpg_signature, invalid_signature}}, Result),
    
    %% Verify it tried to verify signature
    ?assert(meck:called(cryptic_ca_gpg, verify_detached_signature, [CsrPem, GpgSig, '_'])),
    ok.

test_certificate_issuance_requires_verified_identity(DbRef) ->
    %% Reset meck call history from previous tests
    reset_meck_history(),
    
    %% Setup: Mock identity not found
    GpgFp = <<"UNREGISTERED1234567890ABCD1234567890ABCD">>,
    
    meck:expect(cryptic_gpg_registry, get_identity,
                fun(MockDbRef, MockGpgFp) when MockDbRef =:= DbRef,
                                                MockGpgFp =:= GpgFp ->
                    {error, not_found}
                end),
    
    %% Try to issue certificate without registering GPG identity
    {ok, CsrPem} = generate_test_csr(),
    GpgSig = <<"-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----">>,
    
    %% Should fail because identity is not registered
    Result = cryptic_ca_cert:issue_from_csr_with_gpg_proof(CsrPem, GpgFp, GpgSig),
    ?assertMatch({error, gpg_fingerprint_not_registered}, Result),
    
    %% Should have checked the registry
    ?assert(meck:called(cryptic_gpg_registry, get_identity, [DbRef, GpgFp])),
    
    %% Should NOT have tried to verify signature (identity check fails first)
    ?assertNot(meck:called(cryptic_ca_gpg, verify_detached_signature, '_')),
    ok.

test_certificate_issuance_checks_status(DbRef) ->
    %% Reset meck call history from previous tests
    reset_meck_history(),
    
    %% Setup: Mock pending identity
    GpgFp = <<"PENDING9876543210ABCD1234567890ABCD123456">>,
    _GpgPubKey = mock_verified_identity(DbRef, GpgFp, <<"pending">>),
    
    %% Try to issue certificate
    {ok, CsrPem} = generate_test_csr(),
    GpgSig = <<"-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----">>,
    
    %% Should fail because identity is pending
    Result = cryptic_ca_cert:issue_from_csr_with_gpg_proof(CsrPem, GpgFp, GpgSig),
    ?assertMatch({error, gpg_identity_pending_verification}, Result),
    
    %% Should have checked the registry but not verified signature
    ?assert(meck:called(cryptic_gpg_registry, get_identity, [DbRef, GpgFp])),
    ?assertNot(meck:called(cryptic_ca_gpg, verify_detached_signature, '_')),
    ok.

%%%===================================================================
%%% Integration Notes
%%%===================================================================

%% TODO: Add full integration tests with real GPG operations
%%
%% To test the complete flow with real GPG signatures:
%%
%% 1. Generate a real GPG key pair:
%%    gpg --batch --gen-key <<EOF
%%    Key-Type: RSA
%%    Key-Length: 2048
%%    Name-Real: Test User
%%    Name-Email: test@cryptic.example.org
%%    Expire-Date: 0
%%    %no-protection
%%    EOF
%%
%% 2. Export the public key:
%%    gpg --armor --export test@cryptic.example.org > test_pubkey.asc
%%
%% 3. Compute fingerprint:
%%    gpg --fingerprint test@cryptic.example.org
%%
%% 4. Sign the CSR:
%%    gpg --detach-sign --armor -o csr.sig csr.pem
%%
%% 5. Register identity in database with real public key
%%
%% 6. Call issue_from_csr_with_gpg_proof with real signature
%%
%% 7. Verify certificate is issued successfully
%%
%% This would require either:
%% - A test fixture with pre-generated GPG keys
%% - Dynamic GPG key generation in test setup
%% - Integration with erl_gpg_api in test mode

