%%%-------------------------------------------------------------------
%%% @doc Certificate issuance integration tests
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_ca_cert_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%%%===================================================================
%%% Test Setup
%%%===================================================================

setup() ->
    %% Start event manager (required by logging macros)
    gen_event:start_link({local, cryptic_event_manager}),

    %% Start required applications
    application:ensure_all_started(asn1),
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),

    %% Set up test configuration
    application:set_env(cryptic_ca, ca_cert_file, "CA/certs/ca.crt"),
    application:set_env(cryptic_ca, ca_key_file, "CA/private/ca.key"),
    application:set_env(cryptic_ca, cert_default_lifetime_days, 7),

    %% Initialize CA environment
    ok = cryptic_ca_store:init_ca_environment(),

    %% Initialize serial number table (might already be running from previous test)
    case cryptic_ca_serial:start_link() of
        {ok, _Pid} -> ok;
        {error, {already_started, _Pid}} -> ok
    end,

    ok.

cleanup(_) ->
    application:stop(public_key),
    application:stop(crypto),
    application:stop(asn1),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

ca_cert_loading_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      ?_test(test_ca_cert_loading())
     ]}.

test_ca_cert_loading() ->
    %% Verify CA cert is loaded
    {ok, CACert} = application:get_env(cryptic_ca, ca_cert),
    ?assertMatch(#'OTPCertificate'{}, CACert),

    %% Verify CA key is loaded
    {ok, CAKey} = application:get_env(cryptic_ca, ca_key),
    ?assert(is_tuple(CAKey)),

    ok.

csr_parsing_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      ?_test(test_csr_parsing())
     ]}.

test_csr_parsing() ->
    %% Generate test CSR
    {ok, CsrPem} = generate_test_csr(),
    
    %% Test parsing
    {ok, CSR} = cryptic_ca_cert:parse_csr(CsrPem),
    ?assertMatch(#'CertificationRequest'{}, CSR),
    
    %% Test validation
    ?assertEqual(ok, cryptic_ca_cert:validate_csr(CSR)),
    
    ok.

certificate_issuance_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      ?_test(test_certificate_issuance())
     ]}.

test_certificate_issuance() ->
    %% Generate test CSR
    {ok, CsrPem} = generate_test_csr(),
    
    %% Issue certificate
    GpgFp = <<"ABCD1234567890ABCD1234567890ABCD12345678">>,
    {ok, CertPem} = cryptic_ca_cert:issue_from_csr(CsrPem, GpgFp),
    
    %% Verify certificate is PEM-encoded
    ?assert(is_binary(CertPem)),
    ?assert(byte_size(CertPem) > 0),
    ?assert(binary:match(CertPem, <<"-----BEGIN CERTIFICATE-----">>) /= nomatch),
    
    ok.

openssl_verification_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      ?_test(test_openssl_verification())
     ]}.

test_openssl_verification() ->
    %% Generate test CSR
    {ok, CsrPem} = generate_test_csr(),
    
    %% Issue certificate
    GpgFp = <<"TEST1234567890ABCD1234567890ABCD12345678">>,
    {ok, CertPem} = cryptic_ca_cert:issue_from_csr(CsrPem, GpgFp),
    
    %% Write to file
    TestCertFile = "/tmp/test_cert_" ++ integer_to_list(erlang:unique_integer([positive])) ++ ".pem",
    ok = file:write_file(TestCertFile, CertPem),
    
    %% Verify with OpenSSL
    Cmd = "openssl verify -CAfile CA/certs/ca.crt " ++ TestCertFile ++ " 2>&1",
    Output = os:cmd(Cmd),
    
    %% Clean up
    file:delete(TestCertFile),
    
    %% Check result
    ?assert(string:str(Output, ": OK") > 0),
    
    ok.

csr_signature_validation_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"Valid CSR signature", ?_test(test_valid_csr_signature())},
      {"Tampered signature rejected", ?_test(test_tampered_signature())},
      {"Tampered subject rejected", ?_test(test_tampered_subject())}
     ]}.

test_valid_csr_signature() ->
    %% Generate valid CSR
    {ok, CsrPem} = generate_test_csr(),
    {ok, CSR} = cryptic_ca_cert:parse_csr(CsrPem),
    
    %% Should validate successfully
    ?assertEqual(ok, cryptic_ca_cert:validate_csr(CSR)),
    
    ok.

test_tampered_signature() ->
    %% Generate valid CSR
    {ok, CsrPem} = generate_test_csr(),
    {ok, CSR} = cryptic_ca_cert:parse_csr(CsrPem),
    
    %% Tamper with signature (flip some bits)
    #'CertificationRequest'{signature = OrigSig} = CSR,
    <<First:8, Rest/binary>> = OrigSig,
    TamperedSig = <<(First bxor 255):8, Rest/binary>>,
    TamperedCSR = CSR#'CertificationRequest'{signature = TamperedSig},
    
    %% Should fail validation
    Result = cryptic_ca_cert:validate_csr(TamperedCSR),
    ?assertMatch({error, invalid_csr_signature}, Result),
    
    ok.

test_tampered_subject() ->
    %% Generate valid CSR
    {ok, CsrPem} = generate_test_csr(),
    {ok, CSR} = cryptic_ca_cert:parse_csr(CsrPem),
    
    %% Tamper with subject in certificationRequestInfo
    #'CertificationRequest'{certificationRequestInfo = Info} = CSR,
    
    %% Create new subject
    NewSubject = {rdnSequence, [[#'AttributeTypeAndValue'{
        type = {2,5,4,3},  % CN
        value = {utf8String, <<"tampered.example.com">>}
    }]]},
    
    TamperedInfo = Info#'CertificationRequestInfo'{subject = NewSubject},
    TamperedCSR = CSR#'CertificationRequest'{certificationRequestInfo = TamperedInfo},
    
    %% Should fail validation (signature won't match modified info)
    Result = cryptic_ca_cert:validate_csr(TamperedCSR),
    ?assertMatch({error, invalid_csr_signature}, Result),
    
    ok.

%%%===================================================================
%%% Helper Functions
%%%===================================================================

generate_test_csr() ->
    UniqueId = integer_to_list(erlang:unique_integer([positive])),
    KeyFile = "/tmp/test_key_" ++ UniqueId ++ ".pem",
    CsrFile = "/tmp/test_csr_" ++ UniqueId ++ ".pem",
    
    %% Generate key
    KeyCmd = "openssl ecparam -genkey -name secp384r1 -out " ++ KeyFile ++ " 2>&1",
    "" = os:cmd(KeyCmd),
    
    %% Generate CSR
    CsrCmd = "openssl req -new -key " ++ KeyFile ++ 
             " -subj '/CN=test-client-" ++ UniqueId ++ "' -out " ++ CsrFile ++ " 2>&1",
    "" = os:cmd(CsrCmd),
    
    %% Read CSR
    {ok, CsrPem} = file:read_file(CsrFile),
    
    %% Clean up
    file:delete(KeyFile),
    file:delete(CsrFile),
    
    {ok, CsrPem}.
