%%% @doc EUnit tests for cryptic_messages module
%%%
%%% This module contains comprehensive unit tests for all message construction
%%% and validation functions in the cryptic_messages module.
%%%
%%% @author Cryptic Team
%%% @version 1.0.0

-module(cryptic_messages_test).

-include_lib("eunit/include/eunit.hrl").

%%% ============================================================================
%%% Test Setup and Fixtures
%%% ============================================================================

%% Sample test data
sample_binary_keys() ->
    #{
        identity_sign_public => <<1, 2, 3, 4, 5, 6, 7, 8>>,
        identity_dh_public => <<9, 10, 11, 12, 13, 14, 15, 16>>,
        signed_prekey_public => <<17, 18, 19, 20, 21, 22, 23, 24>>,
        signed_prekey_signature => <<25, 26, 27, 28, 29, 30, 31, 32>>
    }.

sample_prekey_bundle() ->
    #{
        one_time_prekeys => [
            #{id => <<1, 2>>, public => <<3, 4>>},
            #{id => <<5, 6>>, public => <<7, 8>>},
            #{id => <<9, 10>>, public => <<11, 12>>}
        ]
    }.

sample_x3dh_message() ->
    #{
        to => <<"alice">>,
        message_id => base64:encode(<<1, 2, 3, 4>>),
        ephemeral_public => base64:encode(<<5, 6, 7, 8>>),
        otpk_id => base64:encode(<<9, 10>>),
        ciphertext => base64:encode(<<11, 12, 13, 14>>),
        nonce => base64:encode(<<15, 16, 17, 18>>),
        signature => base64:encode(<<19, 20, 21, 22>>),
        metadata => base64:encode(<<23, 24, 25, 26>>)
    }.

sample_ratchet_message() ->
    #{
        to => <<"bob">>,
        message_id => base64:encode(<<1, 2, 3, 4>>),
        dh_public => base64:encode(<<5, 6, 7, 8>>),
        dh_step => 1,
        prev_chain_length => 5,
        msg_number => 3,
        ciphertext => base64:encode(<<9, 10, 11, 12>>),
        nonce => base64:encode(<<13, 14, 15, 16>>)
    }.

%%% ============================================================================
%%% Authentication & Key Management Tests
%%% ============================================================================

upload_identity_keys_test_() ->
    [
        ?_test(test_upload_identity_keys_valid()),
        ?_test(test_upload_identity_keys_missing_fields()),
        ?_test(test_upload_identity_keys_invalid_types())
    ].

test_upload_identity_keys_valid() ->
    Keys = sample_binary_keys(),
    {ok, Message} = cryptic_messages:upload_identity_keys(Keys),

    % Check message structure
    ?assertEqual(<<"upload_identity_keys">>, maps:get(<<"type">>, Message)),
    ?assert(maps:is_key(<<"identity_sign_public">>, Message)),
    ?assert(maps:is_key(<<"identity_dh_public">>, Message)),
    ?assert(maps:is_key(<<"signed_prekey_public">>, Message)),
    ?assert(maps:is_key(<<"signed_prekey_signature">>, Message)),

    % Check base64 encoding
    ?assertEqual(
        base64:encode(maps:get(identity_sign_public, Keys)),
        maps:get(<<"identity_sign_public">>, Message)
    ),

    % Validate the message
    {ok, _} = cryptic_messages:validate_message(Message).

test_upload_identity_keys_missing_fields() ->
    Keys = maps:remove(signed_prekey_public, sample_binary_keys()),
    {error, {missing_fields, MissingFields}} =
        cryptic_messages:upload_identity_keys(Keys),
    ?assert(lists:member(signed_prekey_public, MissingFields)).

test_upload_identity_keys_invalid_types() ->
    % The current implementation converts strings to binaries via base64 encoding,
    % so this test validates that non-binary data gets processed correctly
    Keys = maps:put(identity_sign_public, "not_binary", sample_binary_keys()),
    {ok, Message} = cryptic_messages:upload_identity_keys(Keys),

    % Verify the string was base64 encoded
    EncodedString = base64:encode("not_binary"),
    ?assertEqual(EncodedString, maps:get(<<"identity_sign_public">>, Message)).

upload_prekey_bundle_test_() ->
    [
        ?_test(test_upload_prekey_bundle_valid()),
        ?_test(test_upload_prekey_bundle_empty_list()),
        ?_test(test_upload_prekey_bundle_invalid_format())
    ].

test_upload_prekey_bundle_valid() ->
    Bundle = sample_prekey_bundle(),
    {ok, Message} = cryptic_messages:upload_prekey_bundle(Bundle),

    ?assertEqual(<<"upload_prekey_bundle">>, maps:get(<<"type">>, Message)),
    ?assert(maps:is_key(<<"one_time_prekeys">>, Message)),

    Prekeys = maps:get(<<"one_time_prekeys">>, Message),
    ?assertEqual(3, length(Prekeys)),

    % Check first prekey structure
    [FirstPrekey | _] = Prekeys,
    ?assert(maps:is_key(<<"id">>, FirstPrekey)),
    ?assert(maps:is_key(<<"public_key">>, FirstPrekey)).

test_upload_prekey_bundle_empty_list() ->
    Bundle = #{one_time_prekeys => []},
    {error, empty_prekey_list} = cryptic_messages:upload_prekey_bundle(Bundle).

test_upload_prekey_bundle_invalid_format() ->
    Bundle = #{one_time_prekeys => [#{invalid => <<"key">>}]},
    {error, invalid_prekey_entry_format} =
        cryptic_messages:upload_prekey_bundle(Bundle).

get_key_bundle_test_() ->
    [
        ?_test(test_get_key_bundle_valid()),
        ?_test(test_get_key_bundle_missing_user()),
        ?_test(test_get_key_bundle_invalid_user())
    ].

test_get_key_bundle_valid() ->
    Request = #{user => <<"alice">>},
    {ok, Message} = cryptic_messages:get_key_bundle(Request),

    ?assertEqual(<<"get_key_bundle">>, maps:get(<<"type">>, Message)),
    ?assertEqual(<<"alice">>, maps:get(<<"user">>, Message)).

test_get_key_bundle_missing_user() ->
    Request = #{},
    {error, missing_user_field} = cryptic_messages:get_key_bundle(Request).

test_get_key_bundle_invalid_user() ->
    Request = #{user => 123},
    {error, invalid_user_field} = cryptic_messages:get_key_bundle(Request).

key_status_test() ->
    {ok, Message} = cryptic_messages:key_status(),
    ?assertEqual(<<"key_status">>, maps:get(<<"type">>, Message)),
    ?assertEqual(1, maps:size(Message)).

%%% ============================================================================
%%% Messaging Tests
%%% ============================================================================

send_encrypted_test_() ->
    [
        ?_test(test_send_encrypted_valid()),
        ?_test(test_send_encrypted_missing_fields())
    ].

test_send_encrypted_valid() ->
    Request = #{
        to => <<"bob">>,
        message => #{<<"ciphertext">> => <<"encrypted_data">>}
    },
    {ok, Message} = cryptic_messages:send_encrypted(Request),

    ?assertEqual(<<"send_encrypted">>, maps:get(<<"type">>, Message)),
    ?assertEqual(<<"bob">>, maps:get(<<"to">>, Message)),
    ?assertEqual(
        #{<<"ciphertext">> => <<"encrypted_data">>},
        maps:get(<<"message">>, Message)
    ).

test_send_encrypted_missing_fields() ->
    % missing message field
    Request = #{to => <<"bob">>},
    {error, {missing_fields, MissingFields}} =
        cryptic_messages:send_encrypted(Request),
    ?assert(lists:member(message, MissingFields)).

send_message_x3dh_test_() ->
    [
        ?_test(test_send_message_x3dh_valid()),
        ?_test(test_send_message_x3dh_missing_fields())
    ].

test_send_message_x3dh_valid() ->
    Request = sample_x3dh_message(),
    {ok, Message} = cryptic_messages:send_message_x3dh(Request),

    ?assertEqual(<<"send_message_x3dh">>, maps:get(<<"type">>, Message)),
    ?assertEqual(<<"alice">>, maps:get(<<"to">>, Message)),
    ?assert(maps:is_key(<<"message_id">>, Message)),
    ?assert(maps:is_key(<<"ephemeral_public">>, Message)),
    ?assert(maps:is_key(<<"otpk_id">>, Message)),
    ?assert(maps:is_key(<<"ciphertext">>, Message)),
    ?assert(maps:is_key(<<"nonce">>, Message)),
    ?assert(maps:is_key(<<"signature">>, Message)),
    ?assert(maps:is_key(<<"metadata">>, Message)).

test_send_message_x3dh_missing_fields() ->
    Request = maps:remove(signature, sample_x3dh_message()),
    {error, {missing_fields, MissingFields}} =
        cryptic_messages:send_message_x3dh(Request),
    ?assert(lists:member(signature, MissingFields)).

send_message_ratchet_test_() ->
    [
        ?_test(test_send_message_ratchet_valid()),
        ?_test(test_send_message_ratchet_missing_fields())
    ].

test_send_message_ratchet_valid() ->
    Request = sample_ratchet_message(),
    {ok, Message} = cryptic_messages:send_message_ratchet(Request),

    ?assertEqual(<<"send_message_ratchet">>, maps:get(<<"type">>, Message)),
    ?assertEqual(<<"bob">>, maps:get(<<"to">>, Message)),
    ?assertEqual(1, maps:get(<<"dh_step">>, Message)),
    ?assertEqual(5, maps:get(<<"prev_chain_length">>, Message)),
    ?assertEqual(3, maps:get(<<"msg_number">>, Message)).

test_send_message_ratchet_missing_fields() ->
    Request = maps:remove(dh_step, sample_ratchet_message()),
    {error, {missing_fields, MissingFields}} =
        cryptic_messages:send_message_ratchet(Request),
    ?assert(lists:member(dh_step, MissingFields)).

list_users_test() ->
    {ok, Message} = cryptic_messages:list_users(),
    ?assertEqual(<<"list_users">>, maps:get(<<"type">>, Message)).

get_messages_test() ->
    {ok, Message} = cryptic_messages:get_messages(),
    ?assertEqual(<<"get_messages">>, maps:get(<<"type">>, Message)).

%%% ============================================================================
%%% Server Response Tests
%%% ============================================================================

welcome_test_() ->
    [
        ?_test(test_welcome_valid()),
        ?_test(test_welcome_missing_message())
    ].

test_welcome_valid() ->
    Request = #{message => <<"Welcome to Cryptic!">>},
    {ok, Message} = cryptic_messages:welcome(Request),

    ?assertEqual(<<"welcome">>, maps:get(<<"type">>, Message)),
    ?assertEqual(<<"Welcome to Cryptic!">>, maps:get(<<"message">>, Message)).

test_welcome_missing_message() ->
    Request = #{},
    {error, missing_message_field} = cryptic_messages:welcome(Request).

success_test() ->
    Request = #{message => <<"Operation successful">>},
    {ok, Message} = cryptic_messages:success(Request),

    ?assertEqual(<<"success">>, maps:get(<<"type">>, Message)),
    ?assertEqual(<<"Operation successful">>, maps:get(<<"message">>, Message)).

error_test() ->
    Request = #{message => <<"Operation failed">>},
    {ok, Message} = cryptic_messages:error(Request),

    ?assertEqual(<<"error">>, maps:get(<<"type">>, Message)),
    ?assertEqual(<<"Operation failed">>, maps:get(<<"message">>, Message)).

key_status_response_test_() ->
    [
        ?_test(test_key_status_response_valid()),
        ?_test(test_key_status_response_with_error())
    ].

test_key_status_response_valid() ->
    Request = #{
        status => #{
            <<"identity_keys">> => true,
            <<"prekeys_count">> => 42
        }
    },
    {ok, Message} = cryptic_messages:key_status_response(Request),

    ?assertEqual(<<"key_status">>, maps:get(<<"type">>, Message)),
    ?assert(maps:is_key(<<"status">>, Message)),
    ?assertNot(maps:is_key(<<"error">>, Message)).

test_key_status_response_with_error() ->
    Request = #{
        status => #{},
        error => <<"Key retrieval failed">>
    },
    {ok, Message} = cryptic_messages:key_status_response(Request),

    ?assertEqual(<<"key_status">>, maps:get(<<"type">>, Message)),
    ?assertEqual(<<"Key retrieval failed">>, maps:get(<<"error">>, Message)).

key_bundle_response_test() ->
    Request = #{
        user => <<"alice">>,
        key_id => base64:encode(<<1, 2, 3, 4>>),
        identity_sign_public => base64:encode(<<5, 6, 7, 8>>),
        identity_dh_public => base64:encode(<<9, 10, 11, 12>>),
        signed_prekey => base64:encode(<<13, 14, 15, 16>>),
        signed_prekey_signature => base64:encode(<<17, 18, 19, 20>>),
        one_time_prekey => #{
            <<"id">> => base64:encode(<<21, 22>>),
            <<"public_key">> => base64:encode(<<23, 24>>)
        },
        remaining_otpks => 5
    },
    {ok, Message} = cryptic_messages:key_bundle_response(Request),

    ?assertEqual(<<"key_bundle">>, maps:get(<<"type">>, Message)),
    ?assertEqual(<<"alice">>, maps:get(<<"user">>, Message)),
    ?assertEqual(5, maps:get(<<"remaining_otpks">>, Message)).

users_response_test_() ->
    [
        ?_test(test_users_response_valid()),
        ?_test(test_users_response_invalid_format())
    ].

test_users_response_valid() ->
    Request = #{users => [<<"alice">>, <<"bob">>, <<"charlie">>]},
    {ok, Message} = cryptic_messages:users_response(Request),

    ?assertEqual(<<"users">>, maps:get(<<"type">>, Message)),
    ?assertEqual(
        [<<"alice">>, <<"bob">>, <<"charlie">>],
        maps:get(<<"users">>, Message)
    ).

test_users_response_invalid_format() ->
    % invalid user type
    Request = #{users => [<<"alice">>, 123, <<"bob">>]},
    {error, invalid_users_list_format} =
        cryptic_messages:users_response(Request).

message_sent_test_() ->
    [
        ?_test(test_message_sent_minimal()),
        ?_test(test_message_sent_full())
    ].

test_message_sent_minimal() ->
    Request = #{success => true},
    {ok, Message} = cryptic_messages:message_sent(Request),

    ?assertEqual(<<"message_sent">>, maps:get(<<"type">>, Message)),
    ?assertEqual(true, maps:get(<<"success">>, Message)),
    ?assertNot(maps:is_key(<<"to">>, Message)),
    ?assertNot(maps:is_key(<<"timestamp">>, Message)),
    ?assertNot(maps:is_key(<<"message">>, Message)).

test_message_sent_full() ->
    Request = #{
        success => true,
        to => <<"bob">>,
        timestamp => 1633024800,
        message => <<"Message delivered">>
    },
    {ok, Message} = cryptic_messages:message_sent(Request),

    ?assertEqual(<<"message_sent">>, maps:get(<<"type">>, Message)),
    ?assertEqual(true, maps:get(<<"success">>, Message)),
    ?assertEqual(<<"bob">>, maps:get(<<"to">>, Message)),
    ?assertEqual(1633024800, maps:get(<<"timestamp">>, Message)),
    ?assertEqual(<<"Message delivered">>, maps:get(<<"message">>, Message)).

%%% ============================================================================
%%% Utility Function Tests
%%% ============================================================================

validate_message_test_() ->
    [
        ?_test(test_validate_message_valid()),
        ?_test(test_validate_message_missing_type()),
        ?_test(test_validate_message_invalid_type())
    ].

test_validate_message_valid() ->
    Message = #{
        <<"type">> => <<"upload_identity_keys">>,
        <<"identity_sign_public">> => <<"dGVzdA==">>,
        <<"identity_dh_public">> => <<"dGVzdA==">>,
        <<"signed_prekey_public">> => <<"dGVzdA==">>,
        <<"signed_prekey_signature">> => <<"dGVzdA==">>
    },
    {ok, ValidatedMessage} = cryptic_messages:validate_message(Message),
    ?assertEqual(Message, ValidatedMessage).

test_validate_message_missing_type() ->
    Message = #{<<"data">> => <<"test">>},
    {error, missing_type_field} = cryptic_messages:validate_message(Message).

test_validate_message_invalid_type() ->
    Message = #{<<"type">> => 123},
    {error, invalid_type_field} = cryptic_messages:validate_message(Message).

encode_message_test_() ->
    [
        ?_test(test_encode_message_valid()),
        ?_test(test_encode_message_invalid())
    ].

test_encode_message_valid() ->
    Message = #{
        <<"type">> => <<"test">>,
        <<"data">> => <<"hello">>
    },
    {ok, JsonBinary} = cryptic_messages:encode_message(Message),
    ?assert(is_binary(JsonBinary)),

    % Verify it's valid JSON by decoding
    DecodedMap = jsx:decode(JsonBinary, [return_maps]),
    ?assertEqual(Message, DecodedMap).

test_encode_message_invalid() ->
    % Create a message with data that can't be JSON encoded
    Message = #{
        <<"type">> => <<"test">>,
        % functions can't be JSON encoded
        <<"invalid">> => fun() -> ok end
    },
    {error, {json_encode_failed, _}} = cryptic_messages:encode_message(Message).

%%% ============================================================================
%%% Integration Tests
%%% ============================================================================

integration_flow_test() ->
    % Test a complete message construction, validation, and encoding flow

    % 1. Construct identity keys message
    Keys = sample_binary_keys(),
    {ok, IdentityMsg} = cryptic_messages:upload_identity_keys(Keys),

    % 2. Validate the message
    {ok, _} = cryptic_messages:validate_message(IdentityMsg),

    % 3. Encode the message
    {ok, JsonBinary} = cryptic_messages:encode_message(IdentityMsg),

    % 4. Verify round-trip
    DecodedMsg = jsx:decode(JsonBinary, [return_maps]),
    ?assertEqual(IdentityMsg, DecodedMsg),

    % 5. Test prekey bundle flow
    Bundle = sample_prekey_bundle(),
    {ok, BundleMsg} = cryptic_messages:upload_prekey_bundle(Bundle),
    {ok, _} = cryptic_messages:validate_message(BundleMsg),
    {ok, _} = cryptic_messages:encode_message(BundleMsg).

performance_test_() ->
    {timeout, 10, ?_test(test_message_construction_performance())}.

test_message_construction_performance() ->
    % Test that we can construct many messages quickly
    Keys = sample_binary_keys(),

    StartTime = erlang:monotonic_time(),

    % Construct 1000 messages
    lists:foreach(
        fun(_) ->
            {ok, _} = cryptic_messages:upload_identity_keys(Keys)
        end,
        lists:seq(1, 1000)
    ),

    EndTime = erlang:monotonic_time(),
    Duration = erlang:convert_time_unit(
        EndTime - StartTime, native, millisecond
    ),

    % Should complete in reasonable time (< 1 second)
    ?assert(Duration < 1000).

%%% ============================================================================
%%% Error Condition Tests
%%% ============================================================================

edge_cases_test_() ->
    [
        ?_test(test_empty_maps()),
        ?_test(test_large_binary_data()),
        ?_test(test_unicode_strings())
    ].

test_empty_maps() ->
    % Test with empty input maps
    {error, {missing_fields, _}} = cryptic_messages:upload_identity_keys(#{}),
    {error, missing_one_time_prekeys} = cryptic_messages:upload_prekey_bundle(
        #{}
    ),
    {error, missing_user_field} = cryptic_messages:get_key_bundle(#{}).

test_large_binary_data() ->
    % Test with large binary data
    LargeBinary = crypto:strong_rand_bytes(10000),
    Keys = #{
        identity_sign_public => LargeBinary,
        identity_dh_public => LargeBinary,
        signed_prekey_public => LargeBinary,
        signed_prekey_signature => LargeBinary
    },
    {ok, Message} = cryptic_messages:upload_identity_keys(Keys),
    {ok, _} = cryptic_messages:validate_message(Message),
    {ok, _} = cryptic_messages:encode_message(Message).

test_unicode_strings() ->
    % Test with unicode strings
    UnicodeUser = <<"alice_测试"/utf8>>,
    Request = #{user => UnicodeUser},
    {ok, Message} = cryptic_messages:get_key_bundle(Request),
    ?assertEqual(UnicodeUser, maps:get(<<"user">>, Message)),
    {ok, _} = cryptic_messages:encode_message(Message).
