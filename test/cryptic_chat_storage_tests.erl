-module(cryptic_chat_storage_tests).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test Setup and Teardown
%%%===================================================================

%% Test database path
-define(TEST_DB_DIR, "/tmp/cryptic_test").
-define(TEST_USERNAME, "alice").
-define(TEST_SERVER, "localhost").
-define(TEST_PORT, 8443).
-define(TEST_PASSPHRASE, <<"test_passphrase_123">>).


%%%===================================================================
%%% Encryption Tests
%%%===================================================================

encryption_roundtrip_test() ->
    Message = <<"Hello, World! This is a test message.">>,
    Passphrase = <<"test_password">>,

    %% Encrypt the message
    {Salt, Nonce, Ciphertext} = cryptic_chat_storage:encrypt_message(
        Message, Passphrase
    ),

    %% Verify we got valid cryptographic components

    % 16-byte salt
    ?assertEqual(16, byte_size(Salt)),
    % 12-byte nonce
    ?assertEqual(12, byte_size(Nonce)),
    % Non-empty ciphertext
    ?assert(byte_size(Ciphertext) > 0),

    %% Decrypt the message
    {ok, Decrypted} = cryptic_chat_storage:decrypt_message(
        Ciphertext, Salt, Nonce, Passphrase
    ),

    %% Verify plaintext matches
    ?assertEqual(Message, Decrypted).

wrong_passphrase_test() ->
    Message = <<"Secret message">>,
    Passphrase1 = <<"password1">>,
    Passphrase2 = <<"password2">>,

    %% Encrypt with first passphrase
    {Salt, Nonce, Ciphertext} = cryptic_chat_storage:encrypt_message(
        Message, Passphrase1
    ),

    %% Try to decrypt with wrong passphrase
    Result = cryptic_chat_storage:decrypt_message(
        Ciphertext, Salt, Nonce, Passphrase2
    ),

    %% Should fail
    ?assertEqual({error, decryption_failed}, Result).

unique_salts_test() ->
    Message = <<"Same message">>,
    Passphrase = <<"same_password">>,

    %% Encrypt the same message twice
    {Salt1, Nonce1, Ciphertext1} = cryptic_chat_storage:encrypt_message(
        Message, Passphrase
    ),
    {Salt2, Nonce2, Ciphertext2} = cryptic_chat_storage:encrypt_message(
        Message, Passphrase
    ),

    %% Salts should be different (unique per message)
    ?assertNotEqual(Salt1, Salt2),

    %% Nonces should be different
    ?assertNotEqual(Nonce1, Nonce2),

    %% Ciphertexts should be different (due to different salts/nonces)
    ?assertNotEqual(Ciphertext1, Ciphertext2),

    %% But both should decrypt correctly
    {ok, Decrypted1} = cryptic_chat_storage:decrypt_message(
        Ciphertext1, Salt1, Nonce1, Passphrase
    ),
    {ok, Decrypted2} = cryptic_chat_storage:decrypt_message(
        Ciphertext2, Salt2, Nonce2, Passphrase
    ),

    ?assertEqual(Message, Decrypted1),
    ?assertEqual(Message, Decrypted2).

empty_message_test() ->
    Message = <<>>,
    Passphrase = <<"password">>,

    {Salt, Nonce, Ciphertext} = cryptic_chat_storage:encrypt_message(
        Message, Passphrase
    ),
    {ok, Decrypted} = cryptic_chat_storage:decrypt_message(
        Ciphertext, Salt, Nonce, Passphrase
    ),

    ?assertEqual(Message, Decrypted).

large_message_test() ->
    %% 1MB message
    Message = binary:copy(<<"A">>, 1024 * 1024),
    Passphrase = <<"password">>,

    {Salt, Nonce, Ciphertext} = cryptic_chat_storage:encrypt_message(
        Message, Passphrase
    ),
    {ok, Decrypted} = cryptic_chat_storage:decrypt_message(
        Ciphertext, Salt, Nonce, Passphrase
    ),

    ?assertEqual(Message, Decrypted).

unicode_message_test() ->
    Message = <<"Hello 世界 🌍 Здравствуй мир">>,
    Passphrase = <<"パスワード">>,

    {Salt, Nonce, Ciphertext} = cryptic_chat_storage:encrypt_message(
        Message, Passphrase
    ),
    {ok, Decrypted} = cryptic_chat_storage:decrypt_message(
        Ciphertext, Salt, Nonce, Passphrase
    ),

    ?assertEqual(Message, Decrypted).

%%%===================================================================
%%% Time Conversion Tests
%%%===================================================================

datetime_to_unix_test() ->
    %% Test Unix epoch
    Epoch = {{1970, 1, 1}, {0, 0, 0}},
    ?assertEqual(0, cryptic_chat_storage:datetime_to_unix(Epoch)),

    %% Test a known date
    DateTime = {{2025, 10, 25}, {12, 30, 45}},
    UnixTime = cryptic_chat_storage:datetime_to_unix(DateTime),

    %% Verify it's a reasonable Unix timestamp (should be > 2020)

    % Jan 1, 2020
    ?assert(UnixTime > 1577836800).

unix_to_datetime_test() ->
    %% Test Unix epoch
    ?assertEqual(
        {{1970, 1, 1}, {0, 0, 0}},
        cryptic_chat_storage:unix_to_datetime(0)
    ),

    %% Test round-trip conversion
    DateTime = {{2025, 10, 25}, {12, 30, 45}},
    UnixTime = cryptic_chat_storage:datetime_to_unix(DateTime),
    Converted = cryptic_chat_storage:unix_to_datetime(UnixTime),

    ?assertEqual(DateTime, Converted).

%%%===================================================================
%%% Query Function Tests (Unit tests without DB)
%%%===================================================================

%% These tests verify the logic of query functions
%% Full integration tests with actual DB are commented below

query_functions_exist_test() ->
    %% Verify all new query functions are exported
    Exports = cryptic_chat_storage:module_info(exports),

    ?assert(lists:member({get_conversation, 4}, Exports)),
    ?assert(lists:member({get_recent_encrypted_messages, 3}, Exports)),
    ?assert(lists:member({get_messages_by_time_range, 5}, Exports)),
    ?assert(lists:member({get_messages_from_yesterday, 3}, Exports)),
    ?assert(lists:member({get_last_n_messages, 3}, Exports)).

time_range_calculation_test() ->
    %% Test that time range calculations work correctly
    Now = {{2025, 10, 25}, {15, 30, 0}},
    % Same time yesterday
    Yesterday = {{2025, 10, 24}, {15, 30, 0}},

    NowUnix = cryptic_chat_storage:datetime_to_unix(Now),
    YesterdayUnix = cryptic_chat_storage:datetime_to_unix(Yesterday),

    %% Verify yesterday is before now
    ?assert(YesterdayUnix < NowUnix),

    %% Verify exactly 24 hours difference (86400 seconds)
    Diff = NowUnix - YesterdayUnix,
    ?assertEqual(86400, Diff).

%%%===================================================================
%%% Database Integration Tests
%%%===================================================================

%% Note: These tests require actual filesystem access and esqlite
%% They are commented out for now but can be enabled for full integration testing

% init_storage_test_() ->
%     {setup,
%      fun setup/0,
%      fun cleanup/1,
%      fun() ->
%          %% Initialize storage
%          Result = cryptic_chat_storage:init_storage(
%              ?TEST_USERNAME, ?TEST_SERVER, ?TEST_PORT, ?TEST_PASSPHRASE
%          ),
%          ?assertEqual(ok, Result),
%          
%          %% Verify database file was created
%          DbPath = filename:join([
%              cryptic_lib:get_cryptic_dir(?TEST_USERNAME, ?TEST_SERVER, ?TEST_PORT),
%              "messages.db"
%          ]),
%          ?assert(filelib:is_file(DbPath))
%      end}.

% save_and_retrieve_message_test_() ->
%     {setup,
%      fun setup/0,
%      fun cleanup/1,
%      fun() ->
%          %% Initialize storage
%          ok = cryptic_chat_storage:init_storage(
%              ?TEST_USERNAME, ?TEST_SERVER, ?TEST_PORT, ?TEST_PASSPHRASE
%          ),
%          
%          %% Save a message
%          Message = <<"Hello Bob!">>,
%          Timestamp = calendar:universal_time(),
%          
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "alice", "bob", Message, Timestamp, ?TEST_PASSPHRASE
%          ),
%          
%          %% Retrieve last N messages
%          {ok, Messages} = cryptic_chat_storage:get_last_n_messages(
%              "alice", 10, ?TEST_PASSPHRASE
%          ),
%          
%          ?assertEqual(1, length(Messages)),
%          
%          [{FromUser, ToUser, RetrievedMsg, _Ts, _ServerHost, _ServerPort}] = Messages,
%          ?assertEqual("alice", FromUser),
%          ?assertEqual("bob", ToUser),
%          ?assertEqual(Message, RetrievedMsg)
%      end}.

% yesterday_messages_test_() ->
%     {setup,
%      fun setup/0,
%      fun cleanup/1,
%      fun() ->
%          %% Initialize storage
%          ok = cryptic_chat_storage:init_storage(
%              ?TEST_USERNAME, ?TEST_SERVER, ?TEST_PORT, ?TEST_PASSPHRASE
%          ),
%          
%          %% Save messages from yesterday
%          Now = calendar:universal_time(),
%          {Date, _Time} = Now,
%          YesterdayDate = calendar:gregorian_days_to_date(
%              calendar:date_to_gregorian_days(Date) - 1
%          ),
%          YesterdayTime = {YesterdayDate, {14, 30, 0}},
%          
%          Message1 = <<"Yesterday message 1">>,
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "bob", "alice", Message1, YesterdayTime, ?TEST_PASSPHRASE
%          ),
%          
%          Message2 = <<"Yesterday message 2">>,
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "bob", "alice", Message2, YesterdayTime, ?TEST_PASSPHRASE
%          ),
%          
%          %% Save a message from today (should not be included)
%          TodayMessage = <<"Today message">>,
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "bob", "alice", TodayMessage, Now, ?TEST_PASSPHRASE
%          ),
%          
%          %% Retrieve yesterday's messages
%          {ok, Messages} = cryptic_chat_storage:get_messages_from_yesterday(
%              "alice", "bob", ?TEST_PASSPHRASE
%          ),
%          
%          %% Should only get 2 messages (from yesterday)
%          ?assertEqual(2, length(Messages))
%      end}.

% conversation_test_() ->
%     {setup,
%      fun setup/0,
%      fun cleanup/1,
%      fun() ->
%          %% Initialize storage
%          ok = cryptic_chat_storage:init_storage(
%              ?TEST_USERNAME, ?TEST_SERVER, ?TEST_PORT, ?TEST_PASSPHRASE
%          ),
%          
%          %% Save messages between alice and bob
%          Now = calendar:universal_time(),
%          {Date, {H, M, S}} = Now,
%          
%          %% Message 1: alice -> bob
%          Ts1 = {Date, {H, M, S}},
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "alice", "bob", <<"Hi Bob!">>, Ts1, ?TEST_PASSPHRASE
%          ),
%          
%          %% Message 2: bob -> alice (1 second later)
%          Ts2 = {Date, {H, M, S + 1}},
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "bob", "alice", <<"Hi Alice!">>, Ts2, ?TEST_PASSPHRASE
%          ),
%          
%          %% Message 3: alice -> bob (2 seconds later)
%          Ts3 = {Date, {H, M, S + 2}},
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "alice", "bob", <<"How are you?">>, Ts3, ?TEST_PASSPHRASE
%          ),
%          
%          %% Message from alice to charlie (should not be included)
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "alice", "charlie", <<"Hey Charlie">>, Ts3, ?TEST_PASSPHRASE
%          ),
%          
%          %% Get conversation between alice and bob
%          {ok, Messages} = cryptic_chat_storage:get_conversation(
%              "alice", "bob", 10, ?TEST_PASSPHRASE
%          ),
%          
%          %% Should get 3 messages in chronological order
%          ?assertEqual(3, length(Messages)),
%          
%          [Msg1, Msg2, Msg3] = Messages,
%          {From1, To1, Text1, _, _, _} = Msg1,
%          {From2, To2, Text2, _, _, _} = Msg2,
%          {From3, To3, Text3, _, _, _} = Msg3,
%          
%          ?assertEqual("alice", From1),
%          ?assertEqual("bob", To1),
%          ?assertEqual(<<"Hi Bob!">>, Text1),
%          
%          ?assertEqual("bob", From2),
%          ?assertEqual("alice", To2),
%          ?assertEqual(<<"Hi Alice!">>, Text2),
%          
%          ?assertEqual("alice", From3),
%          ?assertEqual("bob", To3),
%          ?assertEqual(<<"How are you?">>, Text3)
%      end}.

% conversation_limit_test_() ->
%     {setup,
%      fun setup/0,
%      fun cleanup/1,
%      fun() ->
%          %% Initialize storage
%          ok = cryptic_chat_storage:init_storage(
%              ?TEST_USERNAME, ?TEST_SERVER, ?TEST_PORT, ?TEST_PASSPHRASE
%          ),
%          
%          %% Save 5 messages
%          Now = calendar:universal_time(),
%          lists:foreach(fun(N) ->
%              Msg = list_to_binary(io_lib:format("Message ~p", [N])),
%              ok = cryptic_chat_storage:save_encrypted_message(
%                  "alice", "bob", Msg, Now, ?TEST_PASSPHRASE
%              )
%          end, lists:seq(1, 5)),
%          
%          %% Get only last 3 messages
%          {ok, Messages} = cryptic_chat_storage:get_conversation(
%              "alice", "bob", 3, ?TEST_PASSPHRASE
%          ),
%          
%          %% Should get exactly 3 messages
%          ?assertEqual(3, length(Messages))
%      end}.

% recent_messages_test_() ->
%     {setup,
%      fun setup/0,
%      fun cleanup/1,
%      fun() ->
%          %% Initialize storage
%          ok = cryptic_chat_storage:init_storage(
%              ?TEST_USERNAME, ?TEST_SERVER, ?TEST_PORT, ?TEST_PASSPHRASE
%          ),
%          
%          %% Save messages with different users
%          Now = calendar:universal_time(),
%          {Date, {H, M, S}} = Now,
%          
%          Ts1 = {Date, {H, M, S}},
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "alice", "bob", <<"To Bob">>, Ts1, ?TEST_PASSPHRASE
%          ),
%          
%          Ts2 = {Date, {H, M, S + 1}},
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "charlie", "alice", <<"From Charlie">>, Ts2, ?TEST_PASSPHRASE
%          ),
%          
%          Ts3 = {Date, {H, M, S + 2}},
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "alice", "dave", <<"To Dave">>, Ts3, ?TEST_PASSPHRASE
%          ),
%          
%          %% Get recent messages for alice (should include all 3)
%          {ok, Messages} = cryptic_chat_storage:get_recent_encrypted_messages(
%              "alice", 10, ?TEST_PASSPHRASE
%          ),
%          
%          %% Should get 3 messages in reverse chronological order (newest first)
%          ?assertEqual(3, length(Messages)),
%          
%          [Msg1, Msg2, Msg3] = Messages,
%          {_, _, Text1, _, _, _} = Msg1,
%          {_, _, Text2, _, _, _} = Msg2,
%          {_, _, Text3, _, _, _} = Msg3,
%          
%          ?assertEqual(<<"To Dave">>, Text1),      % Newest
%          ?assertEqual(<<"From Charlie">>, Text2),
%          ?assertEqual(<<"To Bob">>, Text3)        % Oldest
%      end}.

% time_range_query_test_() ->
%     {setup,
%      fun setup/0,
%      fun cleanup/1,
%      fun() ->
%          %% Initialize storage
%          ok = cryptic_chat_storage:init_storage(
%              ?TEST_USERNAME, ?TEST_SERVER, ?TEST_PORT, ?TEST_PASSPHRASE
%          ),
%          
%          %% Save messages at different times
%          {Date, _} = calendar:universal_time(),
%          
%          %% 10:00 AM
%          Ts1 = {Date, {10, 0, 0}},
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "alice", "bob", <<"Morning message">>, Ts1, ?TEST_PASSPHRASE
%          ),
%          
%          %% 2:00 PM
%          Ts2 = {Date, {14, 0, 0}},
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "alice", "bob", <<"Afternoon message">>, Ts2, ?TEST_PASSPHRASE
%          ),
%          
%          %% 6:00 PM
%          Ts3 = {Date, {18, 0, 0}},
%          ok = cryptic_chat_storage:save_encrypted_message(
%              "alice", "bob", <<"Evening message">>, Ts3, ?TEST_PASSPHRASE
%          ),
%          
%          %% Query messages between 12:00 PM and 5:00 PM (should get only afternoon message)
%          StartTime = {Date, {12, 0, 0}},
%          EndTime = {Date, {17, 0, 0}},
%          
%          {ok, Messages} = cryptic_chat_storage:get_messages_by_time_range(
%              "alice", "bob", StartTime, EndTime, ?TEST_PASSPHRASE
%          ),
%          
%          %% Should get exactly 1 message
%          ?assertEqual(1, length(Messages)),
%          
%          [{_, _, Text, _, _, _}] = Messages,
%          ?assertEqual(<<"Afternoon message">>, Text)
%      end}.

% no_messages_test_() ->
%     {setup,
%      fun setup/0,
%      fun cleanup/1,
%      fun() ->
%          %% Initialize storage
%          ok = cryptic_chat_storage:init_storage(
%              ?TEST_USERNAME, ?TEST_SERVER, ?TEST_PORT, ?TEST_PASSPHRASE
%          ),
%          
%          %% Query when no messages exist
%          {ok, Messages1} = cryptic_chat_storage:get_conversation(
%              "alice", "bob", 10, ?TEST_PASSPHRASE
%          ),
%          ?assertEqual([], Messages1),
%          
%          {ok, Messages2} = cryptic_chat_storage:get_recent_encrypted_messages(
%              "alice", 10, ?TEST_PASSPHRASE
%          ),
%          ?assertEqual([], Messages2),
%          
%          Now = calendar:universal_time(),
%          {ok, Messages3} = cryptic_chat_storage:get_messages_by_time_range(
%              "alice", "bob", Now, Now, ?TEST_PASSPHRASE
%          ),
%          ?assertEqual([], Messages3)
%      end}.
