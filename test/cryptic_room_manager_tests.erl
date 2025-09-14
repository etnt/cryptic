%%% @doc EUnit tests for Cryptic Room Manager
%%%
%%% This module provides comprehensive unit tests for the chat room functionality
%%% implemented in Phase 1. It tests room creation, membership management,
%%% encrypted messaging, and cleanup operations.
%%%
%%% == Test Coverage ==
%%%
%%% <ul>
%%%   <li>Room lifecycle (create, join, leave, delete)</li>
%%%   <li>User membership management</li>
%%%   <li>End-to-end encrypted messaging</li>
%%%   <li>Room listing and information retrieval</li>
%%%   <li>Error handling and edge cases</li>
%%%   <li>Data consistency and cleanup</li>
%%% </ul>
%%%
%%% == Running Tests ==
%%%
%%% ```
%%% %% Run all tests
%%% eunit:test(cryptic_room_manager_tests).
%%%
%%% %% Run specific test
%%% eunit:test({module, cryptic_room_manager_tests}, [verbose]).
%%% '''
%%%
%%% @author Cryptic Team
%%% @version 1.0
%%% @since 2025-09-14

-module(cryptic_room_manager_tests).

-include_lib("eunit/include/eunit.hrl").

%% Include record definitions
-record(room, {
    id :: binary(),
    name :: binary(),
    description :: binary(),
    type :: public | private,
    owner :: binary(),
    created_at :: integer(),
    members :: [binary()],
    password_hash :: binary() | undefined
}).

-record(room_message, {
    id :: binary(),
    room_id :: binary(),
    from :: binary(),
    timestamp :: integer(),
    recipients :: [{binary(), binary(), binary()}]
}).


%%%===================================================================
%%% Test Setup and Teardown
%%%===================================================================

%% @doc Set up test environment
setup() ->
    % Create ETS tables directly for testing
    % Room manager tables
    try ets:delete(rooms) catch _:_ -> ok end,
    try ets:delete(room_messages) catch _:_ -> ok end,
    try ets:delete(user_rooms) catch _:_ -> ok end,
    
    ets:new(rooms, [named_table, set, public, {keypos, 2}]),
    ets:new(room_messages, [named_table, bag, public, {keypos, 3}]),
    ets:new(user_rooms, [named_table, bag, public]),
    
    % Cryptic lib tables
    try ets:delete(cryptic_prekeys) catch _:_ -> ok end,
    try ets:delete(cryptic_messages) catch _:_ -> ok end,
    try ets:delete(cryptic_users) catch _:_ -> ok end,
    
    ets:new(cryptic_prekeys, [named_table, public, bag]),
    ets:new(cryptic_messages, [named_table, public, bag]),
    ets:new(cryptic_users, [named_table, public, bag]),
    
    % Set up test users with prekeys
    ok = cryptic_lib:store_prekey("alice", <<"alice_prekey_32_bytes_long_test!">>),
    ok = cryptic_lib:store_prekey("bob", <<"bob_prekey_32_bytes_long_test!!">>),
    ok = cryptic_lib:store_prekey("charlie", <<"charlie_prekey_32_bytes_long_tes">>),
    
    ok.

%% @doc Clean up test environment
cleanup(_) ->
    % Clean up ETS tables
    try ets:delete(rooms) catch _:_ -> ok end,
    try ets:delete(room_messages) catch _:_ -> ok end,
    try ets:delete(user_rooms) catch _:_ -> ok end,
    try ets:delete(cryptic_prekeys) catch _:_ -> ok end,
    try ets:delete(cryptic_messages) catch _:_ -> ok end,
    try ets:delete(cryptic_users) catch _:_ -> ok end,
    ok.

%% @doc Set up each individual test
setup_each_test() ->
    % Clear all room data between tests
    try ets:delete_all_objects(rooms) catch _:_ -> ok end,
    try ets:delete_all_objects(room_messages) catch _:_ -> ok end,
    try ets:delete_all_objects(user_rooms) catch _:_ -> ok end,
    ok.

%% @doc Clean up each individual test
cleanup_each_test(_) ->
    % Clear all room data after each test
    try ets:delete_all_objects(rooms) catch _:_ -> ok end,
    try ets:delete_all_objects(room_messages) catch _:_ -> ok end,
    try ets:delete_all_objects(user_rooms) catch _:_ -> ok end,
    ok.

%%%===================================================================
%%% Test Suite Definition
%%%===================================================================

%% Main test suite
cryptic_room_manager_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
         {"Room creation and basic operations", {setup, fun setup_each_test/0, fun cleanup_each_test/1, fun test_room_creation/0}},
         {"Room membership management", {setup, fun setup_each_test/0, fun cleanup_each_test/1, fun test_room_membership/0}},
         {"End-to-end encrypted messaging", {setup, fun setup_each_test/0, fun cleanup_each_test/1, fun test_encrypted_messaging/0}},
         {"Room listing and information", {setup, fun setup_each_test/0, fun cleanup_each_test/1, fun test_room_listing/0}},
         {"Room deletion and cleanup", {setup, fun setup_each_test/0, fun cleanup_each_test/1, fun test_room_deletion/0}},
         {"Error handling", {setup, fun setup_each_test/0, fun cleanup_each_test/1, fun test_error_handling/0}},
         {"Multiple rooms scenario", {setup, fun setup_each_test/0, fun cleanup_each_test/1, fun test_multiple_rooms/0}}
     ]}.

%%%===================================================================
%%% Individual Tests
%%%===================================================================

%% @doc Test basic room creation functionality
test_room_creation() ->
    % Test room creation
    {ok, RoomId} = cryptic_room_manager:create_room(
        <<"Test Room">>, 
        <<"A room for testing">>, 
        public, 
        <<"alice">>
    ),
    
    % Verify room ID is a binary UUID
    ?assert(is_binary(RoomId)),
    ?assert(byte_size(RoomId) > 0),
    
    % Verify room exists and has correct properties
    {ok, Room} = cryptic_room_manager:get_room_info(RoomId),
    ?assertEqual(<<"Test Room">>, Room#room.name),
    ?assertEqual(<<"A room for testing">>, Room#room.description),
    ?assertEqual(public, Room#room.type),
    ?assertEqual(<<"alice">>, Room#room.owner),
    ?assertEqual([<<"alice">>], Room#room.members),
    
    % Verify owner is automatically added to user_rooms
    ?assert(cryptic_room_manager:is_room_member(<<"alice">>, RoomId)),
    
    UserRooms = cryptic_room_manager:get_user_rooms(<<"alice">>),
    ?assert(lists:member(RoomId, UserRooms)).

%% @doc Test room membership operations
test_room_membership() ->
    % Create a room
    {ok, RoomId} = cryptic_room_manager:create_room(
        <<"Membership Test">>, 
        <<"Testing membership">>, 
        public, 
        <<"alice">>
    ),
    
    % Test joining room
    ?assertEqual(ok, cryptic_room_manager:join_room(RoomId, <<"bob">>, undefined)),
    
    % Verify bob is now a member
    {ok, Members} = cryptic_room_manager:get_room_members(RoomId),
    ?assert(lists:member(<<"bob">>, Members)),
    ?assert(lists:member(<<"alice">>, Members)),
    ?assertEqual(2, length(Members)),
    
    % Test that user can't join twice
    ?assertEqual({error, already_member}, 
                 cryptic_room_manager:join_room(RoomId, <<"bob">>, undefined)),
    
    % Test leaving room (non-owner)
    ?assertEqual(ok, cryptic_room_manager:leave_room(RoomId, <<"bob">>)),
    
    % Verify bob is no longer a member
    {ok, MembersAfter} = cryptic_room_manager:get_room_members(RoomId),
    ?assertNot(lists:member(<<"bob">>, MembersAfter)),
    ?assert(lists:member(<<"alice">>, MembersAfter)),
    ?assertEqual(1, length(MembersAfter)),
    
    % Test joining again after leaving
    ?assertEqual(ok, cryptic_room_manager:join_room(RoomId, <<"bob">>, undefined)).

%% @doc Test end-to-end encrypted messaging
test_encrypted_messaging() ->
    % Create room with alice and bob
    {ok, RoomId} = cryptic_room_manager:create_room(
        <<"Crypto Test">>, 
        <<"Testing encryption">>, 
        public, 
        <<"alice">>
    ),
    ?assertEqual(ok, cryptic_room_manager:join_room(RoomId, <<"bob">>, undefined)),
    
    % Send encrypted message
    TestMessage = <<"Hello Bob, this is a secret message!">>,
    {ok, MessageId} = cryptic_room_manager:send_room_message(
        RoomId, 
        <<"alice">>, 
        TestMessage
    ),
    
    % Verify message ID is generated
    ?assert(is_binary(MessageId)),
    ?assert(byte_size(MessageId) > 0),
    
    % Retrieve room messages
    Messages = cryptic_room_manager:get_room_messages(RoomId, 0),
    ?assertEqual(1, length(Messages)),
    
    [Message] = Messages,
    ?assertEqual(MessageId, Message#room_message.id),
    ?assertEqual(RoomId, Message#room_message.room_id),
    ?assertEqual(<<"alice">>, Message#room_message.from),
    
    % Verify encryption worked (recipients list should contain Bob's encrypted data)
    Recipients = Message#room_message.recipients,
    ?assertEqual(1, length(Recipients)),
    
    {<<"bob">>, EphemeralKey, EncryptedData} = hd(Recipients),
    ?assert(is_binary(EphemeralKey)),
    ?assert(is_binary(EncryptedData)),
    ?assert(byte_size(EncryptedData) > 0),
    
    % Test decryption
    {ok, DecryptedMessage} = cryptic_room_manager:decrypt_message_for_user(
        EncryptedData, 
        EphemeralKey, 
        "bob"
    ),
    
    % Verify the decrypted message matches the original
    ?assertEqual(TestMessage, DecryptedMessage).

%% @doc Test room listing and information retrieval
test_room_listing() ->
    % Create multiple rooms
    {ok, Room1} = cryptic_room_manager:create_room(
        <<"Public Room 1">>, <<"Public room">>, public, <<"alice">>),
    {ok, _Room2} = cryptic_room_manager:create_room(
        <<"Private Room 1">>, <<"Private room">>, private, <<"bob">>),
    {ok, _Room3} = cryptic_room_manager:create_room(
        <<"Public Room 2">>, <<"Another public room">>, public, <<"alice">>),
    
    % Test listing all rooms
    AllRooms = cryptic_room_manager:list_rooms(all),
    ?assertEqual(3, length(AllRooms)),
    
    % Test listing public rooms
    PublicRooms = cryptic_room_manager:list_rooms(public),
    ?assertEqual(2, length(PublicRooms)),
    
    % Test listing private rooms
    PrivateRooms = cryptic_room_manager:list_rooms(private),
    ?assertEqual(1, length(PrivateRooms)),
    
    % Test listing user's rooms
    AliceRooms = cryptic_room_manager:list_rooms({user, <<"alice">>}),
    ?assertEqual(2, length(AliceRooms)),
    
    BobRooms = cryptic_room_manager:list_rooms({user, <<"bob">>}),
    ?assertEqual(1, length(BobRooms)),
    
    % Test room info retrieval
    {ok, RoomInfo} = cryptic_room_manager:get_room_info(Room1),
    ?assertEqual(<<"Public Room 1">>, RoomInfo#room.name),
    ?assertEqual(public, RoomInfo#room.type),
    ?assertEqual(<<"alice">>, RoomInfo#room.owner).

%% @doc Test room deletion and cleanup
test_room_deletion() ->
    % Create room and add members
    {ok, RoomId} = cryptic_room_manager:create_room(
        <<"Delete Test">>, <<"Test deletion">>, public, <<"alice">>),
    ?assertEqual(ok, cryptic_room_manager:join_room(RoomId, <<"bob">>, undefined)),
    
    % Send a message to create room history
    {ok, _MessageId} = cryptic_room_manager:send_room_message(
        RoomId, <<"alice">>, <<"Test message">>),
    
    % Verify room exists with messages and members
    {ok, _RoomInfo} = cryptic_room_manager:get_room_info(RoomId),
    {ok, Members} = cryptic_room_manager:get_room_members(RoomId),
    ?assertEqual(2, length(Members)),
    
    Messages = cryptic_room_manager:get_room_messages(RoomId, 0),
    ?assertEqual(1, length(Messages)),
    
    % Test owner leaving (should delete room)
    ?assertEqual(ok, cryptic_room_manager:leave_room(RoomId, <<"alice">>)),
    
    % Verify room is completely deleted
    ?assertEqual({error, not_found}, cryptic_room_manager:get_room_info(RoomId)),
    ?assertEqual({error, not_found}, cryptic_room_manager:get_room_members(RoomId)),
    
    % Verify user memberships are cleaned up
    AliceRooms = cryptic_room_manager:get_user_rooms(<<"alice">>),
    ?assertNot(lists:member(RoomId, AliceRooms)),
    
    BobRooms = cryptic_room_manager:get_user_rooms(<<"bob">>),
    ?assertNot(lists:member(RoomId, BobRooms)),
    
    % Verify messages are cleaned up
    MessagesAfter = cryptic_room_manager:get_room_messages(RoomId, 0),
    ?assertEqual([], MessagesAfter).

%% @doc Test error handling and edge cases
test_error_handling() ->
    % Test operations on non-existent room
    FakeRoomId = <<"fake-room-id">>,
    ?assertEqual({error, room_not_found}, 
                 cryptic_room_manager:join_room(FakeRoomId, <<"alice">>, undefined)),
    ?assertEqual({error, room_not_found}, 
                 cryptic_room_manager:leave_room(FakeRoomId, <<"alice">>)),
    ?assertEqual({error, not_found}, 
                 cryptic_room_manager:get_room_info(FakeRoomId)),
    ?assertEqual({error, not_found}, 
                 cryptic_room_manager:get_room_members(FakeRoomId)),
    
    % Create a room for further error testing
    {ok, RoomId} = cryptic_room_manager:create_room(
        <<"Error Test">>, <<"Testing errors">>, public, <<"alice">>),
    
    % Test non-member trying to send message
    ?assertEqual({error, not_member}, 
                 cryptic_room_manager:send_room_message(RoomId, <<"bob">>, <<"Hello">>)),
    
    % Test non-owner trying to delete room
    ?assertEqual(ok, cryptic_room_manager:join_room(RoomId, <<"bob">>, undefined)),
    ?assertEqual({error, not_owner}, 
                 cryptic_room_manager:delete_room(RoomId, <<"bob">>)),
    
    % Test non-member trying to leave
    ?assertEqual(ok, cryptic_room_manager:leave_room(RoomId, <<"bob">>)),
    ?assertEqual({error, not_member}, 
                 cryptic_room_manager:leave_room(RoomId, <<"bob">>)),
    
    % Test sending message to user without prekey
    ?assertEqual(ok, cryptic_room_manager:join_room(RoomId, <<"bob">>, undefined)),
    
    % Temporarily remove bob's prekey to test encryption failure
    ets:delete(cryptic_prekeys, "bob"),
    
    % Message should still be sent but bob won't have an encrypted copy
    {ok, _MessageId} = cryptic_room_manager:send_room_message(
        RoomId, <<"alice">>, <<"Message without recipient key">>),
    
    % Restore bob's prekey for cleanup
    cryptic_lib:store_prekey("bob", <<"bob_prekey_32_bytes_long_test!!">>).

%% @doc Test multiple rooms scenario
test_multiple_rooms() ->
    % Create multiple rooms with different owners
    {ok, Room1} = cryptic_room_manager:create_room(
        <<"Room 1">>, <<"First room">>, public, <<"alice">>),
    {ok, Room2} = cryptic_room_manager:create_room(
        <<"Room 2">>, <<"Second room">>, public, <<"bob">>),
    {ok, Room3} = cryptic_room_manager:create_room(
        <<"Room 3">>, <<"Third room">>, private, <<"alice">>),
    
    % Users join multiple rooms
    ?assertEqual(ok, cryptic_room_manager:join_room(Room1, <<"bob">>, undefined)),
    ?assertEqual(ok, cryptic_room_manager:join_room(Room1, <<"charlie">>, undefined)),
    ?assertEqual(ok, cryptic_room_manager:join_room(Room2, <<"alice">>, undefined)),
    ?assertEqual(ok, cryptic_room_manager:join_room(Room3, <<"charlie">>, undefined)),
    
    % Test cross-room messaging
    {ok, _Msg1} = cryptic_room_manager:send_room_message(
        Room1, <<"alice">>, <<"Message in room 1">>),
    {ok, _Msg2} = cryptic_room_manager:send_room_message(
        Room2, <<"bob">>, <<"Message in room 2">>),
    {ok, _Msg3} = cryptic_room_manager:send_room_message(
        Room3, <<"alice">>, <<"Private message">>),
    
    % Verify message isolation (messages only in correct rooms)
    Messages1 = cryptic_room_manager:get_room_messages(Room1, 0),
    Messages2 = cryptic_room_manager:get_room_messages(Room2, 0),
    Messages3 = cryptic_room_manager:get_room_messages(Room3, 0),
    
    ?assertEqual(1, length(Messages1)),
    ?assertEqual(1, length(Messages2)),
    ?assertEqual(1, length(Messages3)),
    
    % Verify user room memberships
    AliceRooms = cryptic_room_manager:list_rooms({user, <<"alice">>}),
    BobRooms = cryptic_room_manager:list_rooms({user, <<"bob">>}),
    CharlieRooms = cryptic_room_manager:list_rooms({user, <<"charlie">>}),
    
    ?assertEqual(3, length(AliceRooms)),  % alice owns room1,room3 + joined room2
    ?assertEqual(2, length(BobRooms)),    % bob owns room2 + joined room1
    ?assertEqual(2, length(CharlieRooms)), % charlie joined room1,room3
    
    % Test that deleting one room doesn't affect others
    % First, let Bob leave Room1 (non-owner leaving)
    ?assertEqual(ok, cryptic_room_manager:leave_room(Room1, <<"bob">>)),
    
    % Verify room1 still exists (alice is still owner)
    {ok, Room1Info} = cryptic_room_manager:get_room_info(Room1),
    ?assertNot(lists:member(<<"bob">>, Room1Info#room.members)),
    ?assert(lists:member(<<"alice">>, Room1Info#room.members)),
    
    % Now alice leaves (as owner, this will delete the room)
    ?assertEqual(ok, cryptic_room_manager:leave_room(Room1, <<"alice">>)),
    
    % Verify room1 is now deleted
    ?assertEqual({error, not_found}, cryptic_room_manager:get_room_info(Room1)),
    
    % Verify other rooms are unaffected
    {ok, _Room2Info} = cryptic_room_manager:get_room_info(Room2),
    {ok, _Room3Info} = cryptic_room_manager:get_room_info(Room3).

%%%===================================================================
%%% Helper Functions
%%%===================================================================
