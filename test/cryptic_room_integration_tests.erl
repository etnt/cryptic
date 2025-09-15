-module(cryptic_room_integration_tests).
-include_lib("eunit/include/eunit.hrl").

%% Room records
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

%% Test the complete room messaging flow including WebSocket command parsing
-export([]).

% Test setup and cleanup
setup() ->
    % Start necessary applications
    application:start(crypto),
    
    % Start event manager for room handlers
    {ok, _} = gen_event:start_link({local, cryptic_event_manager}),
    gen_event:add_handler(cryptic_event_manager, cryptic_console_logger, []),
    
    % Initialize ETS tables as they would be in the actual server
    ets:new(rooms, [named_table, set, public, {keypos, 2}]),
    ets:new(room_messages, [named_table, bag, public, {keypos, 3}]),  % Match server config
    ets:new(user_rooms, [named_table, bag, public]),  % No keypos like server
    ets:new(users, [named_table, set, public]),
    ets:new(connections, [named_table, set, public]),
    ets:new(user_connections, [named_table, set, public]),  % Add missing table
    % Add test users with prekeys for encryption
    TestUser1 = <<"alice">>,
    TestUser2 = <<"bob">>,
    Prekey1 = crypto:strong_rand_bytes(32),
    Prekey2 = crypto:strong_rand_bytes(32),
    ets:insert(users, {TestUser1, #{prekey => Prekey1}}),
    ets:insert(users, {TestUser2, #{prekey => Prekey2}}),
    {TestUser1, TestUser2, Prekey1, Prekey2}.

cleanup(_) ->
    % Clean up ETS tables
    catch ets:delete(rooms),
    catch ets:delete(room_messages),
    catch ets:delete(user_rooms),
    catch ets:delete(users),
    catch ets:delete(connections),
    catch ets:delete(user_connections),
    
    % Stop event manager
    catch gen_event:stop(cryptic_event_manager),
    ok.

%% Integration test: Complete room workflow with WebSocket command handling
complete_room_workflow_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({TestUser1, TestUser2, _Prekey1, _Prekey2}) ->
         [
             % Test 1: Create room through WebSocket command
             ?_test(begin
                 CreateCommand = #{
                     <<"type">> => <<"create_room">>,
                     <<"name">> => <<"test_room">>,
                     <<"room_type">> => <<"public">>
                 },
                 Response1 = cryptic_room_handlers:handle_room_command(create_room, CreateCommand, TestUser1),
                 ?assertMatch(#{success := true, room_id := _}, Response1),
                 #{room_id := RoomId} = Response1,
                 
                 % Verify room was created
                 [Room] = ets:lookup(rooms, RoomId),
                 ?assertEqual(<<"test_room">>, Room#room.name),
                 ?assertEqual(TestUser1, Room#room.owner),
                 ?assertEqual(public, Room#room.type)
             end),
             
             % Test 2: Join room and send messages
             ?_test(begin
                 % First create a room
                 CreateCommand = #{
                     <<"type">> => <<"create_room">>,
                     <<"name">> => <<"chat_room">>,
                     <<"room_type">> => <<"public">>
                 },
                 CreateResponse = cryptic_room_handlers:handle_room_command(create_room, CreateCommand, TestUser1),
                 #{room_id := RoomId} = CreateResponse,
                 
                 % User2 joins the room
                 JoinCommand = #{
                     <<"type">> => <<"join_room">>,
                     <<"room_id">> => RoomId
                 },
                 JoinResponse = cryptic_room_handlers:handle_room_command(join_room, JoinCommand, TestUser2),
                 ?assertMatch(#{success := true}, JoinResponse),
                 
                 % User1 sends a message
                 MessageCommand = #{
                     <<"type">> => <<"send_room_message">>,
                     <<"room_id">> => RoomId,
                     <<"message">> => <<"Hello room!">>
                 },
                 MessageResponse = cryptic_room_handlers:handle_room_command(send_room_message, MessageCommand, TestUser1),
                 ?assertMatch(#{success := true, message_id := _}, MessageResponse),
                 
                 % Verify message was stored
                 Messages = ets:lookup(room_messages, RoomId),
                 ?assertEqual(1, length(Messages)),
                 
                 [Message] = Messages,
                 ?assertEqual(TestUser1, Message#room_message.from),
                 ?assertEqual(RoomId, Message#room_message.room_id)
             end),
             
             % Test 3: List rooms functionality
             ?_test(begin
                 % Create a couple of rooms
                 CreateCommand1 = #{
                     <<"type">> => <<"create_room">>,
                     <<"name">> => <<"public_room">>,
                     <<"room_type">> => <<"public">>
                 },
                 CreateCommand2 = #{
                     <<"type">> => <<"create_room">>,
                     <<"name">> => <<"private_room">>,
                     <<"room_type">> => <<"private">>
                 },
                 cryptic_room_handlers:handle_room_command(create_room, CreateCommand1, TestUser1),
                 cryptic_room_handlers:handle_room_command(create_room, CreateCommand2, TestUser1),
                 
                 % List rooms
                 ListCommand = #{<<"type">> => <<"list_rooms">>},
                 ListResponse = cryptic_room_handlers:handle_room_command(list_rooms, ListCommand, TestUser1),
                 
                 ?assertMatch(#{success := true, rooms := _}, ListResponse),
                 #{rooms := Rooms} = ListResponse,
                 ?assert(length(Rooms) >= 2)  % May have rooms from other tests
             end),
             
             % Test 4: Leave room functionality
             ?_test(begin
                 % Clear any existing test data
                 ets:delete_all_objects(rooms),
                 ets:delete_all_objects(room_messages),
                 ets:delete_all_objects(user_rooms),
                 
                 % Create room and join
                 CreateCommand = #{
                     <<"type">> => <<"create_room">>,
                     <<"name">> => <<"leave_test">>,
                     <<"room_type">> => <<"public">>
                 },
                 CreateResponse = cryptic_room_handlers:handle_room_command(create_room, CreateCommand, TestUser1),
                 #{room_id := RoomId} = CreateResponse,
                 
                 % User2 joins the room
                 JoinCommand = #{
                     <<"type">> => <<"join_room">>,
                     <<"room_id">> => RoomId
                 },
                 JoinResponse = cryptic_room_handlers:handle_room_command(join_room, JoinCommand, TestUser2),
                 ?assertMatch(#{success := true}, JoinResponse),
                 
                 % Verify user2 is in the room (should be in user_rooms table)
                 UserRooms1 = ets:lookup(user_rooms, TestUser2),
                 ?assertEqual(1, length(UserRooms1)),
                 
                 % User2 leaves the room
                 LeaveCommand = #{
                     <<"type">> => <<"leave_room">>,
                     <<"room_id">> => RoomId
                 },
                 LeaveResponse = cryptic_room_handlers:handle_room_command(leave_room, LeaveCommand, TestUser2),
                 ?assertMatch(#{success := true}, LeaveResponse),
                 
                 % Verify user2 is no longer in the room
                 UserRooms2 = ets:lookup(user_rooms, TestUser2),
                 ?assertEqual(0, length(UserRooms2))
             end)
         ]
     end}.

%% Test error handling in WebSocket commands
error_handling_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun({TestUser1, _TestUser2, _Prekey1, _Prekey2}) ->
         [
             % Test invalid room join
             ?_test(begin
                 JoinCommand = #{
                     <<"type">> => <<"join_room">>,
                     <<"room_id">> => <<"nonexistent_room">>
                 },
                 Response = cryptic_room_handlers:handle_room_command(join_room, JoinCommand, TestUser1),
                 ?assertMatch(#{success := false, message := _}, Response)
             end),
             
             % Test sending message to nonexistent room
             ?_test(begin
                 MessageCommand = #{
                     <<"type">> => <<"send_room_message">>,
                     <<"room_id">> => <<"nonexistent_room">>,
                     <<"message">> => <<"Hello!">>
                 },
                 Response = cryptic_room_handlers:handle_room_command(send_room_message, MessageCommand, TestUser1),
                 ?assertMatch(#{success := false, message := _}, Response)
             end)
         ]
     end}.
