%%% @doc Cryptic Room WebSocket Handlers
%%%
%%% This module handles WebSocket commands related to chat room functionality.
%%% It integrates with the existing cryptic_ws_handler to provide room management
%%% and messaging capabilities via the WebSocket interface.
%%%
%%% == Supported Commands ==
%%%
%%% <ul>
%%%   <li>`create_room' - Create a new chat room</li>
%%%   <li>`join_room' - Join an existing room</li>
%%%   <li>`leave_room' - Leave a room</li>
%%%   <li>`list_rooms' - Get list of available rooms</li>
%%%   <li>`send_room_message' - Send message to room</li>
%%%   <li>`get_room_messages' - Retrieve room message history</li>
%%%   <li>`get_room_members' - Get list of room members</li>
%%% </ul>
%%%
%%% == Message Format ==
%%%
%%% All WebSocket messages follow JSON format with a `type' field indicating
%%% the command and additional fields for parameters.
%%%
%%% @since 1.0.0

-module(cryptic_room_handlers).

-export([
    handle_room_command/3
]).

-import(
    cryptic_room_manager,
    [
        room_id/1,
        room_name/1,
        room_description/1,
        room_type/1,
        room_owner/1,
        room_created_at/1,
        room_members/1,
        room_message_id/1,
        room_message_from/1,
        room_message_timestamp/1,
        room_message_recipients/1
    ]
).

-include("cryptic.hrl").

%%% @doc Handle room-related WebSocket commands
%%%
%%% Processes room management commands received via WebSocket and returns
%%% appropriate responses. This function is called from the main WebSocket
%%% handler when a room-related command is received.
%%%
%%% @param Command The command type (atom)
%%% @param Params Command parameters (map)
%%% @param Username Authenticated username from certificate
%%% @returns JSON response to send back to client
-spec handle_room_command(atom(), map(), binary()) -> map().

%% Create a new room
handle_room_command(create_room, Params, Username) ->
    Name = maps:get(<<"name">>, Params, <<"Unnamed Room">>),
    Description = maps:get(<<"description">>, Params, <<"">>),
    TypeBin = maps:get(<<"room_type">>, Params, <<"public">>),

    Type =
        case TypeBin of
            <<"public">> -> public;
            <<"private">> -> private;
            _ -> public
        end,

    case cryptic_room_manager:create_room(Name, Description, Type, Username) of
        {ok, RoomId} ->
            ?info("User ~s created room ~s (~s)", [Username, Name, RoomId]),
            #{
                type => <<"room_created">>,
                success => true,
                room_id => RoomId,
                name => Name,
                description => Description,
                room_type => TypeBin
            };
        {error, Reason} ->
            ?warning("Failed to create room ~s for user ~s: ~p", [
                Name, Username, Reason
            ]),
            #{
                type => <<"error">>,
                success => false,
                message => iolist_to_binary(
                    io_lib:format("Failed to create room: ~p", [Reason])
                )
            }
    end;
%% Join an existing room
handle_room_command(join_room, Params, Username) ->
    RoomId = maps:get(<<"room_id">>, Params),
    ?dbg("DEBUG ROOM HANDLER: User ~s joining room ~s~n", [Username, RoomId]),
    Password = maps:get(<<"password">>, Params, undefined),

    case cryptic_room_manager:join_room(RoomId, Username, Password) of
        ok ->
            ?info("User ~s joined room ~s", [Username, RoomId]),

            % Get room info to return to client
            {ok, Room} = cryptic_room_manager:get_room_info(RoomId),
            #{
                type => <<"room_joined">>,
                success => true,
                room_id => RoomId,
                room_name => room_name(Room),
                members => room_members(Room)
            };
        {error, Reason} ->
            ?warning("User ~s failed to join room ~s: ~p", [
                Username, RoomId, Reason
            ]),
            #{
                type => <<"error">>,
                success => false,
                message => format_error_message(Reason)
            }
    end;
%% Leave a room
handle_room_command(leave_room, Params, Username) ->
    RoomId = maps:get(<<"room_id">>, Params),

    case cryptic_room_manager:leave_room(RoomId, Username) of
        ok ->
            ?info("User ~s left room ~s", [Username, RoomId]),
            #{
                type => <<"room_left">>,
                success => true,
                room_id => RoomId
            };
        {error, Reason} ->
            ?warning("User ~s failed to leave room ~s: ~p", [
                Username, RoomId, Reason
            ]),
            #{
                type => <<"error">>,
                success => false,
                message => format_error_message(Reason)
            }
    end;
%% List available rooms
handle_room_command(list_rooms, Params, Username) ->
    FilterBin = maps:get(<<"filter">>, Params, <<"public">>),

    Filter =
        case FilterBin of
            <<"all">> -> all;
            <<"public">> -> public;
            <<"private">> -> private;
            <<"joined">> -> {user, Username}
        end,

    Rooms = cryptic_room_manager:list_rooms(Filter),
    RoomList = lists:map(fun format_room_summary/1, Rooms),

    ?dbg("User ~s listed ~b rooms with filter ~s", [
        Username, length(Rooms), FilterBin
    ]),
    #{
        type => <<"rooms_list">>,
        success => true,
        filter => FilterBin,
        rooms => RoomList
    };
%% Send message to room
handle_room_command(send_room_message, Params, Username) ->
    RoomId = maps:get(<<"room_id">>, Params),
    Message = maps:get(<<"message">>, Params),

    case cryptic_room_manager:send_room_message(RoomId, Username, Message) of
        {ok, MessageId} ->
            ?dbg("User ~s sent message to room ~s", [Username, RoomId]),

            % Get room members to broadcast message
            {ok, Members} = cryptic_room_manager:get_room_members(RoomId),
            broadcast_room_message(
                RoomId, Username, Message, MessageId, Members
            ),

            Response = #{
                type => <<"room_message_sent">>,
                success => true,
                room_id => RoomId,
                message_id => MessageId
            },
            io:format("DEBUG ROOM HANDLER: Sending response: ~p~n", [Response]),
            Response;
        {error, Reason} ->
            ?warning("User ~s failed to send message to room ~s: ~p", [
                Username, RoomId, Reason
            ]),
            #{
                type => <<"error">>,
                success => false,
                message => format_error_message(Reason)
            }
    end;
%% Get room message history
handle_room_command(get_room_messages, Params, Username) ->
    RoomId = maps:get(<<"room_id">>, Params),
    Since = maps:get(<<"since">>, Params, 0),

    % Check if user is member of the room
    case cryptic_room_manager:is_room_member(Username, RoomId) of
        true ->
            Messages = cryptic_room_manager:get_room_messages(RoomId, Since),
            MessageList = lists:map(
                fun(Msg) -> format_room_message(Msg, Username) end, Messages
            ),

            #{
                type => <<"room_messages">>,
                success => true,
                room_id => RoomId,
                messages => MessageList
            };
        false ->
            #{
                type => <<"error">>,
                success => false,
                message => <<"Not a member of this room">>
            }
    end;
%% Get room members
handle_room_command(get_room_members, Params, Username) ->
    RoomId = maps:get(<<"room_id">>, Params),

    case cryptic_room_manager:is_room_member(Username, RoomId) of
        true ->
            {ok, Members} = cryptic_room_manager:get_room_members(RoomId),
            {ok, Room} = cryptic_room_manager:get_room_info(RoomId),

            #{
                type => <<"room_members">>,
                success => true,
                room_id => RoomId,
                room_name => room_name(Room),
                members => Members
            };
        false ->
            #{
                type => <<"error">>,
                success => false,
                message => <<"Not a member of this room">>
            }
    end;
%% Unknown command
handle_room_command(Command, _Params, Username) ->
    ?warning("User ~s sent unknown room command: ~p", [Username, Command]),
    #{
        type => <<"error">>,
        success => false,
        message => <<"Unknown room command">>
    }.

%%% Internal Helper Functions

%% Format room summary for listing
format_room_summary(Room) ->
    #{
        id => room_id(Room),
        name => room_name(Room),
        description => room_description(Room),
        type => room_type_binary(Room),
        owner => room_owner(Room),
        member_count => length(room_members(Room)),
        created_at => room_created_at(Room)
    }.

%% Format room message for client
format_room_message(Message, RequestingUser) ->
    % Find the encrypted message for this user
    Recipients = room_message_recipients(Message),
    DecryptedMessage =
        case lists:keyfind(RequestingUser, 1, Recipients) of
            {RequestingUser, EphemeralPublic, Ciphertext} ->
                % Decrypt the message for this user
                case
                    cryptic_room_manager:decrypt_message_for_user(
                        Ciphertext,
                        EphemeralPublic,
                        binary_to_list(RequestingUser)
                    )
                of
                    {ok, Plaintext} -> Plaintext;
                    {error, _Reason} -> <<"[Failed to decrypt message]">>
                end;
            false ->
                <<"[Message not available]">>
        end,

    #{
        id => room_message_id(Message),
        from => room_message_from(Message),
        timestamp => room_message_timestamp(Message),
        message => DecryptedMessage
    }.

%% Broadcast message to all room members
broadcast_room_message(
    RoomId, FromUsername, _PlaintextMessage, MessageId, Members
) ->
    ?dbg("DEBUG BROADCAST: RoomId=~p, MessageId=~p, Members=~p~n", [
        RoomId, MessageId, Members
    ]),

    % Get room information for room name
    {ok, Room} = cryptic_room_manager:get_room_info(RoomId),
    RoomName = room_name(Room),

    % Retrieve the stored room message with encrypted recipients
    % Since room_messages ETS table is keyed by 'from' field (position 3),
    % we need to find messages by room_id field (position 2) using match
    % Pattern: {room_message, ID, RoomId, From, Timestamp, Recipients}
    Pattern = {'_', '_', RoomId, '_', '_', '_'},
    case ets:match_object(room_messages, Pattern) of
        Messages when Messages =/= [] ->
            ?dbg("DEBUG BROADCAST: Found ~p messages for room ~p~n", [
                length(Messages), RoomId
            ]),
            % Find the specific message by ID using the accessor function
            case
                lists:filter(
                    fun(M) -> room_message_id(M) =:= MessageId end, Messages
                )
            of
                [RoomMessage] ->
                    ?dbg("DEBUG BROADCAST: Found specific message ~p~n", [
                        MessageId
                    ]),
                    % Get the encrypted recipients data
                    Recipients = room_message_recipients(RoomMessage),

                    % Get all connected users who are room members
                    ConnectedMembers = lists:filter(
                        fun(Member) ->
                            case ets:lookup(user_connections, Member) of
                                [{Member, _Pid}] -> true;
                                [] -> false
                            end
                        end,
                        Members
                    ),
                    ?dbg("DEBUG BROADCAST: Connected members: ~p~n", [
                        ConnectedMembers
                    ]),
                    % Send individually encrypted message to each connected member
                    lists:foreach(
                        fun(Member) ->
                            send_room_notification_to_member(
                                Member,
                                FromUsername,
                                RoomId,
                                RoomName,
                                MessageId,
                                RoomMessage,
                                Recipients
                            )
                        end,
                        ConnectedMembers
                    );
                [] ->
                    ?error("Could not find room message ~s in room ~s", [
                        MessageId, RoomId
                    ]);
                _ ->
                    ?error(
                        "Multiple messages found with ID ~s in room ~s", [
                            MessageId, RoomId
                        ]
                    )
            end;
        [] ->
            io:format("DEBUG BROADCAST: No messages found for room ~p~n", [
                RoomId
            ]),
            ?error("No messages found for room ~s", [RoomId])
    end.

%% Find encrypted message data for a specific user from recipients list
find_encrypted_message_for_user(Recipients, Username) ->
    case lists:keyfind(Username, 1, Recipients) of
        {Username, EphemeralKey, EncryptedData} ->
            {ok, EphemeralKey, EncryptedData};
        false ->
            {error, not_found}
    end.

%% Send room message notification to a specific member
send_room_notification_to_member(
    Member, FromUsername, RoomId, RoomName, MessageId, RoomMessage, Recipients
) ->
    % Don't send to sender
    if
        Member =/= FromUsername ->
            case find_encrypted_message_for_user(Recipients, Member) of
                {ok, EphemeralKey, EncryptedData} ->
                    ?dbg("DEBUG SENDING: Found encrypted message for ~s", [
                        Member
                    ]),
                    case ets:lookup(user_connections, Member) of
                        [{Member, Pid}] ->
                            Notification = #{
                                type => <<"room_message">>,
                                room_id => RoomId,
                                room_name => RoomName,
                                from => iolist_to_binary(FromUsername),
                                message_id => MessageId,
                                timestamp => room_message_timestamp(
                                    RoomMessage
                                ),
                                ephemeral => base64:encode(EphemeralKey),
                                encrypted_data => base64:encode(EncryptedData)
                            },
                            ?dbg("DEBUG SENDING to ~s: ~p", [
                                Member, Notification
                            ]),
                            % Send as room_notification instead of send_json
                            Pid ! {room_notification, Notification};
                        [] ->
                            ok
                    end;
                {error, not_found} ->
                    ?warning(
                        "No encrypted message found for user ~s in room message ~s",
                        [Member, MessageId]
                    )
            end;
        true ->
            ok
    end.

%% Format error messages for client consumption
format_error_message(room_not_found) ->
    <<"Room not found">>;
format_error_message(already_member) ->
    <<"Already a member of this room">>;
format_error_message(not_member) ->
    <<"Not a member of this room">>;
format_error_message(not_owner) ->
    <<"Only room owner can perform this action">>;
format_error_message(Reason) ->
    iolist_to_binary(io_lib:format("Error: ~p", [Reason])).

room_type_binary(Room) ->
    case room_type(Room) of
        public -> <<"public">>;
        private -> <<"private">>
    end.
