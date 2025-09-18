%%% @doc Cryptic Room Manager
%%%
%%% This module handles chat room management for the Cryptic messaging system.
%%% It provides functionality for creating, joining, leaving, and managing chat rooms
%%% while integrating with the existing WebSocket mTLS infrastructure.
%%%
%%% == Features ==
%%%
%%% <ul>
%%%   <li>Room creation and deletion</li>
%%%   <li>User membership management (join/leave)</li>
%%%   <li>Public and private room support</li>
%%%   <li>Room listing and information retrieval</li>
%%%   <li>Message broadcasting to room members</li>
%%%   <li>Integration with existing authentication system</li>
%%% </ul>
%%%
%%% == Data Storage ==
%%%
%%% The module uses ETS tables for room data storage:
%%% <ul>
%%%   <li>`rooms' - Room definitions and metadata</li>
%%%   <li>`room_messages' - Message history per room</li>
%%%   <li>`user_rooms' - User membership lookup table</li>
%%% </ul>
%%%
%%% == Room Types ==
%%%
%%% <ul>
%%%   <li>`public' - Anyone can join</li>
%%%   <li>`private' - Password or invitation required</li>
%%% </ul>
%%%
%%% @since 1.0.0

-module(cryptic_room_manager).

-include("cryptic.hrl").

-export([
    create_room/4,
    delete_room/2,
    join_room/3,
    leave_room/2,
    list_rooms/1,
    get_room_info/1,
    get_room_members/1,
    send_room_message/3,
    get_room_messages/2,
    is_room_member/2,
    get_user_rooms/1,
    decrypt_message_for_user/3,
    encrypt_message_for_user/2,
    get_user_private_key/1,
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
]).

%% Room record definition
-record(room, {
    % Human-readable room name (now the primary key)
    name :: binary(),
    % Room description
    description :: binary(),
    % Room access type
    type :: public | private,
    % Room creator username
    owner :: binary(),
    % Creation timestamp (Unix time)
    created_at :: integer(),
    % List of member usernames
    members :: [binary()],
    % For private rooms (bcrypt hash)
    password_hash :: binary() | undefined
}).

%% Room message record definition (simplified - no room keys)
-record(room_message, {
    % Unique message ID (UUID)
    id :: binary(),
    % Target room ID
    room_id :: binary(),
    % Sender username
    from :: binary(),
    % Message timestamp (Unix time)
    timestamp :: integer(),
    % [{Username, Nonce, Ciphertext}]
    recipients :: [{binary(), binary(), binary()}]
}).

%%% Record accessor functions (to handle record access safely)

% For backward compatibility, return name as "id"
room_id(#room{name = Name}) -> Name.
room_name(#room{name = Name}) -> Name.
room_description(#room{description = Description}) -> Description.
room_type(#room{type = Type}) -> Type.
room_owner(#room{owner = Owner}) -> Owner.
room_created_at(#room{created_at = CreatedAt}) -> CreatedAt.
room_members(#room{members = Members}) -> Members.

room_message_id(#room_message{id = Id}) -> Id.
room_message_from(#room_message{from = From}) -> From.
room_message_timestamp(#room_message{timestamp = Timestamp}) -> Timestamp.
room_message_recipients(#room_message{recipients = Recipients}) -> Recipients.

%%% @doc Create a new chat room
%%%
%%% Creates a new room with the specified name, description, type, and owner.
%%% The room is stored in the `rooms' ETS table and the owner is automatically
%%% added as the first member.
%%%
%%% @param Name The human-readable room name
%%% @param Description Brief description of the room's purpose
%%% @param Type Room access type (`public' or `private')
%%% @param Owner Username of the room creator
%%% @returns `{ok, RoomId}' on success, `{error, Reason}' on failure
-spec create_room(binary(), binary(), public | private, binary()) ->
    {ok, binary()} | {error, term()}.
create_room(Name, Description, Type, Owner) ->
    Now = erlang:system_time(second),

    Room = #room{
        name = Name,
        description = Description,
        type = Type,
        owner = Owner,
        created_at = Now,
        members = [Owner],
        password_hash = undefined
    },

    try
        true = ets:insert(rooms, Room),
        true = ets:insert(user_rooms, {Owner, Name}),
        {ok, Name}
    catch
        error:Reason ->
            {error, Reason}
    end.

%%% @doc Delete an existing room
%%%
%%% Removes a room and all associated data. Only the room owner can delete a room.
%%% This also removes all user memberships and message history.
%%%
%%% @param RoomId The unique room identifier
%%% @param Username The username attempting to delete the room
%%% @returns `ok' on success, `{error, Reason}' on failure
-spec delete_room(binary(), binary()) -> ok | {error, term()}.
delete_room(RoomId, Username) ->
    case ets:lookup(rooms, RoomId) of
        [#room{owner = Username} = Room] ->
            % Remove all user memberships
            lists:foreach(
                fun(Member) ->
                    ets:delete_object(user_rooms, {Member, RoomId})
                end,
                Room#room.members
            ),

            % Remove room messages
            ets:delete(room_messages, RoomId),

            % Remove room itself
            ets:delete(rooms, RoomId),
            ok;
        [#room{}] ->
            {error, not_owner};
        [] ->
            {error, room_not_found}
    end.

%%% @doc Join a room
%%%
%%% Adds a user to an existing room if they have permission.
%%% For public rooms, anyone can join. For private rooms, password verification
%%% is required (not implemented in Phase 1).
%%%
%%% The function first attempts to find the room by ID. If no room is found,
%%% it will try to find a room with the matching name as a fallback.
%%%
%%% @param RoomIdOrName The unique room identifier (UUID) or room name
%%% @param Username The username attempting to join
%%% @param Password Optional password for private rooms (unused in Phase 1)
%%% @returns `ok' on success, `{error, Reason}' on failure
-spec join_room(binary(), binary(), binary() | undefined) ->
    ok | {error, term()}.
join_room(RoomIdOrName, Username, _Password) ->
    % First try to lookup by ID
    case ets:lookup(rooms, RoomIdOrName) of
        [Room] ->
            join_room_with_room(Room, Username);
        [] ->
            % If not found by ID, try to find by name
            case find_room_by_name(RoomIdOrName) of
                {ok, Room} ->
                    join_room_with_room(Room, Username);
                {error, not_found} ->
                    {error, room_not_found}
            end
    end.

%%% @doc Leave a room
%%%
%%% Removes a user from a room. If the room owner leaves, the room is deleted.
%%% The function first attempts to find the room by ID. If no room is found,
%%% it will try to find a room with the matching name as a fallback.
%%%
%%% @param RoomIdOrName The unique room identifier (UUID) or room name
%%% @param Username The username attempting to leave
%%% @returns `ok' on success, `{error, Reason}' on failure
-spec leave_room(binary(), binary()) -> ok | {error, term()}.
leave_room(RoomIdOrName, Username) ->
    % First try to lookup by ID
    case ets:lookup(rooms, RoomIdOrName) of
        [Room] ->
            leave_room_with_room(Room, Username);
        [] ->
            % If not found by ID, try to find by name
            case find_room_by_name(RoomIdOrName) of
                {ok, Room} ->
                    leave_room_with_room(Room, Username);
                {error, not_found} ->
                    {error, room_not_found}
            end
    end.

%%% @doc List rooms based on filter criteria
%%%
%%% Returns a list of rooms matching the specified filter.
%%%
%%% @param Filter Filter type: `all', `public', `private', or `{user, Username}'
%%% @returns List of room records
-spec list_rooms(all | public | private | {user, binary()}) -> [#room{}].
list_rooms(all) ->
    ets:tab2list(rooms);
list_rooms(public) ->
    ets:match_object(rooms, #room{type = public, _ = '_'});
list_rooms(private) ->
    ets:match_object(rooms, #room{type = private, _ = '_'});
list_rooms({user, Username}) ->
    RoomIds = ets:match(user_rooms, {Username, '$1'}),
    lists:filtermap(
        fun([RoomId]) ->
            case ets:lookup(rooms, RoomId) of
                [Room] -> {true, Room};
                [] -> false
            end
        end,
        RoomIds
    ).

%%% @doc Get detailed room information
%%%
%%% Returns complete information about a specific room.
%%% The function first attempts to find the room by ID. If no room is found,
%%% it will try to find a room with the matching name as a fallback.
%%%
%%% @param RoomIdOrName The unique room identifier (UUID) or room name
%%% @returns `{ok, Room}' if found, `{error, not_found}' otherwise
-spec get_room_info(binary()) -> {ok, #room{}} | {error, not_found}.
get_room_info(RoomIdOrName) ->
    % First try to lookup by ID
    case ets:lookup(rooms, RoomIdOrName) of
        [Room] ->
            {ok, Room};
        [] ->
            % If not found by ID, try to find by name
            case find_room_by_name(RoomIdOrName) of
                {ok, Room} -> {ok, Room};
                {error, not_found} -> {error, not_found}
            end
    end.

%%% @doc Get list of room members
%%%
%%% Returns the list of usernames for all members of a room.
%%% The function first attempts to find the room by ID. If no room is found,
%%% it will try to find a room with the matching name as a fallback.
%%%
%%% @param RoomIdOrName The unique room identifier (UUID) or room name
%%% @returns `{ok, Members}' if room exists, `{error, not_found}' otherwise
-spec get_room_members(binary()) -> {ok, [binary()]} | {error, not_found}.
get_room_members(RoomIdOrName) ->
    % First try to lookup by ID
    case ets:lookup(rooms, RoomIdOrName) of
        [#room{members = Members}] ->
            {ok, Members};
        [] ->
            % If not found by ID, try to find by name
            case find_room_by_name(RoomIdOrName) of
                {ok, #room{members = Members}} -> {ok, Members};
                {error, not_found} -> {error, not_found}
            end
    end.

%%% @doc Send a message to a room (Phase 1 simplified encryption)
%%%
%%% Encrypts the message individually for each room member using the existing
%%% 1-to-1 encryption pattern. The message is stored with encrypted copies
%%% for each recipient.
%%% The function first attempts to find the room by ID. If no room is found,
%%% it will try to find a room with the matching name as a fallback.
%%%
%%% @param RoomIdOrName The target room identifier (UUID) or room name
%%% @param FromUsername The sender's username
%%% @param PlaintextMessage The message content
%%% @returns `{ok, MessageId}' on success, `{error, Reason}' on failure
-spec send_room_message(binary(), binary(), binary()) ->
    {ok, binary()} | {error, term()}.
send_room_message(RoomNameOrId, FromUsername, PlaintextMessage) ->
    % First get the room record to ensure we have the actual room name
    case get_room_info(RoomNameOrId) of
        {ok, #room{name = RoomName, members = Members}} ->
            case lists:member(FromUsername, Members) of
                true ->
                    MessageId = generate_message_id(),
                    Now = erlang:system_time(second),

                    % Encrypt message for each recipient using existing crypto
                    Recipients = encrypt_for_room_members(
                        PlaintextMessage, Members, FromUsername
                    ),

                    Message = #room_message{
                        id = MessageId,
                        % Use room name as room_id
                        room_id = RoomName,
                        from = FromUsername,
                        timestamp = Now,
                        recipients = Recipients
                    },

                    true = ets:insert(room_messages, Message),
                    {ok, MessageId};
                false ->
                    {error, not_member}
            end;
        {error, not_found} ->
            {error, room_not_found}
    end.

%%% @doc Get room message history
%%%
%%% Returns messages for a room since a specified timestamp.
%%% The function first attempts to find the room by ID. If no room is found,
%%% it will try to find a room with the matching name as a fallback.
%%%
%%% @param RoomIdOrName The room identifier (UUID) or room name
%%% @param Since Unix timestamp to filter messages from
%%% @returns List of room messages
-spec get_room_messages(binary(), integer()) -> [#room_message{}].
get_room_messages(RoomNameOrId, Since) ->
    % First try to get the actual room name
    case get_room_info(RoomNameOrId) of
        {ok, #room{name = RoomName}} ->
            AllMessages = ets:lookup(room_messages, RoomName),
            [Msg || Msg <- AllMessages, Msg#room_message.timestamp >= Since];
        {error, not_found} ->
            % Room not found, return empty list
            []
    end.

%%% @doc Check if a user is a member of a room
%%%
%%% The function first attempts to find the room by ID. If no room is found,
%%% it will try to find a room with the matching name as a fallback.
%%%
%%% @param Username The username to check
%%% @param RoomIdOrName The room identifier (UUID) or room name
%%% @returns `true' if user is a member, `false' otherwise
-spec is_room_member(binary(), binary()) -> boolean().
is_room_member(Username, RoomId) when
    is_binary(Username) andalso is_binary(RoomId)
->
    % First try to get the actual room name
    case cryptic_room_manager:get_room_members(RoomId) of
        {ok, Members} ->
            lists:member(Username, Members);
        _ ->
            false
    end.

%%% @doc Get all rooms a user belongs to
%%%
%%% @param Username The username to lookup
%%% @returns List of room IDs the user is a member of
-spec get_user_rooms(binary()) -> [binary()].
get_user_rooms(Username) ->
    [RoomId || {_, RoomId} <- ets:lookup(user_rooms, Username)].

%% Encrypt message for room members (Phase 1 simplified approach)
%% This encrypts each message individually per recipient using existing crypto pattern
-spec encrypt_for_room_members(binary(), [binary()], binary()) ->
    [{binary(), binary(), binary()}].
encrypt_for_room_members(PlaintextMessage, Members, FromUsername) ->
    % Filter out sender (don't encrypt for self)
    Recipients = lists:delete(FromUsername, Members),

    lists:filtermap(
        fun(Username) ->
            case
                encrypt_message_for_user(
                    PlaintextMessage, Username
                )
            of
                {ok, EphPub, EncryptedData} ->
                    {true, {Username, EphPub, EncryptedData}};
                {error, _Reason} ->
                    % Skip this recipient if encryption fails (e.g., no prekey)
                    false
            end
        end,
        Recipients
    ).

%% Encrypt a message for a specific user using their prekey
%% Uses the same encryption scheme as cryptic_client_lib for compatibility
-spec encrypt_message_for_user(binary(), binary()) ->
    {ok, binary(), binary()} | {error, term()}.
encrypt_message_for_user(PlaintextMessage, Username) ->
    % Convert binary username to string for cryptic_lib compatibility
    UsernameStr = binary_to_list(Username),
    case cryptic_lib:get_prekey(UsernameStr) of
        {ok, RecipientPublicKey} ->
            try
                % Use the same encryption scheme as cryptic_client_lib:encrypt_message
                % Generate ephemeral keypair
                {EphPub, EphPriv} = cryptic_lib:gen_keypair(),

                % Compute shared secret
                Shared = cryptic_lib:scalarmult(EphPriv, RecipientPublicKey),

                % Derive AEAD key using ephemeral-based salt
                AeadKey = cryptic_lib:derive_aead_key_ephemeral(Shared, EphPub),

                % Encrypt message
                {Cipher, Nonce} = cryptic_lib:aead_encrypt(
                    PlaintextMessage, AeadKey, <<>>
                ),

                ?dbg(
                    "SERVER ENCRYPT: Message=~p, Nonce=~p bytes, Cipher=~p bytes",
                    [PlaintextMessage, byte_size(Nonce), byte_size(Cipher)]
                ),

                % Format as nonce + cipher (same as regular encrypted messages)
                EncryptedData = <<Nonce/binary, Cipher/binary>>,

                ?dbg("SERVER ENCRYPT: EncryptedData=~p bytes", [
                    byte_size(EncryptedData)
                ]),

                {ok, EphPub, EncryptedData}
            catch
                error:Reason ->
                    {error, {encryption_failed, Reason}}
            end;
        {error, not_found} ->
            {error, user_not_found}
    end.

%%% @doc Decrypt a room message for a specific user (using client-side decryption)
%%%
%%% This function is primarily for testing/debugging purposes.
%%% In normal operation, the client handles decryption using the same
%%% cryptic_lib functions for consistency.
%%%
%%% @param EncryptedData The encrypted message (nonce + ciphertext)
%%% @param EphemeralPublicKey The ephemeral public key used for encryption
%%% @param Username The username of the recipient
%%% @returns `{ok, Plaintext}' on successful decryption, `{error, Reason}' on failure
-spec decrypt_message_for_user(binary(), binary(), string()) ->
    {ok, binary()} | {error, term()}.
decrypt_message_for_user(EncryptedData, EphemeralPublicKey, Username) ->
    case cryptic_lib:get_prekey(Username) of
        {ok, _RecipientPublicKey} ->
            try
                % Get recipient's private key for decryption
                case cryptic_lib:get_private_key(Username) of
                    {ok, RecipientPrivateKey} ->
                        % Compute shared secret
                        Shared = cryptic_lib:scalarmult(
                            RecipientPrivateKey, EphemeralPublicKey
                        ),

                        % Derive AEAD key using ephemeral-based salt
                        AeadKey = cryptic_lib:derive_aead_key_ephemeral(
                            Shared, EphemeralPublicKey
                        ),

                        % Decrypt message (EncryptedData format: nonce + cipher)
                        case
                            cryptic_lib:aead_decrypt(
                                EncryptedData, AeadKey, <<>>
                            )
                        of
                            {ok, Plaintext} ->
                                {ok, Plaintext};
                            {error, DecryptError} ->
                                {error, {decryption_failed, DecryptError}}
                        end;
                    {error, KeyError} ->
                        {error, {private_key_not_found, KeyError}}
                end
            catch
                error:CatchReason ->
                    {error, {decryption_failed, CatchReason}}
            end;
        {error, PrekeyError} ->
            {error, PrekeyError}
    end.

%% Get user's private key (placeholder implementation)
-spec get_user_private_key(string()) -> {ok, binary()} | {error, term()}.
get_user_private_key(Username) ->
    case cryptic_lib:get_prekey(Username) of
        {ok, Prekey} -> {ok, Prekey};
        {error, Reason} -> {error, Reason}
    end.

%%% Internal Functions

%% Helper function to complete joining a room with the found room record
-spec join_room_with_room(#room{}, binary()) -> ok | {error, term()}.
join_room_with_room(#room{name = RoomName, members = Members} = Room, Username) ->
    case lists:member(Username, Members) of
        true ->
            {error, already_member};
        false ->
            % Add user to room
            UpdatedMembers = [Username | Members],
            UpdatedRoom = Room#room{members = UpdatedMembers},

            true = ets:insert(rooms, UpdatedRoom),
            true = ets:insert(user_rooms, {Username, RoomName}),
            ok
    end.

%% Helper function to complete leaving a room with the found room record
-spec leave_room_with_room(#room{}, binary()) -> ok | {error, term()}.
leave_room_with_room(
    #room{name = RoomName, owner = Owner, members = Members} = Room, Username
) ->
    case Owner of
        Username ->
            % Room owner leaving - delete the room
            delete_room(RoomName, Username);
        _ ->
            case lists:member(Username, Members) of
                true ->
                    % Remove user from room
                    UpdatedMembers = lists:delete(Username, Members),
                    UpdatedRoom = Room#room{members = UpdatedMembers},

                    true = ets:insert(rooms, UpdatedRoom),
                    true = ets:delete_object(user_rooms, {Username, RoomName}),
                    ok;
                false ->
                    {error, not_member}
            end
    end.

%% Helper function to find a room by name
-spec find_room_by_name(binary()) -> {ok, #room{}} | {error, not_found}.
find_room_by_name(RoomName) ->
    case ets:match_object(rooms, #room{name = RoomName, _ = '_'}) of
        [Room] -> {ok, Room};
        [] -> {error, not_found};
        % If multiple rooms with same name, return first
        [Room | _] -> {ok, Room}
    end.

%% Generate a unique message ID
-spec generate_message_id() -> binary().
generate_message_id() ->
    UUID = uuid:get_v4(),
    uuid:uuid_to_string(UUID, binary_standard).
