%%% @doc Cryptic WebSocket Message Construction Module
%%%
%%% This module provides a centralized interface for constructing and validating
%%% all WebSocket messages exchanged between the Cryptic client and server. It
%%% standardizes message formats and provides type safety for message construction.
%%%
%%% == Message Format Reference ==
%%%
%%% All messages are JSON objects with a mandatory `type' field. Base64 encoding
%%% is used for all binary data (keys, signatures, ciphertext, etc.).
%%%
%%% === Client to Server Messages ===
%%%
%%% Authentication and Key Management:
%%%
%%% Upload identity keys (Step 4 of auth flow):
%%% <pre>
%%% {
%%%   "type": "upload_identity_keys",
%%%   "identity_sign_public": "base64-ed25519-public-key",
%%%   "identity_dh_public": "base64-x25519-public-key",
%%%   "signed_prekey_public": "base64-signed-prekey",
%%%   "signed_prekey_signature": "base64-signature"
%%% }
%%% </pre>
%%%
%%% Upload prekey bundle (Step 5 of auth flow):
%%% <pre>
%%% {
%%%   "type": "upload_prekey_bundle",
%%%   "one_time_prekeys": [
%%%     {
%%%       "id": "base64-key-id",
%%%       "public_key": "base64-public-key"
%%%     }
%%%   ]
%%% }
%%% </pre>
%%%
%%% Request user's key bundle for X3DH:
%%% <pre>
%%% {
%%%   "type": "get_key_bundle",
%%%   "user": "username"
%%% }
%%% </pre>
%%%
%%% Request current user's key status:
%%% <pre>
%%% {
%%%   "type": "key_status"
%%% }
%%% </pre>
%%%
%%% Encrypted Messaging:
%%%
%%% Send generic encrypted message:
%%% <pre>
%%% {
%%%   "type": "send_encrypted",
%%%   "to": "username",
%%%   "message": {}
%%% }
%%% </pre>
%%%
%%% Send X3DH encrypted message (session initiation):
%%% <pre>
%%% {
%%%   "type": "x3dh",
%%%   "from": "sender_username",
%%%   "to": "username",
%%%   "message_id": "base64-message-id",
%%%   "ephemeral_public": "base64-ephemeral-key",
%%%   "otpk_id": "base64-otpk-id",
%%%   "ciphertext": "base64-encrypted-data",
%%%   "nonce": "base64-nonce",
%%%   "signature": "base64-signature",
%%%   "metadata": "base64-metadata"
%%% }
%%% </pre>
%%%
%%% Send Double Ratchet encrypted message (ongoing communication):
%%% <pre>
%%% {
%%%   "type": "ratchet",
%%%   "from": "sender_username",
%%%   "to": "username",
%%%   "message_id": "base64-message-id",
%%%   "dh_public": "base64-dh-public-key",
%%%   "dh_step": 1,
%%%   "prev_chain_length": 2,
%%%   "msg_number": 3,
%%%   "ciphertext": "base64-encrypted-data",
%%%   "nonce": "base64-nonce"
%%% }
%%% </pre>
%%%
%%% User and Message Management:
%%%
%%% List all users:
%%% <pre>
%%% {
%%%   "type": "list_users"
%%% }
%%% </pre>
%%%
%%% Get stored messages:
%%% <pre>
%%% {
%%%   "type": "get_messages"
%%% }
%%% </pre>
%%%
%%% === Server to Client Messages ===
%%%
%%% General Responses:
%%%
%%% Welcome message on connection:
%%% <pre>
%%% {
%%%   "type": "welcome",
%%%   "message": "welcome-text"
%%% }
%%% </pre>
%%%
%%% Success response:
%%% <pre>
%%% {
%%%   "type": "success",
%%%   "message": "success-message"
%%% }
%%% </pre>
%%%
%%% Error response:
%%% <pre>
%%% {
%%%   "type": "error",
%%%   "message": "error-message"
%%% }
%%% </pre>
%%%
%%% Key Management Responses:
%%%
%%% Key status response:
%%% <pre>
%%% {
%%%   "type": "key_status",
%%%   "status": {},
%%%   "error": "error-message"
%%% }
%%% </pre>
%%%
%%% Key bundle response:
%%% <pre>
%%% {
%%%   "type": "key_bundle",
%%%   "user": "username",
%%%   "key_id": "base64-key-id",
%%%   "identity_sign_public": "base64-ed25519-key",
%%%   "identity_dh_public": "base64-x25519-key",
%%%   "signed_prekey": "base64-signed-prekey",
%%%   "signed_prekey_signature": "base64-signature",
%%%   "one_time_prekey": {
%%%     "id": "base64-otpk-id",
%%%     "public_key": "base64-otpk"
%%%   },
%%%   "remaining_otpks": 42
%%% }
%%% </pre>
%%%
%%% User and Message Responses:
%%%
%%% User status response:
%%% <pre>
%%% {
%%%   "type": "user_status",
%%%   "user": "username",
%%%   "status": "online",
%%%   "message": "status-description"
%%% }
%%% </pre>
%%%
%%% Users list response:
%%% <pre>
%%% {
%%%   "type": "users",
%%%   "users": ["username1", "username2"]
%%% }
%%% </pre>
%%%
%%% Messages response:
%%% <pre>
%%% {
%%%   "type": "messages",
%%%   "messages": []
%%% }
%%% </pre>
%%%
%%% Incoming encrypted message notification:
%%% <pre>
%%% {
%%%   "type": "encrypted_message_received",
%%%   "from": "sender-username",
%%%   "message": {},
%%%   "server_timestamp": 1633610400
%%% }
%%% </pre>
%%%
%%% Message sent confirmation:
%%% <pre>
%%% {
%%%   "type": "message_sent",
%%%   "success": true,
%%%   "to": "recipient",
%%%   "timestamp": 1633610400,
%%%   "message": "confirmation-text"
%%% }
%%% </pre>
%%%
%%% == Message Categories ==
%%%
%%% <ul>
%%%   <li>**Authentication Messages**: Identity key and prekey bundle uploads</li>
%%%   <li>**Key Exchange Messages**: Key bundle requests and responses</li>
%%%   <li>**Encrypted Messaging**: X3DH and Double Ratchet protocol messages</li>
%%%   <li>**User Management**: User listing and status queries</li>
%%%   <li>**Message Management**: Message retrieval and delivery</li>
%%%   <li>**Response Messages**: Success, error, and status responses</li>
%%% </ul>
%%%
%%% == Usage Pattern ==
%%%
%%% All message construction functions follow the pattern:
%%%
%%% <pre>
%%% {ok, Message} = cryptic_messages:upload_identity_keys(#{
%%%     identity_sign_public => SignPub,
%%%     identity_dh_public => DHPub,
%%%     signed_prekey_public => SPKPub,
%%%     signed_prekey_signature => SPKSig
%%% }).
%%% </pre>
%%%
%%% @author Cryptic Team
%%% @version 1.0.0

-module(cryptic_messages).

-export([
    % Client to Server - Authentication & Keys
    upload_identity_keys/1,
    upload_prekey_bundle/1,
    get_key_bundle/1,
    key_status/0,

    % Client to Server - Messaging
    send_encrypted/1,
    send_message_x3dh/1,
    send_message_ratchet/1,

    % Client to Server - User & Message Management
    list_users/0,
    get_messages/0,

    % Server to Client - Responses
    welcome/1,
    success/1,
    error/1,
    key_status_response/1,
    key_bundle_response/1,
    user_status_response/1,
    users_response/1,
    messages_response/1,
    encrypted_message_received/1,
    message_sent/1,

    % Utility Functions
    validate_message/1,
    encode_message/1
]).

%%% ============================================================================
%%% Type Definitions
%%% ============================================================================

-type message_type() ::
    upload_identity_keys
    | upload_prekey_bundle
    | get_key_bundle
    | key_status
    | send_encrypted
    | x3dh
    | ratchet
    | list_users
    | get_messages
    | welcome
    | success
    | error
    | key_status_response
    | key_bundle_response
    | user_status_response
    | users_response
    | messages_response
    | encrypted_message_received
    | message_sent.

-type message_map() :: #{binary() => term()}.
-type validation_result() :: {ok, message_map()} | {error, term()}.

%%% ============================================================================
%%% Client to Server Messages - Authentication & Keys
%%% ============================================================================

%% @doc Construct the `upload_identity_keys' message
%%
%% Uploads the user's Ed25519 signing key, X25519 DH key, signed prekey,
%% and signature following the 5-step authentication flow.
%%
%% @param MsgMap Map containing:
%%   - `identity_sign_public' (binary): Ed25519 public signing key
%%   - `identity_dh_public' (binary): X25519 public DH key
%%   - `signed_prekey_public' (binary): Signed prekey for key agreement
%%   - `signed_prekey_signature' (binary): Signature of signed prekey
%% @returns `{ok, Message}' or `{error, Reason}'
-spec upload_identity_keys(map()) -> validation_result().
upload_identity_keys(MsgMap) ->
    case mk_payload(upload_identity_keys, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"upload_identity_keys">>,
                <<"identity_sign_public">> => base64:encode(
                    maps:get(identity_sign_public, Payload)
                ),
                <<"identity_dh_public">> => base64:encode(
                    maps:get(identity_dh_public, Payload)
                ),
                <<"signed_prekey_public">> => base64:encode(
                    maps:get(signed_prekey_public, Payload)
                ),
                <<"signed_prekey_signature">> => base64:encode(
                    maps:get(signed_prekey_signature, Payload)
                )
            }};
        Error ->
            Error
    end.

%% @doc Construct the `upload_prekey_bundle' message
%%
%% Uploads a bundle of one-time prekeys for X3DH key agreement.
%% This is Step 5 of the authentication flow.
%%
%% @param MsgMap Map containing:
%%   - `one_time_prekeys' (list): List of #{id => KeyId, public => PubKey} maps
%% @returns `{ok, Message}' or `{error, Reason}'
-spec upload_prekey_bundle(map()) -> validation_result().
upload_prekey_bundle(MsgMap) ->
    case mk_payload(upload_prekey_bundle, MsgMap) of
        {ok, Payload} ->
            OneTimePrekeys = lists:map(
                fun(#{id := KeyId, public := PubKey}) ->
                    #{
                        <<"id">> => base64:encode(KeyId),
                        <<"public_key">> => base64:encode(PubKey)
                    }
                end,
                maps:get(one_time_prekeys, Payload)
            ),
            {ok, #{
                <<"type">> => <<"upload_prekey_bundle">>,
                <<"one_time_prekeys">> => OneTimePrekeys
            }};
        Error ->
            Error
    end.

%% @doc Construct the `get_key_bundle' message
%%
%% Requests another user's complete key bundle for X3DH session initiation.
%%
%% @param MsgMap Map containing:
%%   - `user' (binary): Username to get key bundle for
%% @returns `{ok, Message}' or `{error, Reason}'
-spec get_key_bundle(map()) -> validation_result().
get_key_bundle(MsgMap) ->
    case mk_payload(get_key_bundle, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"get_key_bundle">>,
                <<"user">> => maps:get(user, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `key_status' message
%%
%% Requests the current user's key status and statistics.
%%
%% @returns `{ok, Message}'
-spec key_status() -> validation_result().
key_status() ->
    {ok, #{<<"type">> => <<"key_status">>}}.

%%% ============================================================================
%%% Client to Server Messages - Messaging
%%% ============================================================================

%% @doc Construct the `send_encrypted' message
%%
%% Sends a unified encrypted message (either X3DH or Double Ratchet).
%% The server relays the encrypted payload without interpretation.
%%
%% @param MsgMap Map containing:
%%   - `to' (binary): Recipient username
%%   - `message' (map): Encrypted message payload
%% @returns `{ok, Message}' or `{error, Reason}'
-spec send_encrypted(map()) -> validation_result().
send_encrypted(MsgMap) ->
    case mk_payload(send_encrypted, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"send_encrypted">>,
                <<"to">> => maps:get(to, Payload),
                <<"message">> => maps:get(message, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `x3dh' message
%%
%% Sends an X3DH encrypted message for session establishment.
%% Contains all X3DH protocol components including metadata.
%%
%% @param MsgMap Map containing:
%%   - `to' (binary): Recipient username
%%   - `message_id' (binary): Base64-encoded message ID
%%   - `ephemeral_public' (binary): Base64-encoded ephemeral public key
%%   - `otpk_id' (binary | null): Base64-encoded one-time prekey ID or null
%%   - `ciphertext' (binary): Base64-encoded encrypted message
%%   - `nonce' (binary): Base64-encoded nonce
%%   - `signature' (binary): Base64-encoded message signature
%%   - `metadata' (binary): Base64-encoded metadata
%% @returns `{ok, Message}' or `{error, Reason}'
-spec send_message_x3dh(map()) -> validation_result().
send_message_x3dh(MsgMap) ->
    case mk_payload(send_message_x3dh, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"x3dh">>,
                <<"from">> => maps:get(from, Payload),
                <<"to">> => maps:get(to, Payload),
                <<"message_id">> => maps:get(message_id, Payload),
                <<"ephemeral_public">> => maps:get(ephemeral_public, Payload),
                <<"otpk_id">> => maps:get(otpk_id, Payload),
                <<"ciphertext">> => maps:get(ciphertext, Payload),
                <<"nonce">> => maps:get(nonce, Payload),
                <<"signature">> => maps:get(signature, Payload),
                <<"metadata">> => maps:get(metadata, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `ratchet' message
%%
%% Sends a Double Ratchet encrypted message for ongoing communication.
%% Used after X3DH session establishment.
%%
%% @param MsgMap Map containing:
%%   - `to' (binary): Recipient username
%%   - `message_id' (binary): Base64-encoded message ID
%%   - `dh_public' (binary): Base64-encoded current DH public key
%%   - `dh_step' (integer): DH ratchet step number
%%   - `prev_chain_length' (integer): Previous chain length
%%   - `msg_number' (integer): Message number in current chain
%%   - `ciphertext' (binary): Base64-encoded encrypted message
%%   - `nonce' (binary): Base64-encoded nonce
%% @returns `{ok, Message}' or `{error, Reason}'
-spec send_message_ratchet(map()) -> validation_result().
send_message_ratchet(MsgMap) ->
    case mk_payload(send_message_ratchet, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"ratchet">>,
                <<"from">> => maps:get(from, Payload),
                <<"to">> => maps:get(to, Payload),
                <<"message_id">> => maps:get(message_id, Payload),
                <<"dh_public">> => maps:get(dh_public, Payload),
                <<"dh_step">> => maps:get(dh_step, Payload),
                <<"prev_chain_length">> => maps:get(prev_chain_length, Payload),
                <<"msg_number">> => maps:get(msg_number, Payload),
                <<"ciphertext">> => maps:get(ciphertext, Payload),
                <<"nonce">> => maps:get(nonce, Payload)
            }};
        Error ->
            Error
    end.

%%% ============================================================================
%%% Client to Server Messages - User & Message Management
%%% ============================================================================

%% @doc Construct the `list_users' message
%%
%% Requests a list of all registered users.
%%
%% @returns `{ok, Message}'
-spec list_users() -> validation_result().
list_users() ->
    {ok, #{<<"type">> => <<"list_users">>}}.

%% @doc Construct the `get_messages' message
%%
%% Requests all stored messages for the current user.
%%
%% @returns `{ok, Message}'
-spec get_messages() -> validation_result().
get_messages() ->
    {ok, #{<<"type">> => <<"get_messages">>}}.

%%% ============================================================================
%%% Server to Client Messages - Responses
%%% ============================================================================

%% @doc Construct the `welcome' message
%%
%% Server welcome message sent upon WebSocket connection establishment.
%%
%% @param MsgMap Map containing:
%%   - `message' (binary): Welcome message text
%% @returns `{ok, Message}' or `{error, Reason}'
-spec welcome(map()) -> validation_result().
welcome(MsgMap) ->
    case mk_payload(welcome, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"welcome">>,
                <<"message">> => maps:get(message, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `success' message
%%
%% Generic success response from server operations.
%%
%% @param MsgMap Map containing:
%%   - `message' (binary): Success message text
%% @returns `{ok, Message}' or `{error, Reason}'
-spec success(map()) -> validation_result().
success(MsgMap) ->
    case mk_payload(success, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"success">>,
                <<"message">> => maps:get(message, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `error' message
%%
%% Generic error response from server operations.
%%
%% @param MsgMap Map containing:
%%   - `message' (binary): Error message text
%% @returns `{ok, Message}' or `{error, Reason}'
-spec error(map()) -> validation_result().
error(MsgMap) ->
    case mk_payload(error, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"error">>,
                <<"message">> => maps:get(message, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `key_status' response message
%%
%% Server response containing user's key status and statistics.
%%
%% @param MsgMap Map containing:
%%   - `status' (map): Key status information
%%   - `error' (binary, optional): Error message if status unavailable
%% @returns `{ok, Message}' or `{error, Reason}'
-spec key_status_response(map()) -> validation_result().
key_status_response(MsgMap) ->
    case mk_payload(key_status_response, MsgMap) of
        {ok, Payload} ->
            BaseMsg = #{
                <<"type">> => <<"key_status">>,
                <<"status">> => maps:get(status, Payload)
            },
            Message =
                case maps:get(error, Payload, undefined) of
                    undefined -> BaseMsg;
                    ErrorMsg -> BaseMsg#{<<"error">> => ErrorMsg}
                end,
            {ok, Message};
        Error ->
            Error
    end.

%% @doc Construct the `key_bundle' response message
%%
%% Server response containing a user's complete key bundle for X3DH.
%%
%% @param MsgMap Map containing:
%%   - `user' (binary): Username
%%   - `key_id' (binary): Base64-encoded key ID
%%   - `identity_sign_public' (binary): Base64-encoded Ed25519 signing key
%%   - `identity_dh_public' (binary): Base64-encoded X25519 DH key
%%   - `signed_prekey' (binary): Base64-encoded signed prekey
%%   - `signed_prekey_signature' (binary): Base64-encoded signature
%%   - `one_time_prekey' (map | null): Selected one-time prekey or null
%%   - `remaining_otpks' (integer): Count of remaining one-time prekeys
%% @returns `{ok, Message}' or `{error, Reason}'
-spec key_bundle_response(map()) -> validation_result().
key_bundle_response(MsgMap) ->
    case mk_payload(key_bundle_response, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"key_bundle">>,
                <<"user">> => maps:get(user, Payload),
                <<"key_id">> => maps:get(key_id, Payload),
                <<"identity_sign_public">> => maps:get(
                    identity_sign_public, Payload
                ),
                <<"identity_dh_public">> => maps:get(
                    identity_dh_public, Payload
                ),
                <<"signed_prekey">> => maps:get(signed_prekey, Payload),
                <<"signed_prekey_signature">> => maps:get(
                    signed_prekey_signature, Payload
                ),
                <<"one_time_prekey">> => maps:get(one_time_prekey, Payload),
                <<"remaining_otpks">> => maps:get(remaining_otpks, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `user_status' response message
%%
%% Server response indicating a user's online/offline status.
%%
%% @param MsgMap Map containing:
%%   - `user' (binary): Username
%%   - `status' (binary): Status ("online" or "offline")
%%   - `message' (binary): Status description
%% @returns `{ok, Message}' or `{error, Reason}'
-spec user_status_response(map()) -> validation_result().
user_status_response(MsgMap) ->
    case mk_payload(user_status_response, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"user_status">>,
                <<"user">> => maps:get(user, Payload),
                <<"status">> => maps:get(status, Payload),
                <<"message">> => maps:get(message, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `users' response message
%%
%% Server response containing list of all registered users.
%%
%% @param MsgMap Map containing:
%%   - `users' (list): List of usernames as binaries
%% @returns `{ok, Message}' or `{error, Reason}'
-spec users_response(map()) -> validation_result().
users_response(MsgMap) ->
    case mk_payload(users_response, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"users">>,
                <<"users">> => maps:get(users, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `messages' response message
%%
%% Server response containing stored messages for a user.
%%
%% @param MsgMap Map containing:
%%   - `messages' (list): List of stored messages
%% @returns `{ok, Message}' or `{error, Reason}'
-spec messages_response(map()) -> validation_result().
messages_response(MsgMap) ->
    case mk_payload(messages_response, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"messages">>,
                <<"messages">> => maps:get(messages, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `encrypted_message_received' message
%%
%% Server notification of an incoming encrypted message.
%%
%% @param MsgMap Map containing:
%%   - `from' (binary): Sender username
%%   - `message' (map): Encrypted message payload
%%   - `server_timestamp' (integer): Server timestamp
%% @returns `{ok, Message}' or `{error, Reason}'
-spec encrypted_message_received(map()) -> validation_result().
encrypted_message_received(MsgMap) ->
    case mk_payload(encrypted_message_received, MsgMap) of
        {ok, Payload} ->
            {ok, #{
                <<"type">> => <<"encrypted_message_received">>,
                <<"from">> => maps:get(from, Payload),
                <<"message">> => maps:get(message, Payload),
                <<"server_timestamp">> => maps:get(server_timestamp, Payload)
            }};
        Error ->
            Error
    end.

%% @doc Construct the `message_sent' confirmation message
%%
%% Server confirmation that a message was successfully sent/stored.
%%
%% @param MsgMap Map containing:
%%   - `success' (boolean): Whether message was sent successfully
%%   - `to' (binary, optional): Recipient username
%%   - `timestamp' (integer, optional): Server timestamp
%%   - `message' (binary, optional): Confirmation message
%% @returns `{ok, Message}' or `{error, Reason}'
-spec message_sent(map()) -> validation_result().
message_sent(MsgMap) ->
    case mk_payload(message_sent, MsgMap) of
        {ok, Payload} ->
            BaseMsg = #{
                <<"type">> => <<"message_sent">>,
                <<"success">> => maps:get(success, Payload)
            },

            % Add optional fields
            Msg1 =
                case maps:get(to, Payload, undefined) of
                    undefined -> BaseMsg;
                    To -> BaseMsg#{<<"to">> => To}
                end,

            Msg2 =
                case maps:get(timestamp, Payload, undefined) of
                    undefined -> Msg1;
                    Timestamp -> Msg1#{<<"timestamp">> => Timestamp}
                end,

            Message =
                case maps:get(message, Payload, undefined) of
                    undefined -> Msg2;
                    Msg -> Msg2#{<<"message">> => Msg}
                end,

            {ok, Message};
        Error ->
            Error
    end.

%%% ============================================================================
%%% Utility Functions
%%% ============================================================================

%% @doc Validate a constructed message against its expected schema
%%
%% @param Message The message map to validate
%% @returns `{ok, Message}' if valid, `{error, Reason}' if invalid
-spec validate_message(message_map()) -> validation_result().
validate_message(Message) ->
    case maps:get(<<"type">>, Message, undefined) of
        undefined ->
            {error, missing_type_field};
        Type when is_binary(Type) ->
            validate_message_by_type(Type, Message);
        _ ->
            {error, invalid_type_field}
    end.

%% @doc Encode a message as JSON for transmission
%%
%% @param Message The message map to encode
%% @returns `{ok, JsonBinary}' or `{error, Reason}'
-spec encode_message(message_map()) -> {ok, binary()} | {error, term()}.
encode_message(Message) ->
    try
        JsonBinary = jsx:encode(Message),
        {ok, JsonBinary}
    catch
        _:Reason ->
            {error, {json_encode_failed, Reason}}
    end.

%%% ============================================================================
%%% Private Helper Functions
%%% ============================================================================

%% @private
%% Validate message payload and convert to internal format
-spec mk_payload(message_type(), map()) -> {ok, map()} | {error, term()}.

mk_payload(upload_identity_keys, MsgMap) ->
    RequiredFields = [
        identity_sign_public,
        identity_dh_public,
        signed_prekey_public,
        signed_prekey_signature
    ],
    validate_required_fields(RequiredFields, MsgMap);
mk_payload(upload_prekey_bundle, MsgMap) ->
    case maps:get(one_time_prekeys, MsgMap, undefined) of
        undefined ->
            {error, missing_one_time_prekeys};
        Prekeys when is_list(Prekeys) ->
            case validate_prekey_list(Prekeys) of
                ok -> {ok, MsgMap};
                Error -> Error
            end;
        _ ->
            {error, invalid_one_time_prekeys_format}
    end;
mk_payload(get_key_bundle, MsgMap) ->
    case maps:get(user, MsgMap, undefined) of
        undefined -> {error, missing_user_field};
        User when is_binary(User) -> {ok, MsgMap};
        _ -> {error, invalid_user_field}
    end;
mk_payload(send_encrypted, MsgMap) ->
    RequiredFields = [to, message],
    validate_required_fields(RequiredFields, MsgMap);
mk_payload(send_message_x3dh, MsgMap) ->
    RequiredFields = [
        from,
        to,
        message_id,
        ephemeral_public,
        ciphertext,
        nonce,
        signature,
        metadata
    ],
    % otpk_id is optional (can be null)
    validate_required_fields(RequiredFields, MsgMap);
mk_payload(send_message_ratchet, MsgMap) ->
    RequiredFields = [
        from,
        to,
        message_id,
        dh_public,
        dh_step,
        prev_chain_length,
        msg_number,
        ciphertext,
        nonce
    ],
    validate_required_fields(RequiredFields, MsgMap);
mk_payload(welcome, MsgMap) ->
    case maps:get(message, MsgMap, undefined) of
        undefined -> {error, missing_message_field};
        Message when is_binary(Message) -> {ok, MsgMap};
        _ -> {error, invalid_message_field}
    end;
mk_payload(success, MsgMap) ->
    case maps:get(message, MsgMap, undefined) of
        undefined -> {error, missing_message_field};
        Message when is_binary(Message) -> {ok, MsgMap};
        _ -> {error, invalid_message_field}
    end;
mk_payload(error, MsgMap) ->
    case maps:get(message, MsgMap, undefined) of
        undefined -> {error, missing_message_field};
        Message when is_binary(Message) -> {ok, MsgMap};
        _ -> {error, invalid_message_field}
    end;
mk_payload(key_status_response, MsgMap) ->
    case maps:get(status, MsgMap, undefined) of
        undefined -> {error, missing_status_field};
        Status when is_map(Status) -> {ok, MsgMap};
        _ -> {error, invalid_status_field}
    end;
mk_payload(key_bundle_response, MsgMap) ->
    RequiredFields = [
        user,
        key_id,
        identity_sign_public,
        identity_dh_public,
        signed_prekey,
        signed_prekey_signature,
        one_time_prekey,
        remaining_otpks
    ],
    validate_required_fields(RequiredFields, MsgMap);
mk_payload(user_status_response, MsgMap) ->
    RequiredFields = [user, status, message],
    validate_required_fields(RequiredFields, MsgMap);
mk_payload(users_response, MsgMap) ->
    case maps:get(users, MsgMap, undefined) of
        undefined ->
            {error, missing_users_field};
        Users when is_list(Users) ->
            case lists:all(fun is_binary/1, Users) of
                true -> {ok, MsgMap};
                false -> {error, invalid_users_list_format}
            end;
        _ ->
            {error, invalid_users_field}
    end;
mk_payload(messages_response, MsgMap) ->
    case maps:get(messages, MsgMap, undefined) of
        undefined -> {error, missing_messages_field};
        Messages when is_list(Messages) -> {ok, MsgMap};
        _ -> {error, invalid_messages_field}
    end;
mk_payload(encrypted_message_received, MsgMap) ->
    RequiredFields = [from, message, server_timestamp],
    validate_required_fields(RequiredFields, MsgMap);
mk_payload(message_sent, MsgMap) ->
    case maps:get(success, MsgMap, undefined) of
        undefined -> {error, missing_success_field};
        Success when is_boolean(Success) -> {ok, MsgMap};
        _ -> {error, invalid_success_field}
    end;
mk_payload(_, _) ->
    {error, unknown_message_type}.

%% @private
%% Validate that all required fields are present in the message map
-spec validate_required_fields([atom()], map()) ->
    {ok, map()} | {error, term()}.
validate_required_fields(RequiredFields, MsgMap) ->
    case find_missing_fields(RequiredFields, MsgMap) of
        [] -> {ok, MsgMap};
        MissingFields -> {error, {missing_fields, MissingFields}}
    end.

%% @private
%% Find any missing required fields
-spec find_missing_fields([atom()], map()) -> [atom()].
find_missing_fields(RequiredFields, MsgMap) ->
    lists:filter(
        fun(Field) ->
            not maps:is_key(Field, MsgMap)
        end,
        RequiredFields
    ).

%% @private
%% Validate prekey list format
-spec validate_prekey_list(list()) -> ok | {error, term()}.
validate_prekey_list([]) ->
    {error, empty_prekey_list};
validate_prekey_list(Prekeys) ->
    case lists:all(fun validate_prekey_entry/1, Prekeys) of
        true -> ok;
        false -> {error, invalid_prekey_entry_format}
    end.

%% @private
%% Validate individual prekey entry
-spec validate_prekey_entry(term()) -> boolean().
validate_prekey_entry(#{id := Id, public := Public}) when
    is_binary(Id), is_binary(Public)
->
    true;
validate_prekey_entry(_) ->
    false.

%% @private
%% Validate message by type
-spec validate_message_by_type(binary(), message_map()) -> validation_result().
validate_message_by_type(<<"upload_identity_keys">>, Message) ->
    RequiredFields = [
        <<"identity_sign_public">>,
        <<"identity_dh_public">>,
        <<"signed_prekey_public">>,
        <<"signed_prekey_signature">>
    ],
    validate_binary_fields(RequiredFields, Message);
validate_message_by_type(<<"upload_prekey_bundle">>, Message) ->
    case maps:get(<<"one_time_prekeys">>, Message, undefined) of
        undefined -> {error, missing_one_time_prekeys};
        Prekeys when is_list(Prekeys) -> {ok, Message};
        _ -> {error, invalid_one_time_prekeys}
    end;
validate_message_by_type(<<"get_key_bundle">>, Message) ->
    case maps:get(<<"user">>, Message, undefined) of
        undefined -> {error, missing_user};
        User when is_binary(User) -> {ok, Message};
        _ -> {error, invalid_user}
    end;
validate_message_by_type(<<"ratchet">>, Message) ->
    %% Validate ratchet message has all required fields
    %% Note: dh_step, prev_chain_length, msg_number are integers, others are binary
    RequiredFields = [
        <<"from">>,
        <<"to">>,
        <<"message_id">>,
        <<"dh_public">>,
        <<"ciphertext">>,
        <<"nonce">>
    ],
    case validate_binary_fields(RequiredFields, Message) of
        {ok, _} ->
            %% Also check integer fields exist
            case
                {
                    maps:is_key(<<"dh_step">>, Message),
                    maps:is_key(<<"prev_chain_length">>, Message),
                    maps:is_key(<<"msg_number">>, Message)
                }
            of
                {true, true, true} -> {ok, Message};
                _ -> {error, missing_integer_fields}
            end;
        Error ->
            Error
    end;
validate_message_by_type(<<"x3dh">>, Message) ->
    RequiredFields = [
        <<"from">>,
        <<"to">>,
        <<"message_id">>,
        <<"ephemeral_public">>,
        <<"ciphertext">>,
        <<"nonce">>,
        <<"signature">>,
        <<"metadata">>
    ],
    validate_binary_fields(RequiredFields, Message);
validate_message_by_type(Type, Message) ->
    % For other message types, just verify type field exists
    case maps:get(<<"type">>, Message) of
        Type -> {ok, Message};
        _ -> {error, type_mismatch}
    end.

%% @private
%% Validate that specified fields contain binary values
-spec validate_binary_fields([binary()], message_map()) -> validation_result().
validate_binary_fields(Fields, Message) ->
    MissingFields = lists:filter(
        fun(Field) ->
            case maps:get(Field, Message, undefined) of
                undefined -> true;
                Value when is_binary(Value) -> false;
                _ -> true
            end
        end,
        Fields
    ),
    case MissingFields of
        [] -> {ok, Message};
        _ -> {error, {invalid_or_missing_fields, MissingFields}}
    end.
