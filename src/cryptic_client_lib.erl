%% @doc Cryptic Client Library - End-to-End Encrypted Messaging
%%
%% This module provides a comprehensive client library for the Cryptic messaging system,
%% implementing end-to-end encryption using X25519 key exchange and XChaCha20-Poly1305 AEAD.
%%
%% == Features ==
%% <ul>
%%   <li>Client initialization and setup</li>
%%   <li>Prekey management (upload/retrieve public keys)</li>
%%   <li>Message encryption and decryption</li>
%%   <li>High-level E2E messaging flows</li>
%%   <li>JSON parsing and formatting utilities</li>
%%   <li>Comprehensive error handling</li>
%% </ul>
%%
%% == Basic Usage ==
%% ```
%% %% Initialize client
%% ok = cryptic_client_lib:init_client(),
%%
%% %% Generate keypair (using cryptic_lib)
%% {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
%%
%% %% Upload your public key
%% ok = cryptic_client_lib:upload_prekey("http://localhost:8080", "alice", PubKey),
%%
%% %% Send encrypted message
%% ok = cryptic_client_lib:send_encrypted_message(
%%     "http://localhost:8080", "alice", "bob", "Hello!", PrivKey),
%%
%% %% Receive and decrypt messages
%% {ok, Messages} = cryptic_client_lib:receive_and_decrypt_messages(
%%     "http://localhost:8080", "bob", BobPrivKey).
%% '''
%%
%% == Security Properties ==
%% <ul>
%%   <li>Forward secrecy through ephemeral key exchange</li>
%%   <li>Authenticated encryption using XChaCha20-Poly1305</li>
%%   <li>Key derivation using HKDF with ephemeral-based salt</li>
%%   <li>Unicode-safe message handling</li>
%% </ul>
%%
%% @author Torbjörn Törnkvist
%% @version 1.0.0
%% @since September 2025
-module(cryptic_client_lib).

-export([
    %% Client setup
    init_client/0,
    
    %% Prekey management
    upload_prekey/3,
    get_prekey/2,
    list_users/1,
    
    %% Message operations
    encrypt_message/2,
    send_message/6,
    receive_messages/2,
    decrypt_message/2,
    decrypt_message_from_json/2,
    
    %% Utility functions
    parse_message_json/1,
    create_message_json/5,
    format_send_blob_request/5,
    parse_recv_blobs_response/1,
    parse_get_prekey_response/1,
    parse_users_list_response/1,
    
    %% E2E flow helpers
    send_encrypted_message/5,
    receive_and_decrypt_messages/3
]).

%% == Types ==

%% User identifier, can be provided as string or binary.

%% Base URL of the Cryptic server (e.g., "http://localhost:8080").

%% Message content as binary data. Unicode strings are automatically converted.

%% Encrypted message blob containing all cryptographic parameters.
%% <ul>
%%   <li>`from' - Sender's user ID</li>
%%   <li>`ephemeral' - Ephemeral public key (base64 encoded in JSON)</li>
%%   <li>`nonce' - Encryption nonce (base64 encoded in JSON)</li>
%%   <li>`cipher' - Encrypted ciphertext (base64 encoded in JSON)</li>
%% </ul>

-type user_id() :: string() | binary().
-type server_url() :: string().
-type message() :: binary().
%%-type keypair() :: {PublicKey :: binary(), PrivateKey :: binary()}.
-type encrypted_blob() :: #{
    from => user_id(),
    ephemeral => binary(),
    nonce => binary(),
    cipher => binary()
}.

%%%===================================================================
%%% Client Setup
%%%===================================================================

%% @doc Initialize the Cryptic client library.
%%
%% This function must be called before using any other library functions.
%% It ensures that all required applications (inets, crypto) are started
%% and loads the cryptic_nif module for cryptographic operations.
%%
%% == Example ==
%% ```
%% ok = cryptic_client_lib:init_client().
%% '''
%%
%% @returns `ok' if initialization succeeds.
-spec init_client() -> ok.
init_client() ->
    application:ensure_all_started(inets),
    application:ensure_all_started(crypto),
    ok.

%%%===================================================================
%%% Prekey Management
%%%===================================================================

%% @doc Upload a user's public key to the server.
%%
%% Uploads the user's X25519 public key to the server so that other users
%% can retrieve it for message encryption. The public key is base64-encoded
%% for transmission.
%%
%% == Example ==
%% ```
%% {PubKey, _PrivKey} = cryptic_lib:gen_keypair(),
%% ok = cryptic_client_lib:upload_prekey(
%%     "http://localhost:8080", "alice", PubKey).
%% '''
%%
%% @param ServerUrl Base URL of the Cryptic server
%% @param UserId Unique identifier for the user
%% @param PublicKey X25519 public key (32 bytes)
%% @returns `ok' if upload succeeds, `{error, Reason}' if it fails.
-spec upload_prekey(server_url(), user_id(), binary()) -> ok | {error, term()}.
upload_prekey(ServerUrl, UserId, PublicKey) ->
    PubKeyB64 = base64:encode(PublicKey),
    PostData = io_lib:format("{\"prekey\":\"~s\"}", [PubKeyB64]),
    Url = lists:flatten(io_lib:format("~s/upload_prekey/~s", [ServerUrl, UserId])),
    
    case httpc:request(
        post,
        {Url, [], "application/json", PostData},
        [],
        []
    ) of
        {ok, {_, _, _}} -> ok;
        {error, Reason} -> {error, Reason}
    end.

%% @doc Retrieve a user's public key from the server.
%%
%% Fetches another user's X25519 public key from the server for message
%% encryption. The key is automatically base64-decoded from the server response.
%%
%% == Example ==
%% ```
%% {ok, BobPubKey} = cryptic_client_lib:get_prekey(
%%     "http://localhost:8080", "bob").
%% '''
%%
%% @param ServerUrl Base URL of the Cryptic server
%% @param UserId Unique identifier for the target user
%% @returns `{ok, PublicKey}' if successful, `{error, Reason}' if it fails.
%%   Common error reasons include `invalid_response' and HTTP errors.
-spec get_prekey(server_url(), user_id()) -> {ok, binary()} | {error, term()}.
get_prekey(ServerUrl, UserId) ->
    Url = lists:flatten(io_lib:format("~s/get_prekey/~s", [ServerUrl, UserId])),
    
    case httpc:request(get, {Url, []}, [], []) of
        {ok, {_, _, RespData}} ->
            case re:run(RespData, "\"pub\"\\s*:\\s*\"([^\"]+)\"", [
                {capture, [1], list}
            ]) of
                {match, [PubKeyB64]} ->
                    {ok, base64:decode(PubKeyB64)};
                nomatch ->
                    {error, invalid_response}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc List all users who have uploaded prekeys to the server.
%%
%% Retrieves a list of all usernames that have registered prekeys on the server.
%% This is useful for discovering available users for messaging.
%%
%% == Example ==
%% ```
%% {ok, Users} = cryptic_client_lib:list_users("http://localhost:8080"),
%% %% Users = ["alice", "bob", "charlie"]
%% '''
%%
%% @param ServerUrl The URL of the cryptic server
%% @returns `{ok, [string()]}' with list of usernames, or `{error, term()}' on failure
-spec list_users(server_url()) -> {ok, [string()]} | {error, term()}.
list_users(ServerUrl) ->
    Url = lists:flatten(io_lib:format("~s/list_users", [ServerUrl])),
    
    case httpc:request(get, {Url, []}, [], []) of
        {ok, {_, _, RespData}} ->
            case parse_users_list_response(RespData) of
                {ok, Users} ->
                    {ok, Users};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%%%===================================================================
%%% Message Operations
%%%===================================================================

%% @doc Encrypt a message for a recipient using ephemeral key exchange.
%%
%% Encrypts a message using X25519 ephemeral key exchange and XChaCha20-Poly1305 AEAD.
%% This provides forward secrecy as each message uses a fresh ephemeral keypair.
%%
%% == Cryptographic Process ==
%% <ol>
%%   <li>Generate ephemeral X25519 keypair</li>
%%   <li>Compute shared secret: ephemeral_private * recipient_public</li>
%%   <li>Derive AEAD key using HKDF with ephemeral public key as salt</li>
%%   <li>Encrypt message with XChaCha20-Poly1305</li>
%% </ol>
%%
%% == Example ==
%% ```
%% {ok, BobPubKey} = cryptic_client_lib:get_prekey("http://localhost:8080", "bob"),
%% {ok, {EphPub, Nonce, Cipher}} = cryptic_client_lib:encrypt_message(
%%     <<"Hello Bob!">>, BobPubKey).
%% '''
%%
%% @param Message The message to encrypt (string or binary)
%% @param RecipientPubKey X25519 public key of the recipient (32 bytes)
%% @returns `{ok, {EphemeralPubKey, Nonce, Ciphertext}}' if successful,
%%   `{error, Reason}' if encryption fails.
-spec encrypt_message(message(), binary()) -> 
    {ok, {binary(), binary(), binary()}} | {error, term()}.
encrypt_message(Message, RecipientPubKey) ->
    try
        %% Convert message to binary if it's a string
        MessageBin = case is_binary(Message) of
            true -> Message;
            false -> unicode:characters_to_binary(Message)
        end,
        
        %% Generate ephemeral keypair
        {EphPub, EphPriv} = cryptic_lib:gen_keypair(),
        
        %% Compute shared secret
        Shared = cryptic_lib:scalarmult(EphPriv, RecipientPubKey),
        
        %% Derive AEAD key using ephemeral-based salt
        AeadKey = cryptic_lib:derive_aead_key_ephemeral(Shared, EphPub),
        
        %% Encrypt message
        {Cipher, Nonce} = cryptic_lib:aead_encrypt(MessageBin, AeadKey, <<>>),
        
        {ok, {EphPub, Nonce, Cipher}}
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Send an encrypted message blob to the server.
%%
%% Transmits the encrypted message components to the server for delivery.
%% The server stores the encrypted blob until the recipient retrieves it.
%%
%% == Example ==
%% ```
%% {ok, {EphPub, Nonce, Cipher}} = cryptic_client_lib:encrypt_message(
%%     <<"Hello!">>, RecipientPubKey),
%% ok = cryptic_client_lib:send_message(
%%     "http://localhost:8080", "alice", "bob", EphPub, Nonce, Cipher).
%% '''
%%
%% @param ServerUrl Base URL of the Cryptic server
%% @param FromUserId Sender's user ID
%% @param ToUserId Recipient's user ID  
%% @param EphPub Ephemeral public key from encryption (32 bytes)
%% @param Nonce Encryption nonce (24 bytes for XChaCha20)
%% @param Cipher Encrypted ciphertext
%% @returns `ok' if message is successfully sent, `{error, Reason}' if it fails.
-spec send_message(server_url(), user_id(), user_id(), binary(), binary(), binary()) -> 
    ok | {error, term()}.
send_message(ServerUrl, FromUserId, ToUserId, EphPub, Nonce, Cipher) ->
    BlobData = create_message_json(FromUserId, ToUserId, EphPub, Nonce, Cipher),
    Url = lists:flatten(io_lib:format("~s/send_blob", [ServerUrl])),
    
    case httpc:request(
        post,
        {Url, [], "application/json", BlobData},
        [],
        []
    ) of
        {ok, {_, _, _}} -> ok;
        {error, Reason} -> {error, Reason}
    end.

%% @doc Retrieve pending encrypted messages for a user.
%%
%% Fetches all pending encrypted message blobs from the server for the specified user.
%% Messages are returned as encrypted_blob() maps ready for decryption.
%%
%% == Example ==
%% ```
%% {ok, EncryptedBlobs} = cryptic_client_lib:receive_messages(
%%     "http://localhost:8080", "alice").
%% '''
%%
%% @param ServerUrl Base URL of the Cryptic server
%% @param UserId User ID to fetch messages for
%% @returns `{ok, [encrypted_blob()]}' if successful (may be empty list),
%%   `{error, Reason}' if retrieval fails.
-spec receive_messages(server_url(), user_id()) -> 
    {ok, [encrypted_blob()]} | {error, term()}.
receive_messages(ServerUrl, UserId) ->
    Url = lists:flatten(io_lib:format("~s/recv_blobs/~s", [ServerUrl, UserId])),
    
    case httpc:request(get, {Url, []}, [], []) of
        {ok, {_, _, RespStr}} ->
            case RespStr of
                "[]" -> {ok, []};
                _ -> parse_messages_response(RespStr)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Decrypt a received encrypted message.
%%
%% Decrypts an encrypted message blob using the recipient's private key.
%% Supports both tuple format `{Ephemeral, Nonce, Cipher}' for testing
%% and map format for production use.
%%
%% == Cryptographic Process ==
%% <ol>
%%   <li>Compute shared secret: recipient_private * ephemeral_public</li>
%%   <li>Derive AEAD key using HKDF with ephemeral public key as salt</li>
%%   <li>Decrypt ciphertext with XChaCha20-Poly1305</li>
%%   <li>Convert result to UTF-8 string if possible, otherwise keep as binary</li>
%% </ol>
%%
%% == Example ==
%% ```
%% {ok, Messages} = cryptic_client_lib:receive_messages("http://localhost:8080", "alice"),
%% [FirstMsg | _] = Messages,
%% {ok, PlainText} = cryptic_client_lib:decrypt_message(FirstMsg, AlicePrivKey).
%% '''
%%
%% @param EncryptedBlob Either `{Ephemeral, Nonce, Cipher}' tuple or encrypted_blob() map
%% @param RecipientPrivKey X25519 private key of the recipient (32 bytes)
%% @returns `{ok, Message}' if decryption succeeds, `{error, Reason}' if it fails.
%%   Common error reasons include `decryption_failed' and key validation errors.
-spec decrypt_message(encrypted_blob(), binary()) -> 
    {ok, message()} | {error, term()}.
decrypt_message({Ephemeral, Nonce, Cipher}, RecipientPrivKey) ->
    %% Handle tuple format (for testing convenience)
    try
        %% Compute shared secret
        Shared = cryptic_lib:scalarmult(RecipientPrivKey, Ephemeral),
        
        %% Derive AEAD key
        AeadKey = cryptic_lib:derive_aead_key_ephemeral(Shared, Ephemeral),
        
        %% Decrypt message
        case cryptic_lib:aead_decrypt(Cipher, AeadKey, Nonce, <<>>) of
            error -> {error, decryption_failed};
            PlainBin -> 
                %% Convert back to string if possible
                Plain = case unicode:characters_to_list(PlainBin) of
                    {error, _, _} -> PlainBin;  % Keep as binary if not valid UTF-8
                    {incomplete, _, _} -> PlainBin;  % Keep as binary if incomplete
                    List -> List  % Convert to string
                end,
                {ok, Plain}
        end
    catch
        error:Reason -> {error, Reason}
    end;
decrypt_message(EncryptedBlob, RecipientPrivKey) ->
    %% Handle map format (original format)
    try
        #{
            ephemeral := EphemeralB64,
            nonce := NonceB64,
            cipher := CipherB64
        } = EncryptedBlob,
        
        %% Decode base64 fields
        Ephemeral = base64:decode(EphemeralB64),
        Nonce = base64:decode(NonceB64),
        Cipher = base64:decode(CipherB64),
        
        %% Use the tuple version
        decrypt_message({Ephemeral, Nonce, Cipher}, RecipientPrivKey)
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Decrypt message from JSON string (legacy format).
%%
%% Decrypts a message from a JSON string response. This is a legacy function
%% for compatibility with older message formats.
%%
%% @deprecated Use {@link decrypt_message/2} with proper encrypted_blob() format instead.
%%
%% @param RespStr JSON string containing encrypted message fields
%% @param RecipientPrivKey X25519 private key of the recipient
%% @returns `{ok, Message}' if successful, `{error, Reason}' if it fails.
-spec decrypt_message_from_json(string(), binary()) -> 
    {ok, message()} | {error, term()}.
decrypt_message_from_json(RespStr, RecipientPrivKey) ->
    try
        {EphemeralB64, NonceB64, CipherB64} = parse_message_json(RespStr),
        
        EncryptedBlob = #{
            ephemeral => EphemeralB64,
            nonce => NonceB64,
            cipher => CipherB64
        },
        
        decrypt_message(EncryptedBlob, RecipientPrivKey)
    catch
        error:Reason -> {error, Reason}
    end.

%%%===================================================================
%%% Utility Functions
%%%===================================================================

%% @doc Parse JSON message response to extract cryptographic fields.
%%
%% Extracts the ephemeral public key, nonce, and ciphertext from a JSON
%% message response using regular expressions. This is a simple parser
%% for the specific JSON format used by the Cryptic protocol.
%%
%% == Example ==
%% ```
%% JsonResp = "{\"ephemeral\":\"abc...\",\"nonce\":\"def...\",\"cipher\":\"ghi...\"}",
%% {EphB64, NonceB64, CipherB64} = cryptic_client_lib:parse_message_json(JsonResp).
%% '''
%%
%% @param RespStr JSON string containing message fields
%% @returns `{EphemeralB64, NonceB64, CipherB64}' tuple of base64-encoded strings.
-spec parse_message_json(string()) -> {string(), string(), string()}.
parse_message_json(RespStr) ->
    {match, [EphemeralB64]} = re:run(RespStr, "\"ephemeral\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    {match, [NonceB64]} = re:run(RespStr, "\"nonce\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    {match, [CipherB64]} = re:run(RespStr, "\"cipher\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    
    {EphemeralB64, NonceB64, CipherB64}.

%% @doc Create JSON message blob for transmission.
%%
%% Formats the encrypted message components into a JSON string suitable
%% for transmission to the server. All binary data is base64-encoded.
%%
%% == JSON Format ==
%% ```
%% {
%%   "from": "sender_id",
%%   "to": "recipient_id", 
%%   "ephemeral": "base64_ephemeral_key",
%%   "nonce": "base64_nonce",
%%   "cipher": "base64_ciphertext"
%% }
%% '''
%%
%% @param FromUserId Sender's user ID
%% @param ToUserId Recipient's user ID
%% @param EphPub Ephemeral public key (32 bytes)
%% @param Nonce Encryption nonce (24 bytes)
%% @param Cipher Encrypted ciphertext
%% @returns JSON string as iolist()
-spec create_message_json(user_id(), user_id(), binary(), binary(), binary()) -> iolist().
create_message_json(FromUserId, ToUserId, EphPub, Nonce, Cipher) ->
    EphPubB64 = base64:encode(EphPub),
    NonceB64 = base64:encode(Nonce),
    CipherB64 = base64:encode(Cipher),
    
    io_lib:format(
        "{\"from\":\"~s\",\"to\":\"~s\",\"ephemeral\":\"~s\",\"nonce\":\"~s\",\"cipher\":\"~s\"}",
        [FromUserId, ToUserId, EphPubB64, NonceB64, CipherB64]
    ).

%%%===================================================================
%%% High-Level E2E Flow Functions
%%%===================================================================

%% @doc Complete end-to-end encrypted message sending flow.
%%
%% High-level function that handles the complete process of sending an encrypted
%% message: fetches the recipient's public key, encrypts the message, and sends it.
%% This is the recommended function for most use cases.
%%
%% == Process Flow ==
%% <ol>
%%   <li>Fetch recipient's public key from server</li>
%%   <li>Encrypt message using ephemeral key exchange</li>
%%   <li>Send encrypted blob to server</li>
%% </ol>
%%
%% == Example ==
%% ```
%% ok = cryptic_client_lib:send_encrypted_message(
%%     "http://localhost:8080", "alice", "bob", <<"Hello Bob!">>, AlicePrivKey).
%% '''
%%
%% @param ServerUrl Base URL of the Cryptic server
%% @param FromUserId Sender's user ID
%% @param ToUserId Recipient's user ID
%% @param Message Message to encrypt and send
%% @param _FromPrivateKey Sender's private key (currently unused, reserved for future use)
%% @returns `ok' if message is successfully sent, `{error, Reason}' if any step fails.
-spec send_encrypted_message(server_url(), user_id(), user_id(), message(), binary()) -> 
    ok | {error, term()}.
send_encrypted_message(ServerUrl, FromUserId, ToUserId, Message, _FromPrivateKey) ->
    %% Get recipient's public key first
    case get_prekey(ServerUrl, ToUserId) of
        {ok, RecipientPubKey} ->
            send_encrypted_message_with_pubkey(ServerUrl, FromUserId, ToUserId, RecipientPubKey, Message);
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Send encrypted message when recipient's public key is already known.
%%
%% Optimized version of {@link send_encrypted_message/5} for cases where
%% the recipient's public key is already available, avoiding an extra
%% server round-trip.
%%
%% == Example ==
%% ```
%% {ok, BobPubKey} = cryptic_client_lib:get_prekey("http://localhost:8080", "bob"),
%% ok = cryptic_client_lib:send_encrypted_message_with_pubkey(
%%     "http://localhost:8080", "alice", "bob", BobPubKey, <<"Hello Bob!">>).
%% '''
%%
%% @param ServerUrl Base URL of the Cryptic server
%% @param FromUserId Sender's user ID
%% @param ToUserId Recipient's user ID
%% @param RecipientPubKey X25519 public key of the recipient
%% @param Message Message to encrypt and send
%% @returns `ok' if successful, `{error, Reason}' if encryption or sending fails.
-spec send_encrypted_message_with_pubkey(server_url(), user_id(), user_id(), binary(), message()) -> 
    ok | {error, term()}.
send_encrypted_message_with_pubkey(ServerUrl, FromUserId, ToUserId, RecipientPubKey, Message) ->
    case encrypt_message(Message, RecipientPubKey) of
        {ok, {EphPub, Nonce, Cipher}} ->
            send_message(ServerUrl, FromUserId, ToUserId, EphPub, Nonce, Cipher);
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Complete end-to-end message receiving and decryption flow.
%%
%% High-level function that handles the complete process of receiving messages:
%% fetches pending encrypted messages from the server and decrypts them.
%% This is the recommended function for message retrieval.
%%
%% == Process Flow ==
%% <ol>
%%   <li>Fetch pending encrypted messages from server</li>
%%   <li>Decrypt each message using recipient's private key</li>
%%   <li>Return list of `{SenderId, DecryptedMessage}' tuples</li>
%% </ol>
%%
%% == Example ==
%% ```
%% {ok, Messages} = cryptic_client_lib:receive_and_decrypt_messages(
%%     "http://localhost:8080", "bob", BobPrivKey),
%% [{SenderId, Message} | _] = Messages.
%% '''
%%
%% @param ServerUrl Base URL of the Cryptic server
%% @param UserId User ID to fetch messages for
%% @param PrivateKey X25519 private key for decryption
%% @returns `{ok, [{SenderId, DecryptedMessage}]}' if successful,
%%   `{error, Reason}' if retrieval or decryption fails.
%%   Failed decryptions are skipped and do not cause the function to fail.
-spec receive_and_decrypt_messages(server_url(), user_id(), binary()) -> 
    {ok, [message()]} | {error, term()}.
receive_and_decrypt_messages(ServerUrl, UserId, PrivateKey) ->
    case receive_messages(ServerUrl, UserId) of
        {ok, EncryptedBlobs} ->
            decrypt_all_messages(EncryptedBlobs, PrivateKey, []);
        {error, Reason} ->
            {error, Reason}
    end.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @private
%% @doc Parse the JSON response from receive_messages endpoint.
%%
%% Internal function that parses a JSON array response containing
%% multiple encrypted message objects. Uses simple regex-based parsing.
%%
%% @param RespStr JSON array string from server
%% @returns `{ok, [encrypted_blob()]}' if successful, `{error, {parse_error, Reason}}' if parsing fails.
parse_messages_response(RespStr) ->
    try
        %% Simple parsing for multiple messages - assumes array format
        %% This is a simplified parser; production code should use a proper JSON library
        Messages = extract_message_objects(RespStr),
        ParsedMessages = [parse_single_message(Msg) || Msg <- Messages],
        {ok, ParsedMessages}
    catch
        error:Reason -> {error, {parse_error, Reason}}
    end.

%% @private
%% @doc Extract individual message objects from JSON array string.
%%
%% Simple JSON parser that extracts objects between braces from an array.
%% This is a basic implementation; production code should use a proper JSON library.
%%
%% @param RespStr JSON array string
%% @returns List of individual JSON object strings
extract_message_objects(RespStr) ->
    %% Very basic JSON array parsing - extract objects between braces
    %% This is simplified; use a proper JSON library in production
    case re:run(RespStr, "\\{[^}]+\\}", [global, {capture, [0], list}]) of
        {match, Matches} -> [lists:flatten(Match) || [Match] <- Matches];
        nomatch -> []
    end.

%% @private
%% @doc Parse a single message JSON object into encrypted_blob format.
%%
%% Converts a single JSON message object string into the standard
%% encrypted_blob() map format used throughout the library.
%%
%% @param MessageStr Single JSON object string
%% @returns encrypted_blob() map with sender and crypto fields
parse_single_message(MessageStr) ->
    {EphemeralB64, NonceB64, CipherB64} = parse_message_json(MessageStr),
    
    %% Extract 'from' field
    {match, [FromUser]} = re:run(MessageStr, "\"from\"\\s*:\\s*\"([^\"]+)\"", [
        {capture, [1], list}
    ]),
    
    #{
        from => FromUser,
        ephemeral => EphemeralB64,
        nonce => NonceB64,
        cipher => CipherB64
    }.

%% @private
%% @doc Decrypt a list of encrypted messages, preserving sender information.
%%
%% Internal recursive function that decrypts multiple messages and returns
%% tuples containing both sender ID and decrypted message. Failed decryptions
%% are silently skipped to ensure robustness.
%%
%% @param EncryptedBlobs List of encrypted_blob() maps to decrypt
%% @param PrivateKey X25519 private key for decryption
%% @param Acc Accumulator for recursive processing
%% @returns `{ok, [{SenderId, DecryptedMessage}]}' with successfully decrypted messages
decrypt_all_messages([], _PrivateKey, Acc) ->
    {ok, lists:reverse(Acc)};
decrypt_all_messages([EncryptedBlob | Rest], PrivateKey, Acc) ->
    case decrypt_message(EncryptedBlob, PrivateKey) of
        {ok, PlainText} ->
            %% Extract sender from the encrypted blob
            From = maps:get(from, EncryptedBlob),
            decrypt_all_messages(Rest, PrivateKey, [{From, PlainText} | Acc]);
        {error, _Reason} ->
            %% Skip failed decryptions and continue
            decrypt_all_messages(Rest, PrivateKey, Acc)
    end.

%%%===================================================================
%%% Additional Utility Functions (for testing)
%%%===================================================================

%% @doc Format a send blob request as JSON string.
%%
%% Utility function for formatting encrypted message components into
%% a JSON request suitable for the `/send_blob' endpoint. Used primarily
%% for testing and debugging.
%%
%% == Example ==
%% ```
%% JsonStr = cryptic_client_lib:format_send_blob_request(
%%     "alice", "bob", EphemeralKey, Nonce, Cipher).
%% '''
%%
%% @param From Sender's user ID
%% @param To Recipient's user ID
%% @param Ephemeral Ephemeral public key (32 bytes)
%% @param Nonce Encryption nonce (24 bytes)
%% @param Cipher Encrypted ciphertext
%% @returns JSON string representation of the send blob request
-spec format_send_blob_request(string(), string(), binary(), binary(), binary()) -> string().
format_send_blob_request(From, To, Ephemeral, Nonce, Cipher) ->
    EphemeralB64 = base64:encode(Ephemeral),
    NonceB64 = base64:encode(Nonce),
    CipherB64 = base64:encode(Cipher),
    io_lib:format(
        "{\"from\":\"~s\",\"to\":\"~s\",\"ephemeral\":\"~s\",\"nonce\":\"~s\",\"cipher\":\"~s\"}",
        [From, To, EphemeralB64, NonceB64, CipherB64]
    ).

%% @doc Parse received blobs response from JSON string.
%%
%% Parses a JSON array response from the `/recv_blobs' endpoint into
%% a list of message tuples. Uses simple regex-based parsing for the
%% specific JSON format returned by the server.
%%
%% == Example ==
%% ```
%% JsonResp = "[{\"from\":\"alice\",\"ephemeral\":\"...\",\"nonce\":\"...\",\"cipher\":\"...\"}]",
%% Blobs = cryptic_client_lib:parse_recv_blobs_response(JsonResp).
%% '''
%%
%% @param RespStr JSON array string from `/recv_blobs' endpoint
%% @returns List of `{SenderId, EphemeralKey, Nonce, Cipher}' tuples with
%%   binary data already base64-decoded.
-spec parse_recv_blobs_response(string()) -> [{string(), binary(), binary(), binary()}].
parse_recv_blobs_response(RespStr) ->
    try
        %% Very basic JSON array parsing - extract objects between braces
        case re:run(RespStr, "\\{[^}]+\\}", [global, {capture, [0], list}]) of
            {match, Matches} ->
                lists:map(fun([BlobStr]) ->
                    parse_blob_object(lists:flatten(BlobStr))
                end, Matches);
            nomatch -> []
        end
    catch
        _:_ -> []
    end.

%% @doc Parse get prekey response from JSON string.
%%
%% Parses a JSON response from the `/get_prekey' endpoint to extract
%% the user's public key. The key is automatically base64-decoded.
%%
%% == Example ==
%% ```
%% JsonResp = "{\"pub\":\"base64_encoded_key_here\"}",
%% {ok, PubKey} = cryptic_client_lib:parse_get_prekey_response(JsonResp).
%% '''
%%
%% @param RespStr JSON string from `/get_prekey' endpoint
%% @returns `{ok, PublicKey}' if parsing succeeds, `{error, Reason}' if it fails.
%%   Common error reasons include `invalid_response' and `parse_error'.
-spec parse_get_prekey_response(string()) -> {ok, binary()} | {error, term()}.
parse_get_prekey_response(RespStr) ->
    try
        case re:run(RespStr, "\"pub\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]) of
            {match, [PubB64]} ->
                PubKey = base64:decode(lists:flatten(PubB64)),
                {ok, PubKey};
            nomatch ->
                {error, invalid_response}
        end
    catch
        _:_ ->
            {error, parse_error}
    end.

%% @doc Parse the JSON response from the `/list_users' endpoint.
%%
%% Parses a JSON array of usernames from the server's list_users endpoint.
%% The expected format is: `["alice", "bob", "charlie"]'
%%
%% == Example ==
%% ```
%% {ok, Users} = cryptic_client_lib:parse_users_list_response("[\"alice\",\"bob\"]"),
%% %% Users = ["alice", "bob"]
%% '''
%%
%% @param RespStr The JSON response string from the server
%% @returns `{ok, [string()]}' with list of usernames, or `{error, term()}' on parse failure
%%   Common error reasons include `invalid_response' and `parse_error'.
-spec parse_users_list_response(string()) -> {ok, [string()]} | {error, term()}.
parse_users_list_response(RespStr) ->
    try
        case string:trim(RespStr) of
            "[]" ->
                {ok, []};
            _ ->
                %% Use regex to extract all quoted strings from the JSON array
                case re:run(RespStr, "\"([^\"]+)\"", [global, {capture, [1], list}]) of
                    {match, Matches} ->
                        Users = [lists:flatten(Match) || [Match] <- Matches],
                        {ok, Users};
                    nomatch ->
                        {error, invalid_response}
                end
        end
    catch
        _:_ ->
            {error, parse_error}
    end.

%% @private
%% @doc Parse individual encrypted blob object from JSON string.
%%
%% Extracts cryptographic fields from a single JSON message object
%% and returns them as a tuple with decoded binary data.
%%
%% @param BlobStr Single JSON object string
%% @returns `{SenderId, EphemeralKey, Nonce, Cipher}' tuple with binary data
parse_blob_object(BlobStr) ->
    {match, [From]} = re:run(BlobStr, "\"from\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {match, [EphB64]} = re:run(BlobStr, "\"ephemeral\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {match, [NonceB64]} = re:run(BlobStr, "\"nonce\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {match, [CiphB64]} = re:run(BlobStr, "\"cipher\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    
    {lists:flatten(From),
     base64:decode(lists:flatten(EphB64)),
     base64:decode(lists:flatten(NonceB64)),
     base64:decode(lists:flatten(CiphB64))}.
