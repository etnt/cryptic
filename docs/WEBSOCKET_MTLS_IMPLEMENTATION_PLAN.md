# WebSocket mTLS Implementation Plan for Cryptic

## What is mTLS?

**mTLS** (mutual TLS) is a security protocol where both the client and server authenticate each other using X.509 certificates. Unlike regular TLS where only the server presents a certificate, mTLS requires the client to also provide a certificate, enabling strong bidirectional authentication without passwords or tokens.

## Overview

This plan implements **Phase 1.5: Client Certificate Authentication** from the Authentication Plan, with the following modifications:

1. **HTTP Client**: Use `gun` library instead of `httpc`
2. **Transport**: WebSocket over TLS instead of plain HTTP REST
3. **Certificate Management**: Use `myca` project for certificate generation and management
4. **Architecture**: Persistent WebSocket connections with bidirectional communication

## Architecture Overview

```
┌─────────────────┐                    ┌─────────────────┐
│   Cryptic       │                    │   Cryptic       │
│   Client        │                    │   Server        │
│                 │                    │                 │
│ ┌─────────────┐ │   WebSocket/TLS    │ ┌─────────────┐ │
│ │gun WebSocket│ │◄──────────────────►│ │cowboy_ws    │ │
│ │  Handler    │ │   + Client Cert    │ │  Handler    │ │
│ └─────────────┘ │                    │ └─────────────┘ │
│       │         │                    │       │         │
│ ┌─────────────┐ │                    │ ┌─────────────┐ │
│ │ UI/Commands │ │                    │ │ Message     │ │
│ │  Handler    │ │                    │ │ Router      │ │
│ └─────────────┘ │                    │ └─────────────┘ │
└─────────────────┘                    └─────────────────┘
        │                                       │
        │                                       │
   ┌─────────────┐                         ┌─────────────┐
   │   Client    │                         │   Server    │
   │Certificate  │                         │Certificate  │
   │(myca)       │                         │(myca)       │
   └─────────────┘                         └─────────────┘
```

## Implementation Phases

### Phase 1: Certificate Infrastructure (1-2 days)

#### 1.1 Set up myca Certificate Authority

```bash
# Initialize the CA
cd CA
make init

# Generate root CA
./scripts/gen-root-ca.sh

# Generate server certificate
./scripts/gen-server-cert.sh cryptic-server localhost 127.0.0.1

# Generate client certificates for users
./scripts/gen-client-cert.sh alice
./scripts/gen-client-cert.sh bob
./scripts/gen-client-cert.sh charlie
```

#### 1.2 Certificate Integration Script

Create `scripts/setup-certificates.sh`:

```bash
#!/bin/bash
# Setup certificates for cryptic development

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRYPTIC_ROOT="$(dirname "$SCRIPT_DIR")"
CA_DIR="$CRYPTIC_ROOT/CA"
CERT_DIR="$CRYPTIC_ROOT/priv/ssl"

echo "Setting up Cryptic certificates using myca..."

# Ensure CA directory exists and is initialized
if [ ! -d "$CA_DIR" ]; then
    echo "Error: CA directory not found. Run 'make CA' first."
    exit 1
fi

cd "$CA_DIR"

# Initialize CA if not already done
if [ ! -f "ca/private/ca.key" ]; then
    echo "Initializing Certificate Authority..."
    make init
    ./scripts/gen-root-ca.sh
fi

# Generate server certificate
echo "Generating server certificate..."
./scripts/gen-server-cert.sh cryptic-server localhost 127.0.0.1

# Generate client certificates
echo "Generating client certificates..."
for user in alice bob charlie admin; do
    echo "  - Generating certificate for: $user"
    ./scripts/gen-client-cert.sh "$user"
done

# Create cryptic ssl directory
mkdir -p "$CERT_DIR"

# Copy certificates to cryptic priv/ssl
echo "Copying certificates to cryptic/priv/ssl..."

# Server certificates
cp ca/certs/ca.crt "$CERT_DIR/"
cp server/cryptic-server.crt "$CERT_DIR/server.crt"
cp server/cryptic-server.key "$CERT_DIR/server.key"

# Client certificates
for user in alice bob charlie admin; do
    cp "client/${user}.crt" "$CERT_DIR/client_${user}.crt"
    cp "client/${user}.key" "$CERT_DIR/client_${user}.key"
    
    # Create combined PEM file for easier gun configuration
    cat "client/${user}.crt" "client/${user}.key" > "$CERT_DIR/client_${user}.pem"
done

echo "✅ Certificate setup complete!"
echo ""
echo "Server certificates:"
echo "  - CA: $CERT_DIR/ca.crt"
echo "  - Server cert: $CERT_DIR/server.crt"
echo "  - Server key: $CERT_DIR/server.key"
echo ""
echo "Client certificates:"
for user in alice bob charlie admin; do
    echo "  - ${user}: $CERT_DIR/client_${user}.pem"
done
```

### Phase 2: Server WebSocket Implementation (2-3 days)

#### 2.1 Add gun dependency and WebSocket support

Update `rebar.config`:

```erlang
{deps, [
    {cowboy, "2.9.0"},
    {ranch, "2.1.0"},
    {cowlib, "2.11.0"},
    {gun, "2.0.1"},  % Add gun for client
    {cecho, ".*", {git, "https://github.com/mazenharake/cecho.git", {branch, "master"}}}
]}.
```

#### 2.2 Create WebSocket Server Handler

Create `src/cryptic_ws_handler.erl`:

```erlang
-module(cryptic_ws_handler).
-behaviour(cowboy_websocket).

-export([init/2, websocket_init/1, websocket_handle/2, websocket_info/2]).

%% HTTP to WebSocket upgrade
init(Req, State) ->
    %% Extract client certificate information during handshake
    case get_client_identity(Req) of
        {ok, Username} ->
            io:format("Client ~s authenticated via certificate~n", [Username]),
            {cowboy_websocket, Req, #{username => Username}};
        {error, Reason} ->
            io:format("Client certificate authentication failed: ~p~n", [Reason]),
            {ok, cowboy_req:reply(401, #{}, <<"Client certificate required">>, Req), State}
    end.

%% WebSocket initialization
websocket_init(State = #{username := Username}) ->
    %% Register this connection for the user
    register_user_connection(Username, self()),
    
    %% Send welcome message
    WelcomeMsg = #{
        type => <<"welcome">>,
        message => <<"Connected to Cryptic server">>,
        username => list_to_binary(Username)
    },
    {[{text, jsx:encode(WelcomeMsg)}], State}.

%% Handle incoming WebSocket messages
websocket_handle({text, Msg}, State = #{username := Username}) ->
    try
        Command = jsx:decode(Msg, [return_maps]),
        case handle_command(Command, Username, State) of
            {reply, Response} ->
                {[{text, jsx:encode(Response)}], State};
            {reply, Response, NewState} ->
                {[{text, jsx:encode(Response)}], NewState};
            {noreply, NewState} ->
                {[], NewState};
            {error, ErrorMsg} ->
                ErrorResponse = #{
                    type => <<"error">>,
                    message => list_to_binary(ErrorMsg)
                },
                {[{text, jsx:encode(ErrorResponse)}], State}
        end
    catch
        _:Error ->
            ErrorResponse = #{
                type => <<"error">>,
                message => <<"Invalid JSON format">>
            },
            {[{text, jsx:encode(ErrorResponse)}], State}
    end;

websocket_handle({binary, _Data}, State) ->
    %% Handle binary data if needed
    {[], State};

websocket_handle(_Data, State) ->
    {[], State}.

%% Handle Erlang messages sent to this process
websocket_info({message, FromUser, Message}, State = #{username := Username}) ->
    %% Incoming message from another user
    Response = #{
        type => <<"message">>,
        from => list_to_binary(FromUser),
        to => list_to_binary(Username),
        message => Message
    },
    {[{text, jsx:encode(Response)}], State};

websocket_info(_Info, State) ->
    {[], State}.

%% Handle WebSocket commands
handle_command(#{<<"type">> := <<"upload_prekey">>, <<"prekey">> := PrekeyB64}, Username, State) ->
    try
        Prekey = base64:decode(PrekeyB64),
        case cryptic_lib:store_prekey(Username, Prekey) of
            ok ->
                {reply, #{type => <<"success">>, message => <<"Prekey uploaded">>}};
            {error, Reason} ->
                {error, io_lib:format("Failed to store prekey: ~p", [Reason])}
        end
    catch
        _:_ ->
            {error, "Invalid prekey format"}
    end;

handle_command(#{<<"type">> := <<"get_prekey">>, <<"user">> := UserB}, Username, State) ->
    User = binary_to_list(UserB),
    case cryptic_lib:get_prekey(User) of
        {ok, Prekey} ->
            Response = #{
                type => <<"prekey">>,
                user => UserB,
                prekey => base64:encode(Prekey)
            },
            {reply, Response};
        {error, not_found} ->
            {error, "User not found"}
    end;

handle_command(#{<<"type">> := <<"send_message">>, <<"to">> := ToUserB, 
                 <<"ephemeral">> := EphB64, <<"nonce">> := NonceB64, 
                 <<"cipher">> := CipherB64}, Username, State) ->
    ToUser = binary_to_list(ToUserB),
    
    %% Create message blob
    MessageBlob = #{
        from => Username,
        to => ToUser,
        ephemeral => EphB64,
        nonce => NonceB64,
        cipher => CipherB64,
        timestamp => erlang:system_time(second)
    },
    
    %% Store message
    cryptic_lib:store_message(ToUser, MessageBlob),
    
    %% Try to deliver immediately if user is online
    case find_user_connection(ToUser) of
        {ok, Pid} ->
            Pid ! {message, Username, MessageBlob};
        not_found ->
            ok  % Message stored for later retrieval
    end,
    
    {reply, #{type => <<"success">>, message => <<"Message sent">>}};

handle_command(#{<<"type">> := <<"get_messages">>}, Username, State) ->
    Messages = cryptic_lib:get_messages(Username),
    Response = #{
        type => <<"messages">>,
        messages => Messages
    },
    {reply, Response};

handle_command(#{<<"type">> := <<"list_users">>}, Username, State) ->
    Users = cryptic_lib:list_users(),
    Response = #{
        type => <<"users">>,
        users => [list_to_binary(U) || U <- Users]
    },
    {reply, Response};

handle_command(Command, Username, State) ->
    io:format("Unknown command from ~s: ~p~n", [Username, Command]),
    {error, "Unknown command"}.

%% Extract client identity from certificate
get_client_identity(Req) ->
    case cowboy_req:cert(Req) of
        undefined ->
            {error, no_client_cert};
        Cert ->
            case extract_username_from_cert(Cert) of
                {ok, Username} -> {ok, Username};
                {error, Reason} -> {error, Reason}
            end
    end.

%% Extract username from X.509 certificate Common Name
extract_username_from_cert(CertDER) ->
    try
        Cert = public_key:pkix_decode_cert(CertDER, otp),
        TBSCert = Cert#'OTPCertificate'.tbsCertificate,
        Subject = TBSCert#'OTPTBSCertificate'.subject,
        case extract_common_name(Subject) of
            {ok, CN} -> {ok, CN};
            error -> {error, no_common_name}
        end
    catch
        _:Error ->
            {error, {cert_decode_error, Error}}
    end.

%% Extract Common Name from certificate subject
extract_common_name({rdnSequence, RDNSeq}) ->
    extract_cn_from_sequence(RDNSeq).

extract_cn_from_sequence([]) ->
    error;
extract_cn_from_sequence([RDN | Rest]) ->
    case extract_cn_from_rdn(RDN) of
        {ok, CN} -> {ok, CN};
        error -> extract_cn_from_sequence(Rest)
    end.

extract_cn_from_rdn([]) ->
    error;
extract_cn_from_rdn([#'AttributeTypeAndValue'{type = ?'id-at-commonName', 
                                             value = Value} | _]) ->
    case Value of
        {utf8String, CN} -> {ok, binary_to_list(CN)};
        {printableString, CN} -> {ok, CN};
        {teletexString, CN} -> {ok, binary_to_list(CN)};
        CN when is_list(CN) -> {ok, CN};
        CN when is_binary(CN) -> {ok, binary_to_list(CN)}
    end;
extract_cn_from_rdn([_ | Rest]) ->
    extract_cn_from_rdn(Rest).

%% Connection management
register_user_connection(Username, Pid) ->
    ets:insert(user_connections, {Username, Pid}).

find_user_connection(Username) ->
    case ets:lookup(user_connections, Username) of
        [{Username, Pid}] -> {ok, Pid};
        [] -> not_found
    end.
```

#### 2.3 Update Server to Support WebSocket with mTLS

Update `src/cryptic_server.erl`:

```erlang
%% Add WebSocket mTLS server
start_websocket_mtls() ->
    start_websocket_mtls(#{}).

start_websocket_mtls(Config) ->
    application:ensure_all_started(cowboy),
    application:ensure_all_started(ssl),
    
    %% Create user connections ETS table
    ets:new(user_connections, [named_table, set, public]),
    
    Port = maps:get(port, Config, 8443),
    CertFile = maps:get(certfile, Config, "priv/ssl/server.crt"),
    KeyFile = maps:get(keyfile, Config, "priv/ssl/server.key"),
    CACertFile = maps:get(cacertfile, Config, "priv/ssl/ca.crt"),
    
    %% WebSocket route
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/ws", cryptic_ws_handler, []},
            {"/", cowboy_static, {priv_file, cryptic, "index.html"}}
        ]}
    ]),
    
    %% TLS options with client certificate verification
    TLSOptions = [
        {port, Port},
        {certfile, CertFile},
        {keyfile, KeyFile},
        {cacertfile, CACertFile},
        {verify, verify_peer},
        {fail_if_no_peer_cert, true},
        {depth, 2},
        {versions, ['tlsv1.2', 'tlsv1.3']},
        {ciphers, [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256"
        ]},
        {honor_server_cipher_order, true}
    ],
    
    {ok, _} = cowboy:start_tls(cryptic_ws_listener, TLSOptions, #{
        env => #{dispatch => Dispatch}
    }),
    
    io:format("Cryptic WebSocket server with mTLS started on port ~p~n", [Port]),
    {ok, started}.
```

### Phase 3: Client WebSocket Implementation (2-3 days)

#### 3.1 Create WebSocket Client Module

Create `src/cryptic_ws_client.erl`:

```erlang
-module(cryptic_ws_client).
-behaviour(gen_server).

-export([start_link/3, send_command/2, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    username,
    server_host,
    server_port,
    conn_pid,
    stream_ref,
    cert_file,
    key_file,
    ca_file,
    connected = false,
    pending_commands = []
}).

%% API
start_link(Username, ServerHost, CertConfig) ->
    gen_server:start_link(?MODULE, {Username, ServerHost, CertConfig}, []).

send_command(Pid, Command) ->
    gen_server:call(Pid, {send_command, Command}).

stop(Pid) ->
    gen_server:call(Pid, stop).

%% Callbacks
init({Username, ServerHost, CertConfig}) ->
    State = #state{
        username = Username,
        server_host = ServerHost,
        server_port = maps:get(port, CertConfig, 8443),
        cert_file = maps:get(cert_file, CertConfig),
        key_file = maps:get(key_file, CertConfig),
        ca_file = maps:get(ca_file, CertConfig)
    },
    {ok, State, {continue, connect}}.

handle_continue(connect, State) ->
    case connect_websocket(State) of
        {ok, NewState} ->
            {noreply, NewState};
        {error, Reason} ->
            io:format("Failed to connect: ~p~n", [Reason]),
            {stop, {connection_failed, Reason}, State}
    end.

handle_call({send_command, Command}, _From, State = #state{connected = true}) ->
    JsonCommand = jsx:encode(Command),
    gun:ws_send(State#state.conn_pid, State#state.stream_ref, {text, JsonCommand}),
    {reply, ok, State};

handle_call({send_command, Command}, _From, State = #state{connected = false}) ->
    %% Queue command until connected
    NewState = State#state{
        pending_commands = [Command | State#state.pending_commands]
    },
    {reply, queued, NewState};

handle_call(stop, _From, State) ->
    {stop, normal, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({gun_upgrade, ConnPid, StreamRef, [<<"websocket">>], _Headers}, 
            State = #state{conn_pid = ConnPid, stream_ref = StreamRef}) ->
    io:format("WebSocket connection established for ~s~n", [State#state.username]),
    
    %% Send any pending commands
    lists:foreach(fun(Command) ->
        JsonCommand = jsx:encode(Command),
        gun:ws_send(ConnPid, StreamRef, {text, JsonCommand})
    end, lists:reverse(State#state.pending_commands)),
    
    {noreply, State#state{connected = true, pending_commands = []}};

handle_info({gun_ws, _ConnPid, _StreamRef, {text, Data}}, State) ->
    case jsx:decode(Data, [return_maps]) of
        Message = #{<<"type">> := Type} ->
            handle_server_message(Type, Message, State);
        _ ->
            io:format("Invalid message format: ~s~n", [Data]),
            {noreply, State}
    end;

handle_info({gun_ws, _ConnPid, _StreamRef, {close, Code, Reason}}, State) ->
    io:format("WebSocket closed: ~p ~s~n", [Code, Reason]),
    {noreply, State#state{connected = false}};

handle_info({gun_error, _ConnPid, _StreamRef, Reason}, State) ->
    io:format("WebSocket error: ~p~n", [Reason]),
    {noreply, State#state{connected = false}};

handle_info({gun_down, ConnPid, _Protocol, Reason, _KilledStreams}, 
            State = #state{conn_pid = ConnPid}) ->
    io:format("Connection down: ~p~n", [Reason]),
    {noreply, State#state{connected = false}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{conn_pid = ConnPid}) when ConnPid =/= undefined ->
    gun:close(ConnPid);
terminate(_Reason, _State) ->
    ok.

%% Internal functions
connect_websocket(State) ->
    application:ensure_all_started(gun),
    
    %% TLS options with client certificate
    TLSOptions = [
        {verify, verify_peer},
        {cacertfile, State#state.ca_file},
        {certfile, State#state.cert_file},
        {keyfile, State#state.key_file},
        {versions, ['tlsv1.2', 'tlsv1.3']},
        {alpn_preferred_protocols, [<<"http/1.1">>]}
    ],
    
    ConnOpts = #{
        transport => tls,
        tls_opts => TLSOptions,
        protocols => [http]
    },
    
    case gun:open(State#state.server_host, State#state.server_port, ConnOpts) of
        {ok, ConnPid} ->
            case gun:await_up(ConnPid, 5000) of
                {ok, _Protocol} ->
                    StreamRef = gun:ws_upgrade(ConnPid, "/ws"),
                    NewState = State#state{
                        conn_pid = ConnPid,
                        stream_ref = StreamRef
                    },
                    {ok, NewState};
                {error, Reason} ->
                    gun:close(ConnPid),
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

handle_server_message(<<"welcome">>, Message, State) ->
    io:format("Server welcome: ~s~n", [maps:get(<<"message">>, Message, <<"Unknown">>)]),
    {noreply, State};

handle_server_message(<<"message">>, Message, State) ->
    From = maps:get(<<"from">>, Message),
    MessageContent = maps:get(<<"message">>, Message),
    io:format("Message from ~s: ~p~n", [From, MessageContent]),
    %% Forward to UI or message handler
    cryptic_cecho_ui:handle_incoming_message(From, MessageContent),
    {noreply, State};

handle_server_message(<<"error">>, Message, State) ->
    ErrorMsg = maps:get(<<"message">>, Message, <<"Unknown error">>),
    io:format("Server error: ~s~n", [ErrorMsg]),
    {noreply, State};

handle_server_message(Type, Message, State) ->
    io:format("Unknown message type ~s: ~p~n", [Type, Message]),
    {noreply, State}.
```

#### 3.2 Update Client Library for WebSocket

Create `src/cryptic_ws_client_lib.erl`:

```erlang
-module(cryptic_ws_client_lib).
-export([
    start_client/3,
    upload_prekey/3,
    get_prekey/3,
    send_encrypted_message/6,
    get_messages/2,
    list_users/2
]).

-record(client_state, {
    ws_client_pid,
    username,
    keypair
}).

%% Start WebSocket client with certificate authentication
start_client(Username, ServerHost, CertConfig) ->
    case cryptic_ws_client:start_link(Username, ServerHost, CertConfig) of
        {ok, Pid} ->
            {ok, #client_state{
                ws_client_pid = Pid,
                username = Username
            }};
        {error, Reason} ->
            {error, Reason}
    end.

%% Upload prekey via WebSocket
upload_prekey(ClientState, Username, PublicKey) ->
    Command = #{
        type => <<"upload_prekey">>,
        username => list_to_binary(Username),
        prekey => base64:encode(PublicKey)
    },
    cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, Command).

%% Get user's prekey via WebSocket
get_prekey(ClientState, Username, TargetUser) ->
    Command = #{
        type => <<"get_prekey">>,
        user => list_to_binary(TargetUser)
    },
    cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, Command).

%% Send encrypted message via WebSocket  
send_encrypted_message(ClientState, FromUser, ToUser, EphPub, Nonce, Cipher) ->
    Command = #{
        type => <<"send_message">>,
        from => list_to_binary(FromUser),
        to => list_to_binary(ToUser),
        ephemeral => base64:encode(EphPub),
        nonce => base64:encode(Nonce),
        cipher => base64:encode(Cipher)
    },
    cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, Command).

%% Get messages via WebSocket
get_messages(ClientState, Username) ->
    Command = #{
        type => <<"get_messages">>
    },
    cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, Command).

%% List users via WebSocket
list_users(ClientState, Username) ->
    Command = #{
        type => <<"list_users">>
    },
    cryptic_ws_client:send_command(ClientState#client_state.ws_client_pid, Command).
```

### Phase 4: UI Integration (1-2 days)

#### 4.1 Update Terminal UI for WebSocket

Update `src/cryptic_cecho_ui.erl`:

```erlang
%% Add WebSocket client support
start_with_certificate(ServerHost, CertFile) ->
    %% Extract username from certificate
    Username = extract_username_from_cert_file(CertFile),
    
    %% Setup certificate configuration
    CertConfig = #{
        cert_file => CertFile,
        key_file => string:replace(CertFile, ".crt", ".key"),
        ca_file => "priv/ssl/ca.crt",
        port => 8443
    },
    
    %% Start WebSocket client
    case cryptic_ws_client_lib:start_client(Username, ServerHost, CertConfig) of
        {ok, ClientState} ->
            %% Generate and upload prekey
            {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
            cryptic_ws_client_lib:upload_prekey(ClientState, Username, PubKey),
            
            %% Start UI with WebSocket client
            start_ui_with_websocket(ClientState, Username, {PubKey, PrivKey});
        {error, Reason} ->
            io:format("Failed to start WebSocket client: ~p~n", [Reason]),
            {error, Reason}
    end.

%% Handle incoming WebSocket messages from UI
handle_incoming_message(From, MessageBlob) ->
    %% Decode and decrypt message
    %% Update UI with new message
    %% This will be called by the WebSocket client
    ok.
```

### Phase 5: Testing and Integration (1-2 days)

#### 5.1 Create Test Scripts

Create `scripts/test-websocket-mtls.sh`:

```bash
#!/bin/bash
# Test WebSocket mTLS functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRYPTIC_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Testing Cryptic WebSocket mTLS..."

# 1. Setup certificates
echo "Setting up certificates..."
$SCRIPT_DIR/setup-certificates.sh

# 2. Start server
echo "Starting WebSocket mTLS server..."
cd "$CRYPTIC_ROOT"
erl -pa _build/default/lib/*/ebin -eval "
    cryptic_server:start_websocket_mtls(),
    timer:sleep(infinity).
" -noshell &
SERVER_PID=$!

# Wait for server to start
sleep 3

# 3. Test client connections
echo "Testing client connections..."

# Test Alice
erl -pa _build/default/lib/*/ebin -eval "
    cryptic_cecho_ui:start_with_certificate(\"localhost\", \"priv/ssl/client_alice.crt\"),
    timer:sleep(5000),
    halt().
" -noshell &

# Test Bob  
erl -pa _build/default/lib/*/ebin -eval "
    cryptic_cecho_ui:start_with_certificate(\"localhost\", \"priv/ssl/client_bob.crt\"),
    timer:sleep(5000),
    halt().
" -noshell &

wait

# 4. Cleanup
echo "Cleaning up..."
kill $SERVER_PID 2>/dev/null || true

echo "✅ WebSocket mTLS test complete!"
```

## Benefits of This Approach

### 1. **Persistent Connections**
- Real-time bidirectional communication
- Lower latency than HTTP polling
- Efficient for chat applications

### 2. **Strong Authentication**
- Certificate-based identity verification
- No passwords or tokens to manage
- Authentication happens at TLS layer

### 3. **Professional Certificate Management**
- Uses established `myca` project
- Proper CA hierarchy
- Standard X.509 certificate handling

### 4. **Modern HTTP Client**
- `gun` library provides HTTP/2 and WebSocket support
- Better connection pooling and management
- More efficient than `httpc`

### 5. **Bidirectional Protocol**
- Server can push messages to clients
- Real-time notifications
- Better user experience

## Security Considerations

### 1. **Transport Security**
- TLS 1.2/1.3 encryption
- Perfect Forward Secrecy
- Strong cipher suites

### 2. **Authentication**
- X.509 client certificates
- CA-signed certificates
- Certificate revocation support (via myca)

### 3. **Message Security**
- End-to-end encryption still maintained
- Certificate auth is orthogonal to message encryption
- Defense in depth

## Implementation Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| **Phase 1** | 1-2 days | Certificate infrastructure setup |
| **Phase 2** | 2-3 days | WebSocket server implementation |
| **Phase 3** | 2-3 days | WebSocket client implementation |
| **Phase 4** | 1-2 days | UI integration |
| **Phase 5** | 1-2 days | Testing and debugging |
| **Total** | **7-12 days** | Complete implementation |

## Dependencies

### New Dependencies to Add
```erlang
{deps, [
    {cowboy, "2.9.0"},      % Existing
    {ranch, "2.1.0"},       % Existing  
    {cowlib, "2.11.0"},     % Existing
    {gun, "2.0.1"},         % NEW: HTTP/2 and WebSocket client
    {jsx, "3.1.0"},         % NEW: JSON encoding/decoding
    {cecho, ".*", {git, "https://github.com/mazenharake/cecho.git", {branch, "master"}}} % Existing
]}.
```

### External Tools
- `myca` (already cloned in CA/)
- OpenSSL (for certificate operations)

This plan provides a comprehensive, modern approach to implementing client certificate authentication with WebSocket transport, leveraging the existing `gunsmoke` and `myca` projects for proven patterns and certificate management.
