# Authentication and Access Control Plan for Cryptic

## Current State Analysis

### Security Gap
Currently, the Cryptic chat system allows **anyone** to register by simply calling:
```bash
register <username>
```

This creates significant security risks:
- **No identity verification**: Anyone can claim any username
- **No access control**: Malicious actors can join conversations
- **No accountability**: Messages cannot be reliably attributed to real users
- **No user management**: No way to revoke access or manage permissions

## Authentication Strategy Overview

We propose implementing a **multi-layered authentication system** that balances security, usability, and implementation complexity:

1. **Pre-shared Key (PSK) Authentication** - Simple, immediate solution
2. **JWT-based Token Authentication** - Modern, scalable approach  
3. **Ed25519 Digital Signatures** - Cryptographically strong identity verification
4. **Optional: Hardware Security Key Support** - Enterprise-grade security

## Phase 1: Pre-Shared Key Authentication (Quick Win)

### Implementation Effort: **LOW** (1-2 days)

**Concept**: Users must provide a pre-shared secret to register.

### ⚠️ CRITICAL SECURITY REQUIREMENT: SSL/TLS

**PSK authentication REQUIRES SSL/TLS encryption** because:
- **Tokens transmitted in plaintext** over HTTP can be intercepted
- **Man-in-the-middle attacks** can capture authentication tokens
- **Network eavesdropping** exposes all authentication credentials

```bash
# INSECURE - tokens visible to network attackers
curl -X POST http://localhost:8080/upload_prekey \
  -d '{"user_id":"alice","prekey":"...","auth_token":"secret_alice_2024"}'
  
# SECURE - tokens encrypted in transit  
curl -X POST https://localhost:8443/upload_prekey \
  -d '{"user_id":"alice","prekey":"...","auth_token":"secret_alice_2024"}'
```

### SSL/TLS Server Configuration

```erlang
%% Enhanced cryptic_server.erl with HTTPS support
start_https(CfgMap) ->
    application:ensure_all_started(ssl),
    
    %% HTTP server (redirect to HTTPS)
    HttpDispatch = cowboy_router:compile([
        {'_', [
            {"/[...]", redirect_to_https_handler, []}
        ]}
    ]),
    {ok, _} = cowboy:start_clear(http_listener,
        [{port, maps:get(http_port, CfgMap, 8080)}],
        #{env => #{dispatch => HttpDispatch}}),
    
    %% HTTPS server with TLS
    HttpsDispatch = cowboy_router:compile([
        {'_', [
            {"/upload_prekey/:user_id", cryptic_handlers, upload_prekey},
            {"/get_prekey/:user_id", cryptic_handlers, get_prekey},
            {"/send_blob", cryptic_handlers, send_blob},
            {"/recv_blobs/:user_id", cryptic_handlers, recv_blobs},
            {"/peek_messages/:user_id", cryptic_handlers, peek_messages},
            {"/list_users", cryptic_handlers, list_users}
        ]}
    ]),
    
    %% TLS options
    TlsOpts = [
        {certfile, maps:get(certfile, CfgMap, "priv/ssl/server.crt")},
        {keyfile, maps:get(keyfile, CfgMap, "priv/ssl/server.key")},
        {versions, ['tlsv1.2', 'tlsv1.3']},
        {ciphers, [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256", 
            "TLS_AES_128_GCM_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384"
        ]},
        {honor_server_cipher_order, true}
    ],
    
    {ok, _} = cowboy:start_tls(https_listener,
        [{port, maps:get(https_port, CfgMap, 8443)}] ++ TlsOpts,
        #{env => #{dispatch => HttpsDispatch}}),
        
    io:format("HTTPS server started on port ~p~n", 
              [maps:get(https_port, CfgMap, 8443)]).

%% Redirect HTTP to HTTPS
-module(redirect_to_https_handler).
-behaviour(cowboy_handler).

init(Req, State) ->
    Host = cowboy_req:host(Req),
    Path = cowboy_req:path(Req),
    HttpsUrl = <<"https://", Host/binary, ":8443", Path/binary>>,
    
    Req2 = cowboy_req:reply(301, 
        #{<<"location">> => HttpsUrl}, 
        <<"Redirecting to HTTPS">>, Req),
    {ok, Req2, State}.
```

### Self-Signed Certificate Generation (Development)

```bash
# Generate development certificates
mkdir -p priv/ssl

# Create private key
openssl genrsa -out priv/ssl/server.key 2048

# Create certificate signing request
openssl req -new -key priv/ssl/server.key -out priv/ssl/server.csr \
  -subj "/C=US/ST=Dev/L=Dev/O=Cryptic/CN=localhost"

# Create self-signed certificate
openssl x509 -req -days 365 -in priv/ssl/server.csr \
  -signkey priv/ssl/server.key -out priv/ssl/server.crt

# Clean up CSR
rm priv/ssl/server.csr
```

### Production Certificate Setup

```bash
# For production, use Let's Encrypt or commercial CA
# Example with certbot:
certbot certonly --standalone -d your-cryptic-server.com

# Copy certificates to Erlang app
cp /etc/letsencrypt/live/your-domain/fullchain.pem priv/ssl/server.crt
cp /etc/letsencrypt/live/your-domain/privkey.pem priv/ssl/server.key
```

### Server-Side Changes
```erlang
%% In cryptic_handlers.erl
init(Req = #{method := <<"POST">>}, upload_prekey) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    case parse_prekey_with_auth(Body) of
        {ok, UserId, PubKey, AuthToken} ->
            case validate_auth_token(UserId, AuthToken) of
                true ->
                    %% Proceed with existing registration logic
                    store_prekey(UserId, PubKey),
                    {ok, cowboy_req:reply(200, #{}, <<"OK">>, Req1), state};
                false ->
                    ErrorResp = <<"{\"error\":\"invalid_auth_token\"}">>,
                    {ok, cowboy_req:reply(401, 
                        #{<<"content-type">> => <<"application/json">>}, 
                        ErrorResp, Req1), state}
            end;
        {error, _} ->
            %% Return auth error
            ErrorResp = <<"{\"error\":\"authentication_required\"}">>,
            {ok, cowboy_req:reply(401, 
                #{<<"content-type">> => <<"application/json">>}, 
                ErrorResp, Req1), state}
    end.

%% Simple PSK validation
validate_auth_token(UserId, AuthToken) ->
    %% In production: load from secure config or database
    ValidTokens = #{
        "alice" => "secret_alice_2024",
        "bob" => "secret_bob_2024",
        "charlie" => "secret_charlie_2024"
    },
    case maps:get(UserId, ValidTokens, undefined) of
        AuthToken -> true;
        _ -> false
    end.
```

### Client-Side Changes
```erlang
%% In cryptic_client_lib.erl
upload_prekey_with_auth(ServerUrl, UserId, PublicKey, AuthToken) ->
    AuthBody = #{
        <<"user_id">> => list_to_binary(UserId),
        <<"prekey">> => base64:encode(PublicKey),
        <<"auth_token">> => list_to_binary(AuthToken)
    },
    JsonBody = json:encode(AuthBody),
    %% Rest of HTTP request logic...
```

### UI Changes  
```erlang
%% In cryptic_cecho_ui.erl
process_command("register " ++ Username, UIState) ->
    %% Prompt for authentication token
    case get_auth_token_from_user() of
        {ok, AuthToken} ->
            %% Proceed with authenticated registration
            case cryptic_client_lib:upload_prekey_with_auth(
                ServerUrl, Username, PubKey, AuthToken) of
                ok -> add_system_message("Successfully registered!", UIState);
                {error, auth_failed} -> 
                    add_system_message("Authentication failed. Invalid token.", UIState)
            end;
        cancelled ->
            add_system_message("Registration cancelled.", UIState)
    end.
```

### Configuration Management
```erlang
%% New module: cryptic_auth_config.erl
-module(cryptic_auth_config).
-export([load_auth_tokens/0, is_valid_token/2]).

load_auth_tokens() ->
    %% Load from environment variable or config file
    case os:getenv("CRYPTIC_AUTH_TOKENS") of
        false ->
            %% Default tokens for development
            #{
                "alice" => "dev_token_alice",
                "bob" => "dev_token_bob"
            };
        TokensJson ->
            %% Parse JSON configuration
            json:decode(TokensJson)
    end.
```

### Pros and Cons
**Pros:**
- ✅ Quick to implement (1-2 days)
- ✅ Immediately prevents unauthorized access
- ✅ Simple to deploy and configure
- ✅ No external dependencies

**Cons:**
- ❌ **REQUIRES SSL/TLS** - tokens sent in plaintext otherwise
- ❌ Shared secrets are hard to manage securely
- ❌ No automatic token rotation
- ❌ Tokens could be intercepted if SSL is compromised
- ❌ No fine-grained permissions

## Phase 1.5: SSL Client Certificates (Mutual TLS Authentication)

### Implementation Effort: **MEDIUM** (2-4 days)

**Concept**: Use X.509 client certificates for mutual TLS authentication - the TLS layer itself handles authentication.

### ✅ TRANSPORT SECURITY: Built-in SSL/TLS

**SSL client certificates PROVIDE BOTH authentication AND encryption** because:
- **Authentication happens during TLS handshake** - no application-layer auth needed
- **Client identity verified cryptographically** by the TLS stack
- **No passwords or tokens** - certificate-based authentication
- **Mutual authentication** - both client and server verify each other

```bash
# Client connects with certificate - authentication is automatic
curl --cert client.crt --key client.key \
     --cacert server.crt \
     https://localhost:8443/upload_prekey/alice

# Server automatically knows the client identity from the certificate
# No additional authentication headers or tokens needed!
```

### Server-Side Implementation

```erlang
%% Enhanced cryptic_server.erl with client certificate authentication
start_mtls(CfgMap) ->
    application:ensure_all_started(ssl),
    
    %% mTLS configuration requiring client certificates
    TlsOpts = [
        {certfile, maps:get(certfile, CfgMap, "priv/ssl/server.crt")},
        {keyfile, maps:get(keyfile, CfgMap, "priv/ssl/server.key")},
        {cacertfile, maps:get(cacertfile, CfgMap, "priv/ssl/ca.crt")}, % CA for client certs
        
        %% Require client certificates
        {verify, verify_peer},
        {fail_if_no_peer_cert, true},
        
        %% TLS versions and ciphers
        {versions, ['tlsv1.2', 'tlsv1.3']},
        {ciphers, [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384"
        ]},
        {honor_server_cipher_order, true},
        
        %% Custom certificate verification
        {verify_fun, {fun verify_client_cert/3, []}}
    ],
    
    HttpsDispatch = cowboy_router:compile([
        {'_', [
            {"/upload_prekey/:user_id", cryptic_mtls_handlers, upload_prekey},
            {"/get_prekey/:user_id", cryptic_mtls_handlers, get_prekey},
            {"/send_blob", cryptic_mtls_handlers, send_blob},
            {"/recv_blobs/:user_id", cryptic_mtls_handlers, recv_blobs},
            {"/peek_messages/:user_id", cryptic_mtls_handlers, peek_messages},
            {"/list_users", cryptic_mtls_handlers, list_users}
        ]}
    ]),
    
    {ok, _} = cowboy:start_tls(mtls_listener,
        [{port, maps:get(mtls_port, CfgMap, 8443)}] ++ TlsOpts,
        #{env => #{dispatch => HttpsDispatch}}),
        
    io:format("mTLS server started on port ~p~n", 
              [maps:get(mtls_port, CfgMap, 8443)]).

%% Custom client certificate verification
verify_client_cert(Cert, valid_peer, UserState) ->
    %% Extract subject from certificate
    Subject = public_key:pkix_decode_cert(Cert, otp),
    TBSCert = Subject#'OTPCertificate'.tbsCertificate,
    SubjectName = TBSCert#'OTPTBSCertificate'.subject,
    
    %% Extract Common Name (CN) from subject
    case extract_common_name(SubjectName) of
        {ok, Username} ->
            %% Check if user is authorized
            case is_authorized_user(Username) of
                true ->
                    %% Store username for handler access
                    {valid, [{client_username, Username} | UserState]};
                false ->
                    {fail, "User not authorized"}
            end;
        {error, no_cn} ->
            {fail, "Certificate missing Common Name"}
    end;
verify_client_cert(_Cert, valid, UserState) ->
    {valid, UserState};
verify_client_cert(_Cert, _Event, _UserState) ->
    {fail, "Certificate validation failed"}.

%% Extract Common Name from X.509 subject
extract_common_name({rdnSequence, RDNSequence}) ->
    case find_cn_attribute(RDNSequence) of
        {ok, CN} -> {ok, unicode:characters_to_list(CN)};
        error -> {error, no_cn}
    end.

find_cn_attribute([]) ->
    error;
find_cn_attribute([RDN | Rest]) ->
    case find_cn_in_rdn(RDN) of
        {ok, CN} -> {ok, CN};
        error -> find_cn_attribute(Rest)
    end.

find_cn_in_rdn([]) ->
    error;
find_cn_in_rdn([#'AttributeTypeAndValue'{type = ?'id-at-commonName', 
                                        value = {utf8String, CN}} | _]) ->
    {ok, CN};
find_cn_in_rdn([#'AttributeTypeAndValue'{type = ?'id-at-commonName', 
                                        value = {printableString, CN}} | _]) ->
    {ok, CN};
find_cn_in_rdn([_ | Rest]) ->
    find_cn_in_rdn(Rest).

%% Simple authorization check (extend as needed)
is_authorized_user(Username) ->
    AuthorizedUsers = ["alice", "bob", "charlie", "admin"],
    lists:member(Username, AuthorizedUsers).
```

### Enhanced Request Handlers

```erlang
%% New module: cryptic_mtls_handlers.erl
-module(cryptic_mtls_handlers).
-behaviour(cowboy_handler).

init(Req = #{method := <<"POST">>}, upload_prekey) ->
    %% Extract client identity from TLS connection
    case get_client_identity(Req) of
        {ok, ClientUsername} ->
            %% Client is already authenticated by TLS!
            %% Verify they're trying to register as themselves
            RequestedUser = cowboy_req:binding(user_id, Req),
            case binary_to_list(RequestedUser) of
                ClientUsername ->
                    %% Proceed with prekey upload
                    process_prekey_upload(Req, ClientUsername);
                OtherUser ->
                    %% Client trying to register as different user
                    ErrorResp = <<"{\"error\":\"cannot_register_as_different_user\"}">>,
                    {ok, cowboy_req:reply(403, 
                        #{<<"content-type">> => <<"application/json">>}, 
                        ErrorResp, Req), state}
            end;
        {error, no_client_cert} ->
            ErrorResp = <<"{\"error\":\"client_certificate_required\"}">>,
            {ok, cowboy_req:reply(401, 
                #{<<"content-type">> => <<"application/json">>}, 
                ErrorResp, Req), state}
    end.

%% Extract authenticated client identity from TLS connection
get_client_identity(Req) ->
    case cowboy_req:cert(Req) of
        undefined ->
            {error, no_client_cert};
        Cert ->
            %% Certificate was already verified during TLS handshake
            %% Extract username from certificate subject
            case extract_username_from_cert(Cert) of
                {ok, Username} -> {ok, Username};
                {error, Reason} -> {error, Reason}
            end
    end.
```

### Certificate Generation and Management

```bash
#!/bin/bash
# scripts/generate-mtls-certs.sh

echo "Generating mTLS certificates for Cryptic..."

mkdir -p priv/ssl

# 1. Generate CA private key
openssl genrsa -out priv/ssl/ca.key 4096

# 2. Generate CA certificate
openssl req -new -x509 -days 3650 -key priv/ssl/ca.key -out priv/ssl/ca.crt \
  -subj "/C=US/ST=Dev/L=Dev/O=Cryptic CA/CN=Cryptic Root CA"

# 3. Generate server private key
openssl genrsa -out priv/ssl/server.key 2048

# 4. Generate server certificate signing request
openssl req -new -key priv/ssl/server.key -out priv/ssl/server.csr \
  -subj "/C=US/ST=Dev/L=Dev/O=Cryptic/CN=localhost"

# 5. Generate server certificate signed by CA
openssl x509 -req -days 365 -in priv/ssl/server.csr \
  -CA priv/ssl/ca.crt -CAkey priv/ssl/ca.key -CAcreateserial \
  -out priv/ssl/server.crt

# 6. Generate client certificates for users
for user in alice bob charlie admin; do
    echo "Generating client certificate for: $user"
    
    # Client private key
    openssl genrsa -out "priv/ssl/client_${user}.key" 2048
    
    # Client certificate signing request
    openssl req -new -key "priv/ssl/client_${user}.key" \
      -out "priv/ssl/client_${user}.csr" \
      -subj "/C=US/ST=Dev/L=Dev/O=Cryptic/CN=${user}"
    
    # Client certificate signed by CA
    openssl x509 -req -days 365 -in "priv/ssl/client_${user}.csr" \
      -CA priv/ssl/ca.crt -CAkey priv/ssl/ca.key -CAcreateserial \
      -out "priv/ssl/client_${user}.crt"
    
    # Clean up CSR
    rm "priv/ssl/client_${user}.csr"
    
    # Create client bundle for easy distribution
    cat "priv/ssl/client_${user}.crt" "priv/ssl/client_${user}.key" \
      > "priv/ssl/client_${user}.pem"
done

# Clean up
rm priv/ssl/server.csr
rm priv/ssl/ca.srl

echo "✅ mTLS certificates generated!"
echo ""
echo "Server files:"
echo "  - priv/ssl/ca.crt (Certificate Authority)"
echo "  - priv/ssl/server.crt (Server certificate)"
echo "  - priv/ssl/server.key (Server private key)"
echo ""
echo "Client files (distribute to users):"
for user in alice bob charlie admin; do
    echo "  - priv/ssl/client_${user}.pem (${user}'s client certificate + key)"
done
```

### Client-Side mTLS Support

```erlang
%% Enhanced cryptic_client_lib.erl with client certificate support
init_client_mtls(ClientCertFile, ClientKeyFile, CACertFile) ->
    application:ensure_all_started(inets),
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),
    
    %% Configure HTTPS client with client certificate
    httpc:set_options([{socket_opts, [
        %% Client certificate for authentication
        {certfile, ClientCertFile},
        {keyfile, ClientKeyFile},
        
        %% Server verification
        {verify, verify_peer},
        {cacertfile, CACertFile},
        {depth, 3},
        
        %% TLS configuration
        {versions, ['tlsv1.2', 'tlsv1.3']},
        {ciphers, ssl:cipher_suites(default, 'tlsv1.3')}
    ]}]).

%% Upload prekey with mTLS authentication
upload_prekey_mtls(ServerUrl, UserId, PublicKey) ->
    %% No authentication token needed - certificate provides identity
    Url = lists:flatten(io_lib:format("~s/upload_prekey/~s", [ServerUrl, UserId])),
    
    Body = #{
        <<"user_id">> => list_to_binary(UserId),
        <<"prekey">> => base64:encode(PublicKey)
        %% No auth_token needed - mTLS handles authentication
    },
    JsonBody = json:encode(Body),
    
    case httpc:request(post, {Url, [], "application/json", JsonBody}, 
                      [{timeout, 10000}], []) of
        {ok, {{_, 200, _}, _, _}} ->
            ok;
        {ok, {{_, 401, _}, _, Body}} ->
            {error, {auth_failed, "Client certificate required or invalid"}};
        {ok, {{_, 403, _}, _, Body}} ->
            {error, {forbidden, "Certificate valid but access denied"}};
        {ok, {{_, StatusCode, _}, _, ErrorBody}} ->
            {error, {http_error, StatusCode, ErrorBody}};
        {error, Reason} ->
            {error, {connection_failed, Reason}}
    end.
```

### Terminal UI Integration

```erlang
%% Enhanced cryptic_cecho_ui.erl for mTLS
start_mtls(ServerUrl, ClientCertFile) ->
    %% Initialize mTLS client
    ClientKeyFile = string:replace(ClientCertFile, ".pem", ".key"),
    CACertFile = "priv/ssl/ca.crt",
    
    cryptic_client_lib:init_client_mtls(ClientCertFile, ClientKeyFile, CACertFile),
    
    %% Extract username from certificate
    {ok, Username} = extract_username_from_cert_file(ClientCertFile),
    
    %% Start UI with pre-authenticated user
    start_with_user(ServerUrl, Username).

%% Simplified registration - no manual username entry needed
process_mtls_registration(UIState, Username) ->
    %% User identity comes from certificate - no username prompt needed
    ChatState = UIState#ui_state.chat_state,
    {PubKey, PrivKey} = cryptic_lib:gen_keypair(),
    
    case cryptic_client_lib:upload_prekey_mtls(
        ChatState#chat_state.server_url, Username, PubKey) of
        ok ->
            NewChatState = ChatState#chat_state{
                current_user = Username,
                keypair = {PubKey, PrivKey}
            },
            NewUIState = UIState#ui_state{chat_state = NewChatState},
            add_system_message("Successfully registered via mTLS certificate!", NewUIState);
        {error, Reason} ->
            ErrMsg = io_lib:format("mTLS registration failed: ~p", [Reason]),
            add_system_message(lists:flatten(ErrMsg), UIState)
    end.
```

### Pros and Cons

**Pros:**
- ✅ **Authentication built into TLS layer** - no application-layer auth needed
- ✅ **Mutual authentication** - both client and server verify each other
- ✅ **No passwords or tokens** to manage or steal
- ✅ **Strong cryptographic identity** based on X.509 PKI
- ✅ **Zero application changes** needed for basic auth (handled by TLS)
- ✅ **Enterprise-friendly** - integrates with existing PKI infrastructure
- ✅ **Non-repudiation** - certificate signatures prove identity
- ✅ **Granular access control** - different certificates for different users/roles

**Cons:**
- ❌ **Certificate management complexity** - PKI infrastructure required
- ❌ **Certificate distribution** - need secure way to distribute client certs
- ❌ **Certificate revocation** - need CRL or OCSP for revocation
- ❌ **Client setup complexity** - users must install and configure certificates
- ❌ **Certificate expiration** - need renewal processes
- ❌ **Browser integration** - more complex for web clients
- ❌ **Backup/recovery** - losing certificate = losing access

### Use Cases

**Perfect for:**
- Enterprise environments with existing PKI
- High-security deployments requiring mutual authentication
- Automated systems and API clients
- Environments where certificate management is already established

**Not ideal for:**
- Consumer applications (too complex for end users)
- Rapid prototyping (certificate setup overhead)
- Mobile applications (certificate storage challenges)
- Large-scale public deployments (PKI management overhead)

## Phase 2: JWT-Based Authentication (Modern Solution)

### Implementation Effort: **MEDIUM** (3-5 days)

**Concept**: Users authenticate with username/password to receive signed JWT tokens.

### ⚠️ CRITICAL SECURITY REQUIREMENT: SSL/TLS

**JWT authentication ABSOLUTELY REQUIRES SSL/TLS** because:
- **Bearer tokens** in Authorization headers are plaintext without TLS
- **Login credentials** (username/password) must be encrypted in transit
- **Token theft** over unencrypted connections compromises accounts
- **Session hijacking** becomes trivial without transport encryption

```bash
# INSECURE - credentials and tokens visible to attackers
curl -X POST http://localhost:8080/auth/login \
  -d '{"username":"alice","password":"secret123"}'
  
# Response: {"token":"eyJ0eXAiOiJKV1QiLCJhbGc..."} # EXPOSED!

# SECURE - all data encrypted
curl -X POST https://localhost:8443/auth/login \
  -d '{"username":"alice","password":"secret123"}' \
  -H "Content-Type: application/json"
```

### JWT Token Structure
```json
{
  "iss": "cryptic-chat-server",
  "sub": "alice",
  "exp": 1640995200,
  "iat": 1640908800,
  "permissions": ["chat", "register"],
  "groups": ["developers", "admins"]
}
```

### Enhanced Client Configuration

```erlang
%% Updated cryptic_client_lib.erl with HTTPS support
-module(cryptic_client_lib).

init_client() ->
    application:ensure_all_started(inets),
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),
    
    %% Configure HTTPS client options
    httpc:set_options([
        {https_proxy, undefined},
        {proxy, undefined}
    ]),
    
    %% For development with self-signed certs (INSECURE for production!)
    ssl:start(),
    httpc:set_options([{socket_opts, [
        {verify, verify_none},  % ONLY for development!
        {versions, ['tlsv1.2', 'tlsv1.3']}
    ]}]).

%% Production HTTPS client (verify certificates)
init_client_production() ->
    application:ensure_all_started(inets),
    application:ensure_all_started(crypto), 
    application:ensure_all_started(ssl),
    
    %% Configure secure HTTPS client
    httpc:set_options([{socket_opts, [
        {verify, verify_peer},
        {cacertfile, "/etc/ssl/certs/ca-certificates.crt"}, % System CA bundle
        {depth, 3},
        {versions, ['tlsv1.2', 'tlsv1.3']},
        {ciphers, ssl:cipher_suites(default, 'tlsv1.3')}
    ]}]).

upload_prekey_with_auth(ServerUrl, UserId, PublicKey, AuthToken) ->
    %% Ensure HTTPS URL
    HttpsUrl = ensure_https_url(ServerUrl),
    Url = lists:flatten(io_lib:format("~s/upload_prekey/~s", [HttpsUrl, UserId])),
    
    AuthBody = #{
        <<"user_id">> => list_to_binary(UserId),
        <<"prekey">> => base64:encode(PublicKey), 
        <<"auth_token">> => list_to_binary(AuthToken)
    },
    JsonBody = json:encode(AuthBody),
    
    case httpc:request(post, {Url, [], "application/json", JsonBody}, 
                      [{timeout, 10000}], []) of
        {ok, {{_, 200, _}, _, _}} ->
            ok;
        {ok, {{_, 401, _}, _, Body}} ->
            {error, {auth_failed, Body}};
        {ok, {{_, StatusCode, _}, _, Body}} ->
            {error, {http_error, StatusCode, Body}};
        {error, Reason} ->
            {error, {connection_failed, Reason}}
    end.

%% Ensure URL uses HTTPS
ensure_https_url("http://" ++ Rest) ->
    "https://" ++ Rest;
ensure_https_url("https://" ++ _Rest = Url) ->
    Url;
ensure_https_url(Url) ->
    "https://" ++ Url.
```

### Server Implementation
```erlang
%% New module: cryptic_auth_jwt.erl
-module(cryptic_auth_jwt).
-export([login/2, validate_token/1, generate_token/2]).

login(Username, Password) ->
    case validate_credentials(Username, Password) of
        {ok, UserInfo} ->
            Token = generate_token(Username, UserInfo),
            {ok, Token};
        {error, invalid_credentials} ->
            {error, authentication_failed}
    end.

generate_token(Username, UserInfo) ->
    Claims = #{
        <<"iss">> => <<"cryptic-chat-server">>,
        <<"sub">> => list_to_binary(Username),
        <<"exp">> => erlang:system_time(second) + 3600, % 1 hour
        <<"iat">> => erlang:system_time(second),
        <<"permissions">> => maps:get(permissions, UserInfo, [<<"chat">>])
    },
    %% Use jose library for JWT creation
    jose_jwt:sign(get_signing_key(), Claims).

validate_token(Token) ->
    try
        case jose_jwt:verify(get_signing_key(), Token) of
            {true, Claims, _} ->
                %% Check expiration
                Now = erlang:system_time(second),
                Exp = maps:get(<<"exp">>, Claims),
                case Now < Exp of
                    true -> {ok, Claims};
                    false -> {error, token_expired}
                end;
            {false, _, _} ->
                {error, invalid_signature}
        end
    catch
        _:_ -> {error, malformed_token}
    end.
```

### Enhanced Request Handling
```erlang
%% Modified cryptic_handlers.erl
init(Req = #{method := <<"POST">>}, upload_prekey) ->
    case extract_and_validate_jwt(Req) of
        {ok, Claims} ->
            Username = maps:get(<<"sub">>, Claims),
            Permissions = maps:get(<<"permissions">>, Claims, []),
            case lists:member(<<"register">>, Permissions) of
                true ->
                    %% Proceed with registration
                    process_prekey_upload(Req, Username);
                false ->
                    unauthorized_response(Req, "insufficient_permissions")
            end;
        {error, Reason} ->
            unauthorized_response(Req, Reason)
    end.

extract_and_validate_jwt(Req) ->
    case cowboy_req:header(<<"authorization">>, Req) of
        <<"Bearer ", Token/binary>> ->
            cryptic_auth_jwt:validate_token(Token);
        _ ->
            {error, missing_auth_header}
    end.
```

### User Management Database
```erlang
%% Simple ETS-based user store (upgrade to real DB in production)
-module(cryptic_user_store).
-export([init/0, create_user/3, validate_credentials/2]).

init() ->
    ets:new(users, [named_table, set, public]),
    %% Create default admin user
    create_user("admin", "admin_password_2024", [<<"admin">>, <<"chat">>]).

create_user(Username, Password, Permissions) ->
    %% Hash password with bcrypt
    Salt = crypto:strong_rand_bytes(16),
    Hash = crypto:hash(sha256, <<Password/binary, Salt/binary>>),
    UserRecord = #{
        username => Username,
        password_hash => Hash,
        salt => Salt,
        permissions => Permissions,
        created_at => erlang:system_time(second)
    },
    ets:insert(users, {Username, UserRecord}).

validate_credentials(Username, Password) ->
    case ets:lookup(users, Username) of
        [{Username, UserRecord}] ->
            StoredHash = maps:get(password_hash, UserRecord),
            Salt = maps:get(salt, UserRecord),
            ProvidedHash = crypto:hash(sha256, <<Password/binary, Salt/binary>>),
            case crypto_secure_compare(StoredHash, ProvidedHash) of
                true -> {ok, UserRecord};
                false -> {error, invalid_credentials}
            end;
        [] ->
            {error, user_not_found}
    end.

%% Constant-time comparison to prevent timing attacks
crypto_secure_compare(A, B) when byte_size(A) =/= byte_size(B) ->
    false;
crypto_secure_compare(A, B) ->
    crypto_secure_compare(A, B, 0).

crypto_secure_compare(<<>>, <<>>, Acc) ->
    Acc =:= 0;
crypto_secure_compare(<<X, RestA/binary>>, <<Y, RestB/binary>>, Acc) ->
    crypto_secure_compare(RestA, RestB, Acc bor (X bxor Y)).
```

### Pros and Cons
**Pros:**
- ✅ Industry standard authentication
- ✅ Stateless (server doesn't need to store sessions)
- ✅ Fine-grained permissions support
- ✅ Token expiration and automatic refresh
- ✅ Scalable and well-understood

**Cons:**
- ❌ **REQUIRES SSL/TLS** - completely insecure without encryption
- ❌ More complex implementation than PSK
- ❌ Requires secure key management for JWT signing
- ❌ Password-based (vulnerable to weak passwords)
- ❌ Token theft could compromise account (if SSL is compromised)

## Phase 3: Ed25519 Digital Signatures (Cryptographically Strong)

### Implementation Effort: **MEDIUM-HIGH** (4-7 days)

**Concept**: Use Ed25519 digital signatures for cryptographically provable identity.

### ✅ TRANSPORT SECURITY: SSL/TLS Optional (But Recommended)

**Ed25519 authentication is cryptographically secure even without SSL/TLS** because:
- **Challenge-response protocol** prevents replay attacks
- **Digital signatures** cannot be forged even if intercepted
- **Private keys** never transmitted over the network
- **Each authentication** uses a fresh random challenge

However, **SSL/TLS is still recommended** for:
- **Metadata protection** (hiding usernames, timing, message sizes)
- **Traffic analysis resistance** 
- **Defense in depth** security strategy

```bash
# Even over HTTP, Ed25519 auth is cryptographically secure
# (though SSL is still recommended for metadata protection)
curl -X POST http://localhost:8080/auth/challenge \
  -d '{"username":"alice"}'
# Response: {"challenge":"base64_random_bytes"}

curl -X POST http://localhost:8080/auth/verify \
  -d '{"username":"alice","challenge":"...","signature":"..."}'
# Signature proves identity without exposing private key
```

### Identity Key Management
```erlang
%% Each user has two keypairs:
%% 1. X25519 keypair for message encryption (existing)
%% 2. Ed25519 keypair for identity/authentication

-record(user_identity, {
    username :: string(),
    identity_public_key :: binary(),  % Ed25519 public key
    encryption_public_key :: binary(), % X25519 public key  
    created_at :: integer(),
    permissions :: [binary()]
}).
```

### Authentication Challenge-Response
```erlang
%% New authentication flow:
%% 1. Client requests challenge for username
%% 2. Server generates random challenge
%% 3. Client signs challenge with Ed25519 private key
%% 4. Server verifies signature with stored public key
%% 5. Server issues session token

challenge_response_auth(Username) ->
    %% Step 1: Generate challenge
    Challenge = crypto:strong_rand_bytes(32),
    
    %% Store challenge temporarily (5 minute expiry)
    ets:insert(auth_challenges, {Username, Challenge, 
                                erlang:system_time(second) + 300}),
    
    %% Return challenge to client
    {ok, Challenge}.

verify_challenge_signature(Username, Challenge, Signature) ->
    case ets:lookup(auth_challenges, Username) of
        [{Username, Challenge, ExpiryTime}] ->
            Now = erlang:system_time(second),
            case Now < ExpiryTime of
                true ->
                    %% Get user's Ed25519 public key
                    case get_user_identity_key(Username) of
                        {ok, PubKey} ->
                            %% Verify signature
                            case crypto:verify(eddsa, sha256, Challenge, 
                                             Signature, [PubKey, ed25519]) of
                                true ->
                                    %% Clean up challenge
                                    ets:delete(auth_challenges, Username),
                                    %% Generate session token
                                    generate_session_token(Username);
                                false ->
                                    {error, invalid_signature}
                            end;
                        {error, _} ->
                            {error, user_not_found}
                    end;
                false ->
                    {error, challenge_expired}
            end;
        _ ->
            {error, invalid_challenge}
    end.
```

### Client-Side Identity Management
```erlang
%% Enhanced client with identity management
-module(cryptic_identity).
-export([generate_identity/1, sign_challenge/2, load_identity/1]).

generate_identity(Username) ->
    %% Generate Ed25519 keypair for identity
    {IdentityPub, IdentityPriv} = crypto:generate_key(eddsa, ed25519),
    
    %% Generate X25519 keypair for encryption
    {EncryptionPub, EncryptionPriv} = cryptic_lib:gen_keypair(),
    
    Identity = #{
        username => Username,
        identity_public => IdentityPub,
        identity_private => IdentityPriv,
        encryption_public => EncryptionPub,
        encryption_private => EncryptionPriv,
        created_at => erlang:system_time(second)
    },
    
    %% Store securely (encrypted with user password)
    store_identity_securely(Username, Identity),
    
    Identity.

sign_challenge(Challenge, IdentityPrivateKey) ->
    crypto:sign(eddsa, sha256, Challenge, [IdentityPrivateKey, ed25519]).

authenticate_with_identity(ServerUrl, Username, IdentityPrivateKey) ->
    %% Step 1: Request challenge
    {ok, Challenge} = request_challenge(ServerUrl, Username),
    
    %% Step 2: Sign challenge
    Signature = sign_challenge(Challenge, IdentityPrivateKey),
    
    %% Step 3: Send signed challenge
    submit_challenge_response(ServerUrl, Username, Challenge, Signature).
```

### Pros and Cons
**Pros:**
- ✅ Cryptographically provable identity
- ✅ **Secure even without SSL/TLS** (though TLS still recommended)
- ✅ No passwords to compromise
- ✅ Non-repudiation (signatures prove authorship)
- ✅ Integrates well with existing X25519 infrastructure
- ✅ Resistant to server compromise (private keys never sent)

**Cons:**
- ❌ Complex key management for users
- ❌ Key loss = permanent account loss  
- ❌ Requires secure client-side key storage
- ❌ More complex backup/recovery procedures

## Phase 4: Hardware Security Key Support (Enterprise)

### Implementation Effort: **HIGH** (1-2 weeks)

**Concept**: Support hardware security keys (YubiKey, etc.) for enterprise deployments.

### 🔒 TRANSPORT SECURITY: SSL/TLS Required

**Hardware key authentication REQUIRES SSL/TLS** because:
- **WebAuthn protocol** mandates HTTPS for security
- **Hardware attestations** contain sensitive cryptographic material
- **Browser security model** blocks WebAuthn over HTTP
- **Enterprise compliance** requires encrypted transport

```javascript
// WebAuthn ONLY works over HTTPS
if (location.protocol !== 'https:') {
    throw new Error('WebAuthn requires HTTPS');
}

// Hardware key authentication
navigator.credentials.create({
    publicKey: {
        challenge: new Uint8Array([/* challenge bytes */]),
        rp: { name: "Cryptic Chat", id: "cryptic-server.com" },
        user: { id: userId, name: username, displayName: username },
        // ... other WebAuthn options
    }
});
```

### FIDO2/WebAuthn Integration
```erlang
%% Integration with hardware security keys
%% Requires WebAuthn protocol implementation

-module(cryptic_webauthn).
-export([register_key/2, authenticate_with_key/2]).

register_key(Username, KeyInfo) ->
    %% Store hardware key public key and metadata
    KeyRecord = #{
        username => Username,
        key_id => maps:get(<<"id">>, KeyInfo),
        public_key => maps:get(<<"publicKey">>, KeyInfo),
        algorithm => maps:get(<<"alg">>, KeyInfo, -7), % ES256
        registered_at => erlang:system_time(second)
    },
    
    ets:insert(hardware_keys, {Username, KeyRecord}),
    {ok, <<"Key registered successfully">>}.

authenticate_with_key(Username, AuthData) ->
    %% Verify WebAuthn assertion
    case verify_webauthn_assertion(Username, AuthData) of
        {ok, verified} ->
            generate_session_token(Username);
        {error, Reason} ->
            {error, Reason}
    end.
```

## SSL/TLS Requirements Summary

| Authentication Method | SSL/TLS Requirement | Reason |
|----------------------|---------------------|---------|
| **Phase 1: PSK** | ⚠️ **MANDATORY** | Tokens sent in plaintext |
| **Phase 1.5: mTLS** | ✅ **BUILT-IN** | Authentication IS the TLS layer |
| **Phase 2: JWT** | ⚠️ **MANDATORY** | Credentials + tokens in plaintext |
| **Phase 3: Ed25519** | ✅ **Recommended** | Cryptographically secure without, but TLS provides metadata protection |
| **Phase 4: Hardware Keys** | ⚠️ **MANDATORY** | WebAuthn protocol requirement |

### Quick SSL/TLS Setup Guide

```bash
# 1. Development: Generate self-signed certificate
./scripts/generate-dev-certs.sh

# 1.5. Development: Generate mTLS certificates (includes client certs)
./scripts/generate-mtls-certs.sh

# 2. Production: Use Let's Encrypt
certbot certonly --standalone -d your-server.com

# 3a. Start server with HTTPS
erl -pa _build/default/lib/*/ebin
1> cryptic_server:start_https(#{
    https_port => 8443,
    certfile => "priv/ssl/server.crt", 
    keyfile => "priv/ssl/server.key"
}).

# 3b. Start server with mTLS (mutual authentication)
1> cryptic_server:start_mtls(#{
    mtls_port => 8443,
    certfile => "priv/ssl/server.crt",
    keyfile => "priv/ssl/server.key", 
    cacertfile => "priv/ssl/ca.crt"
}).

# 4a. Update client to use HTTPS
1> cryptic_cecho_ui:start("https://localhost:8443").

# 4b. Update client to use mTLS (with client certificate)
1> cryptic_cecho_ui:start_mtls("https://localhost:8443", "priv/ssl/client_alice.pem").
```

## Recommended Implementation Roadmap

### Week 1: SSL/TLS + Quick Security (Phase 1 or 1.5)
- **Option A: Basic HTTPS + PSK**
  - Day 1: Implement HTTPS server with TLS support
  - Day 2: Add PSK authentication with secure token validation
  - Day 3-5: Client integration and testing
  
- **Option B: mTLS (Enterprise)**
  - Day 1-2: Implement mTLS server with client certificate verification
  - Day 3: Generate CA and client certificates
  - Day 4-5: Client certificate integration and testing

### Week 2-3: Modern Auth (Phase 2)  
- JWT authentication system (over HTTPS)
- User management database
- Permission-based access control
- Token refresh mechanisms
- Production certificate setup

### Week 4-5: Strong Identity (Phase 3)
- Ed25519 identity keypairs
- Challenge-response authentication (works with or without TLS)
- Secure client key storage
- Identity verification flow

### Future: Enterprise Features (Phase 4)
- Hardware security key support (requires HTTPS)
- FIDO2/WebAuthn integration
- Multi-factor authentication
- Enterprise user management

## Security Configuration Example

```erlang
%% config/auth.config
#{
    auth_method => jwt, % psk | jwt | ed25519 | hardware
    
    %% JWT settings
    jwt => #{
        secret_key => <<"your-256-bit-secret">>,
        issuer => <<"cryptic-chat-server">>,
        expiry_seconds => 3600,
        refresh_expiry_seconds => 86400
    },
    
    %% PSK settings (for simple deployments)
    psk => #{
        tokens => #{
            <<"alice">> => <<"secure_token_alice">>,
            <<"bob">> => <<"secure_token_bob">>
        }
    },
    
    %% Permission levels
    permissions => #{
        admin => [<<"chat">>, <<"register">>, <<"list_users">>, <<"manage_users">>],
        user => [<<"chat">>, <<"register">>, <<"list_users">>],
        guest => [<<"chat">>]
    }
}.
```

## Summary

This plan provides a **layered approach** to authentication:

1. **Phase 1 (PSK)**: Immediate security with minimal effort
2. **Phase 2 (JWT)**: Modern, scalable authentication  
3. **Phase 3 (Ed25519)**: Cryptographically strong identity
4. **Phase 4 (Hardware)**: Enterprise-grade security

Each phase builds upon the previous one, allowing for **incremental security improvements** while maintaining system usability. The modular design means you can choose the authentication level that fits your deployment requirements and security needs.

**Recommendation**: Start with **Phase 1** for immediate security, then implement **Phase 2** for a production-ready system. Phase 3 and 4 are for high-security environments.
