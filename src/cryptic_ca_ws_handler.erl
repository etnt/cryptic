%% @doc WebSocket handler for CA invite operations from trusted clients (cryptic_console)
%%
%% This module handles WebSocket connections from authenticated clients
%% (cryptic_console) for invite management operations. Authentication is
%% provided by the existing mTLS connection.
%%
%% Supported Commands:
%% - invite_create: Create a new invite token
%% - invite_list: List invites created by the authenticated user
%% - invite_revoke: Revoke an unused invite
%% - gpg_register_bootstrap: Register GPG key for existing mTLS user
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since October 2025
-module(cryptic_ca_ws_handler).

-export([
    init/2,
    websocket_init/1,
    websocket_handle/2,
    websocket_info/2,
    terminate/3
]).

%% Export for testing
-export([handle_command/2]).

-include_lib("kernel/include/logger.hrl").
-include("../include/cryptic_ca.hrl").

-record(state, {
    gpg_fp :: binary() | undefined,
    db_ref :: term(),
    authenticated = false :: boolean()
}).

%%====================================================================
%% Cowboy WebSocket Callbacks
%%====================================================================

%% @doc Initialize the WebSocket handler.
%%
%% Upgrades the HTTP connection to WebSocket protocol. The client must
%% be authenticated via mTLS before this handler is invoked.
%%
%% @param Req Cowboy request object
%% @param _Opts Handler options (unused)
%% @returns {cowboy_websocket, Req, State} to upgrade to WebSocket
init(Req, _Opts) ->
    ?LOG_DEBUG("Initializing CA WebSocket handler"),

    %% Get database reference from application environment
    {ok, DbRef} = application:get_env(cryptic, ca_db_ref),

    State = #state{
        db_ref = DbRef,
        authenticated = false
    },

    {cowboy_websocket, Req, State, #{
        % 10 minutes
        idle_timeout => 600000
    }}.

%% @doc WebSocket connection established.
%%
%% Extracts the GPG fingerprint from the mTLS certificate (if available)
%% or waits for bootstrap registration.
%%
%% @param State Handler state
%% @returns {ok, State} on successful initialization
websocket_init(State) ->
    ?LOG_INFO("CA WebSocket connection established"),

    %% TODO: Extract GPG fingerprint from mTLS cert subject CN
    %% For now, mark as not fully authenticated until bootstrap or verification

    {ok, State}.

%% @doc Handle incoming WebSocket frames.
%%
%% Processes commands from the client and returns responses.
%%
%% @param Frame Incoming WebSocket frame
%% @param State Handler state
%% @returns {reply, Frame, State} | {ok, State}
websocket_handle({text, Msg}, State) ->
    ?LOG_DEBUG("Received WebSocket message: ~p", [Msg]),

    try
        %% Decode JSON message
        MsgMap = jsx:decode(Msg, [return_maps]),
        handle_command(MsgMap, State)
    catch
        Error:Reason:Stack ->
            ?LOG_ERROR(
                "Error handling WebSocket message: ~p:~p~nStack: ~p",
                [Error, Reason, Stack]
            ),
            ErrorResp = jsx:encode(#{
                error => <<"invalid_request">>,
                message => <<"Failed to process request">>
            }),
            {reply, {text, ErrorResp}, State}
    end;
websocket_handle({binary, _}, State) ->
    %% We only support text frames for JSON messages
    ErrorResp = jsx:encode(#{
        error => <<"unsupported_frame_type">>,
        message => <<"Only text frames are supported">>
    }),
    {reply, {text, ErrorResp}, State};
websocket_handle(_Frame, State) ->
    {ok, State}.

%% @doc Handle Erlang messages sent to the WebSocket process.
%%
%% @param Info Erlang message
%% @param State Handler state
%% @returns {ok, State}
websocket_info(_Info, State) ->
    {ok, State}.

%% @doc Cleanup when WebSocket connection is closed.
%%
%% @param Reason Termination reason
%% @param _Req Cowboy request (unused)
%% @param _State Handler state (unused)
%% @returns ok
terminate(_Reason, _Req, _State) ->
    ?LOG_INFO("CA WebSocket connection terminated"),
    ok.

%%====================================================================
%% Command Handlers
%%====================================================================

%% @doc Route commands to appropriate handlers.
%%
%% @param MsgMap Decoded JSON message map
%% @param State Handler state
%% @returns {reply, Frame, State} | {ok, State}
-spec handle_command(map(), #state{}) ->
    {reply, tuple(), #state{}} | {ok, #state{}}.

handle_command(#{<<"command">> := <<"invite_create">>} = Msg, State) ->
    handle_invite_create(Msg, State);
handle_command(#{<<"command">> := <<"invite_list">>} = Msg, State) ->
    handle_invite_list(Msg, State);
handle_command(#{<<"command">> := <<"invite_revoke">>} = Msg, State) ->
    handle_invite_revoke(Msg, State);
handle_command(#{<<"command">> := <<"gpg_register_bootstrap">>} = Msg, State) ->
    handle_gpg_register_bootstrap(Msg, State);
handle_command(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"unknown_command">>,
        message =>
            <<"Supported commands: invite_create, invite_list, invite_revoke, gpg_register_bootstrap">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @doc Handle invite_create command.
%%
%% Creates a new invite token that can be used by another user to register.
%%
%% Request format:
%% ```
%% {
%%   "command": "invite_create",
%%   "expiry_hours": 24,
%%   "meta": {"note": "Inviting Bob"}
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "invite_id": "inv-8f3b12a4...",
%%   "expires_at": 1234567890
%% }
%% '''
-spec handle_invite_create(map(), #state{}) -> {reply, tuple(), #state{}}.
handle_invite_create(_Msg, #state{gpg_fp = undefined} = State) ->
    %% Not authenticated with GPG key
    ErrorResp = jsx:encode(#{
        error => <<"not_authenticated">>,
        message =>
            <<"Please register your GPG key first using gpg_register_bootstrap">>
    }),
    {reply, {text, ErrorResp}, State};
handle_invite_create(Msg, #state{gpg_fp = InviterFp, db_ref = DbRef} = State) ->
    ExpiryHours = maps:get(<<"expiry_hours">>, Msg, 24),
    Meta = maps:get(<<"meta">>, Msg, #{}),

    ?LOG_INFO("Creating invite for inviter ~s, expiry: ~p hours", [
        InviterFp, ExpiryHours
    ]),

    %% Check rate limit for invite creation
    case cryptic_ca_rate_limiter:check_limit(InviterFp, invite_create, 1) of
        {ok, _Remaining} ->
            create_invite_impl(DbRef, InviterFp, ExpiryHours, Meta, State);
        {error, rate_limited, RetryAfter} ->
            ?LOG_WARNING(
                "Rate limit exceeded for inviter ~s, retry after ~p seconds",
                [InviterFp, RetryAfter]
            ),
            ErrorResp = jsx:encode(#{
                error => <<"rate_limited">>,
                message => <<"Too many invite creation requests">>,
                retry_after => RetryAfter
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @private Create invite after rate limit check
create_invite_impl(DbRef, InviterFp, ExpiryHours, Meta, State) ->
    case
        cryptic_invite_mgr:create_invite(DbRef, InviterFp, ExpiryHours, Meta)
    of
        {ok, InviteId} ->
            {ok, Invite} = cryptic_ca_store:get_invite(DbRef, InviteId),

            Response = jsx:encode(#{
                status => <<"success">>,
                invite_id => InviteId,
                expires_at => Invite#invite.expires_at
            }),

            ?LOG_INFO("Invite created successfully: ~s", [InviteId]),
            {reply, {text, Response}, State};
        {error, Reason} ->
            ?LOG_ERROR("Failed to create invite: ~p", [Reason]),
            ErrorResp = jsx:encode(#{
                error => <<"invite_creation_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @doc Handle invite_list command.
%%
%% Lists all invites created by the authenticated user.
%%
%% Request format:
%% ```
%% {
%%   "command": "invite_list"
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "invites": [
%%     {
%%       "invite_id": "inv-123",
%%       "expires_at": 1234567890,
%%       "consumed": false,
%%       "expired": false
%%     }
%%   ]
%% }
%% '''
-spec handle_invite_list(map(), #state{}) -> {reply, tuple(), #state{}}.
handle_invite_list(_Msg, #state{gpg_fp = undefined} = State) ->
    ErrorResp = jsx:encode(#{
        error => <<"not_authenticated">>,
        message => <<"Please register your GPG key first">>
    }),
    {reply, {text, ErrorResp}, State};
handle_invite_list(_Msg, #state{gpg_fp = InviterFp, db_ref = DbRef} = State) ->
    %% Check rate limit for invite listing
    case cryptic_ca_rate_limiter:check_limit(InviterFp, invite_list, 1) of
        {ok, _Remaining} ->
            list_invites_impl(DbRef, InviterFp, State);
        {error, rate_limited, RetryAfter} ->
            ?LOG_WARNING(
                "Rate limit exceeded for invite_list ~s, retry after ~p seconds",
                [InviterFp, RetryAfter]
            ),
            ErrorResp = jsx:encode(#{
                error => <<"rate_limited">>,
                message => <<"Too many list requests">>,
                retry_after => RetryAfter
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @private List invites after rate limit check
list_invites_impl(DbRef, InviterFp, State) ->
    case cryptic_invite_mgr:list_user_invites(DbRef, InviterFp) of
        {ok, Invites} ->
            Response = jsx:encode(#{
                status => <<"success">>,
                invites => Invites
            }),
            {reply, {text, Response}, State};
        {error, Reason} ->
            ErrorResp = jsx:encode(#{
                error => <<"list_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @doc Handle invite_revoke command.
%%
%% Revokes an unused invite token.
%%
%% Request format:
%% ```
%% {
%%   "command": "invite_revoke",
%%   "invite_id": "inv-123"
%% }
%% '''
-spec handle_invite_revoke(map(), #state{}) -> {reply, tuple(), #state{}}.
handle_invite_revoke(_Msg, #state{gpg_fp = undefined} = State) ->
    ErrorResp = jsx:encode(#{
        error => <<"not_authenticated">>,
        message => <<"Please register your GPG key first">>
    }),
    {reply, {text, ErrorResp}, State};
handle_invite_revoke(
    #{<<"invite_id">> := InviteId},
    #state{gpg_fp = GpgFp, db_ref = DbRef} = State
) ->
    %% Check rate limit for invite revocation
    case cryptic_ca_rate_limiter:check_limit(GpgFp, invite_revoke, 1) of
        {ok, _Remaining} ->
            revoke_invite_impl(DbRef, InviteId, State);
        {error, rate_limited, RetryAfter} ->
            ?LOG_WARNING(
                "Rate limit exceeded for invite_revoke ~s, retry after ~p seconds",
                [GpgFp, RetryAfter]
            ),
            ErrorResp = jsx:encode(#{
                error => <<"rate_limited">>,
                message => <<"Too many revoke requests">>,
                retry_after => RetryAfter
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_invite_revoke(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"missing_invite_id">>,
        message => <<"invite_id is required">>
    }),
    {reply, {text, ErrorResp}, State}.

%% @private Revoke invite after rate limit check
revoke_invite_impl(DbRef, InviteId, State) ->
    case cryptic_invite_mgr:revoke_invite(DbRef, InviteId) of
        ok ->
            Response = jsx:encode(#{
                status => <<"success">>,
                invite_id => InviteId
            }),
            {reply, {text, Response}, State};
        {error, Reason} ->
            ErrorResp = jsx:encode(#{
                error => <<"revoke_failed">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end.

%% @doc Handle gpg_register_bootstrap command.
%%
%% Registers a GPG key for a user who already has a valid mTLS certificate.
%% This is used for the initial admin setup or for users transitioning from
%% TLS-only to GPG-based authentication.
%%
%% Request format:
%% ```
%% {
%%   "command": "gpg_register_bootstrap",
%%   "gpg_pub": "-----BEGIN PGP PUBLIC KEY BLOCK-----..."
%% }
%% '''
%%
%% Response format:
%% ```
%% {
%%   "status": "success",
%%   "gpg_fp": "ABCD1234...",
%%   "registered_at": 1234567890
%% }
%% '''
-spec handle_gpg_register_bootstrap(map(), #state{}) ->
    {reply, tuple(), #state{}}.
handle_gpg_register_bootstrap(
    #{<<"gpg_pub">> := GpgPub}, #state{db_ref = DbRef} = State
) ->
    ?LOG_INFO("Bootstrap GPG registration request"),

    %% Validate and extract GPG public key
    case cryptic_ca_gpg:extract_public_key(GpgPub) of
        {ok, ValidatedKey} ->
            %% Compute fingerprint
            case cryptic_ca_gpg:compute_fingerprint(ValidatedKey) of
                {ok, GpgFp} ->
                    %% Register as bootstrap identity
                    case
                        cryptic_gpg_registry:register_bootstrap_identity(
                            DbRef, GpgFp, ValidatedKey
                        )
                    of
                        ok ->
                            Now = erlang:system_time(second),
                            Response = jsx:encode(#{
                                status => <<"success">>,
                                gpg_fp => GpgFp,
                                registered_at => Now
                            }),

                            ?LOG_INFO(
                                "GPG bootstrap registration successful: ~s", [
                                    GpgFp
                                ]
                            ),

                            %% Update state to mark as authenticated
                            NewState = State#state{
                                gpg_fp = GpgFp,
                                authenticated = true
                            },
                            {reply, {text, Response}, NewState};
                        {error, Reason} ->
                            ?LOG_ERROR("GPG registration failed: ~p", [Reason]),
                            ErrorResp = jsx:encode(#{
                                error => <<"registration_failed">>,
                                message => iolist_to_binary(
                                    io_lib:format("~p", [Reason])
                                )
                            }),
                            {reply, {text, ErrorResp}, State}
                    end;
                {error, Reason} ->
                    ErrorResp = jsx:encode(#{
                        error => <<"fingerprint_computation_failed">>,
                        message => iolist_to_binary(
                            io_lib:format("~p", [Reason])
                        )
                    }),
                    {reply, {text, ErrorResp}, State}
            end;
        {error, Reason} ->
            ErrorResp = jsx:encode(#{
                error => <<"invalid_gpg_key">>,
                message => iolist_to_binary(io_lib:format("~p", [Reason]))
            }),
            {reply, {text, ErrorResp}, State}
    end;
handle_gpg_register_bootstrap(_Msg, State) ->
    ErrorResp = jsx:encode(#{
        error => <<"missing_gpg_pub">>,
        message => <<"gpg_pub is required">>
    }),
    {reply, {text, ErrorResp}, State}.
