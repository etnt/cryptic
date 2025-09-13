%%%-------------------------------------------------------------------
%%% @doc
%%% Event manager for Cryptic.
%%% This module handles event notifications and manages event handlers
%%% for logging and monitoring Cryptic events.
%%%
%%% == Configuration ==
%%%
%%% The event handlers can be configured in two ways:
%%%
%%% <ul>
%%%   <li>Application environment: Set the `cryptic_event_handlers' variable
%%%       in the application configuration.</li>
%%%   <li>Environment variable: Set `CRYPTIC_EVENT_HANDLERS' to a
%%%       comma-separated list of handler module names
%%%       (e.g. "cryptic_console_logger,cryptic_file_logger").</li>
%%% </ul>
%%%
%%% The environment variable takes precedence over the application setting.
%%%
%%% @author Torbjörn Törnkvist <kruskakli@gmail.com>
%%% @copyright 2025 Torbjörn Törnkvist
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_event_manager).

-export([
    notify/2,
    add_handler/2,
    delete_handler/2,
    setup_event_handlers/0,
    setup_event_handlers/1
]).

%%--------------------------------------------------------------------
%% @doc
%% Sends a notification to all registered event handlers.
%% @param EventId The type of event being notified
%% @param Data The data associated with the event
%% @end
%%--------------------------------------------------------------------
-spec notify(EventId :: atom(), Data :: any()) -> ok.
notify(EventId, Data) ->
    gen_event:notify(?MODULE, {EventId, Data}).

%%--------------------------------------------------------------------
%% @doc
%% Adds an event handler to the event manager.
%% @param Handler The event handler module to add
%% @param Args Initialization arguments for the handler (map)
%% @end
%%--------------------------------------------------------------------
-spec add_handler(Handler :: module(), Args :: map()) ->
    ok | {'EXIT', term()} | term().
add_handler(Handler, Args) ->
    gen_event:add_handler(?MODULE, Handler, Args).

%%--------------------------------------------------------------------
%% @doc
%% Removes an event handler from the event manager.
%% @param Handler The event handler module to remove
%% @param Args Arguments for the termination
%% @end
%%--------------------------------------------------------------------
-spec delete_handler(Handler :: module(), Args :: term()) ->
    term() | {error, module_not_found} | {'EXIT', term()}.
delete_handler(Handler, Args) ->
    gen_event:delete_handler(?MODULE, Handler, Args).

%%--------------------------------------------------------------------
%% @doc
%% Sets up the event handlers for the Cryptic implementation.
%% Reads configuration from application environment or environment variables.
%% @end
%%--------------------------------------------------------------------
-spec setup_event_handlers() -> ok.
setup_event_handlers() ->
    setup_event_handlers(#{}).

%%--------------------------------------------------------------------
%% @doc
%% Sets up the event handlers for the Cryptic implementation with configuration.
%% Reads configuration from application environment or environment variables.
%% @param Config Configuration map passed to event handlers (e.g., #{log_type => server})
%% @end
%%--------------------------------------------------------------------
-spec setup_event_handlers(Config :: map()) -> ok.
setup_event_handlers(Config) ->
    %% An environment variable can override the default event handlers
    %% defined in the application configuration.
    case
        maybe_env_handlers(
            application:get_env(cryptic, cryptic_event_handlers, [])
        )
    of
        [] ->
            ok;
        EventHandlers ->
            try
                [add_handler(M, Config) || M <- EventHandlers]
            catch
                _:Error ->
                    error_logger:error_msg(
                        "Failed to add event handler(s): ~p", [Error]
                    )
            end
    end,
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Determines debug mode based on environment variables and application settings.
%% Environment variable: `CRYPTIC_EVENT_HANDLERS' override application settings.
%% Example: `CRYPTIC_EVENT_HANDLERS=cryptic_console_logger,cryptic_file_logger'
%% @private
%% @end
%%--------------------------------------------------------------------
-spec maybe_env_handlers(Default :: list()) -> list().
maybe_env_handlers(Default) when is_list(Default) ->
    case os:getenv("CRYPTIC_EVENT_HANDLERS") of
        false ->
            Default;
        Str when is_list(Str) ->
            case string:tokens(Str, ",") of
                [] ->
                    Default;
                Tokens ->
                    %% Convert tokens to module names
                    try
                        [list_to_atom(M) || M <- Tokens]
                    catch
                        _:Error ->
                            error_logger:error_msg(
                                "Failed to parse event handlers: ~p", [Error]
                            ),
                            Default
                    end
            end;
        _ ->
            Default
    end;
maybe_env_handlers(_Default) ->
    error_logger:error_msg(
        "Invalid default value for event handlers, expected list, got: ~p", [
            _Default
        ]
    ),
    [].
