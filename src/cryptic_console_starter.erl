%%% @doc Cryptic Console Starter - Entry point for standard Erlang startup
%%%
%%% This module provides the entry point for starting the Cryptic console
%%% using standard Erlang `-s` flag instead of escript.
%%%
%%% == Usage Examples ==
%%%
%%% Interactive mode with shell:
%%% ```
%%% erl -pa _build/default/lib/*/ebin \
%%%     -s cryptic_console_starter start \
%%%     -cryptic username alice \
%%%     -cryptic server_host localhost \
%%%     -cryptic server_port 8443 \
%%%     -cryptic enable_db true
%%% '''
%%%
%%% Detached mode (background):
%%% ```
%%% erl -pa _build/default/lib/*/ebin \
%%%     -detached \
%%%     -sname alice \
%%%     -s cryptic_console_starter start \
%%%     -cryptic username alice \
%%%     -cryptic server_host localhost \
%%%     -cryptic server_port 8443
%%% '''
%%%
%%% Connect to detached console:
%%% ```
%%% erl -sname admin -remsh alice@localhost
%%% '''
%%%
%%% == Configuration ==
%%%
%%% Configuration is provided via application environment variables:
%%% <ul>
%%%   <li>`username' - Username (required, binary or string)</li>
%%%   <li>`server_host' - Server hostname (default: "localhost")</li>
%%%   <li>`server_port' - Server port (default: 8443)</li>
%%%   <li>`notifier' - Path to notification script (optional)</li>
%%%   <li>`enable_db' - Enable message storage (default: false)</li>
%%%   <li>`interactive' - Start interactive console (default: true)</li>
%%% </ul>

-module(cryptic_console_starter).

%% API
-export([start/0]).
-export([start_link/0, start_link/1]).
-export([stop/0]).

-include("cryptic.hrl").

%%%===================================================================
%%% Api Functions
%%%===================================================================

%% @doc Start the console with configuration from application environment
%% This is called when using `erl -s cryptic_console_starter start'
-spec start() -> ok.
start() ->
    spawn(fun() -> run() end).

%% @doc Start the console with optional args (for -s flag compatibility)
%% Args are ignored, configuration comes from application environment
-spec run() -> ok.
run() ->
    %% Ensure the cryptic application is loaded
    case application:load(cryptic) of
        ok -> ok;
        {error, {already_loaded, cryptic}} -> ok;
        {error, Reason} ->
            io:format("Failed to load cryptic application: ~p~n", [Reason]),
            init:stop(1)
    end,

    %% Make sure we can be found by e.g TUI RPC's.
    register(cryptic_console, self()),

    %% Get configuration from application environment
    Config = get_config(),
    ok = setup_event_management(Config),

    %% Validate required config
    case maps:get(username, Config, undefined) of
        undefined ->
            io:format("Error: username not configured~n"),
            init:stop(1);
        Username ->
            %% Start Erlang distribution if node name is configured
            case maps:get(node_name, Config, undefined) of
                undefined ->
                    ok;
                NodeNameStr ->
                    start_distribution(Username, NodeNameStr)
            end
    end,

    %% Display startup banner
    ?info("=== Cryptic Console ===~n", []),
    ?info("Username: ~s~n", [maps:get(username, Config)]),
    ?info("Nodename: ~p~n", [node()]),
    ?info("Server: ~s:~p~n", [
        maps:get(server_host, Config, "localhost"),
        maps:get(server_port, Config, 8443)
    ]),

    %% Show TUI mode status
    case maps:get(tui_mode, Config, false) of
        true ->
            ?info("Mode: TUI (detached backend)~n", []);
        false ->
            ?info("Mode: Interactive console~n", [])
    end,

    cryptic_console:main(Config).

%% @doc Start as a linked process (for supervision)
-spec start_link() -> {ok, pid()}.
start_link() ->
    start_link([]).

%% @doc Start as a linked process with config
-spec start_link(list()) -> {ok, pid()}.
start_link(_Args) ->
    Config = get_config(),
    Pid = spawn_link(fun() -> cryptic_console:main(Config) end),
    {ok, Pid}.

%% @doc Stop the console
-spec stop() -> ok.
stop() ->
    case whereis(cryptic_console) of
        undefined ->
            ok;
        Pid ->
            exit(Pid, normal),
            ok
    end.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @doc Start Erlang distribution with the given node name
-spec start_distribution(binary() | string(), string()) -> ok.
start_distribution(Username, NodeNameStr) ->
    %% Convert username to string if needed
    UsernameStr = case Username of
        U when is_binary(U) -> binary_to_list(U);
        U when is_list(U) -> U;
        U when is_atom(U) -> atom_to_list(U)
    end,
    
    %% Build full node name (e.g., alice@localhost)
    %% NodeNameStr should already contain the host part (e.g., "localhost")
    FullNodeName = UsernameStr ++ "@" ++ NodeNameStr,
    NodeName = list_to_atom(FullNodeName),

    %% Start distribution
    case net_kernel:start([NodeName, shortnames]) of
        {ok, _Pid} ->
            ?info("Started Erlang distribution: ~p~n", [NodeName]),
            ok;
        {error, {already_started, _Pid}} ->
            ?error("Erlang distribution already started~n", []),
            ok;
        {error, Reason} ->
            ?error("Failed to start Erlang distribution as: ~p , Reason:~p~n",
                   [NodeName, Reason]),
            ok
    end.

%% @doc Get configuration from environment variables and application environment
%% Environment variables take precedence over application environment
-spec get_config() -> map().
get_config() ->
    %% Try environment variables first (set by shell script)
    %% Fall back to application environment (set via -cryptic flags)
    Username = get_env_var("CRYPTIC_USERNAME", fun() -> get_env(username, undefined) end),
    ServerHost = get_env_var("CRYPTIC_SERVER_HOST", fun() -> get_env(server_host, "localhost") end),
    ServerPort = get_env_var("CRYPTIC_SERVER_PORT", fun() -> get_env(server_port, "8443") end),
    Notifier = get_env_var("CRYPTIC_NOTIFIER", fun() -> get_env(notifier, undefined) end),
    EnableDb = get_env_var("CRYPTIC_ENABLE_DB", fun() -> get_env(enable_db, false) end),
    Interactive = get_env_var("CRYPTIC_INTERACTIVE", fun() -> get_env(interactive, true) end),
    TuiMode = get_env_var("CRYPTIC_TUI_MODE", fun() -> get_env(tui_mode, false) end),
    NodeName = get_env_var("CRYPTIC_NODE_NAME", fun() -> get_env(node_name, undefined) end),

    %% Convert username to binary if needed
    UsernameBin = case Username of
        undefined -> undefined;
        U when is_binary(U) -> U;
        U when is_list(U) -> list_to_binary(U);
        U when is_atom(U) -> atom_to_binary(U, utf8)
    end,

    CrypticDir = cryptic_lib:get_cryptic_dir(Username,
                                             ServerHost,
                                             list_to_integer(ServerPort)),


    #{
        username => UsernameBin,
        server_host => ensure_string(ServerHost),
        server_port => ensure_integer(ServerPort),
        notifier => ensure_string(Notifier),
        enable_db => ensure_boolean(EnableDb),
        interactive => ensure_boolean(Interactive),
        tui_mode => ensure_boolean(TuiMode),
        node_name => ensure_string(NodeName),
        cryptic_dir => CrypticDir
    }.

%% @doc Setup event management
-spec setup_event_management(Config :: map()) -> ok.
setup_event_management(Config) ->
    Username = maps:get(username, Config),

    %% Start the event manager for logging
    case gen_event:start_link({local, cryptic_event_manager}) of
        {ok, _} ->
            ok;
        {error, {already_started, _}} ->
            ok;
        {error, Reason} ->
            io:format("Failed to start event manager: ~p~n", [Reason]),
            throw(event_manager)
    end,

    %% Set up event handlers for UI client with client configuration
    EventCfg = Config#{
        log_type => client,
        log_dir => filename:join([maps:get(cryptic_dir,Config,"."), "logs"]),
        username => Username
    },
    case cryptic_event_manager:setup_event_handlers(EventCfg) of
        ok ->
            ok;
        {error, SetupReason} ->
            io:format("Failed to setup event handlers: ~p~n", [SetupReason])
    end.

%% @doc Get value from OS environment variable with fallback function
-spec get_env_var(string(), fun(() -> term())) -> term().
get_env_var(VarName, FallbackFun) ->
    case os:getenv(VarName) of
        false -> FallbackFun();
        "" -> FallbackFun();
        Value -> Value
    end.

%% @doc Get application environment variable with default
-spec get_env(atom(), term()) -> term().
get_env(Key, Default) ->
    case application:get_env(cryptic, Key) of
        {ok, Value} -> Value;
        undefined -> Default
    end.

%% @doc Ensure value is a string
-spec ensure_string(term()) -> string() | undefined.
ensure_string(undefined) -> undefined;
ensure_string(Value) when is_list(Value) -> Value;
ensure_string(Value) when is_binary(Value) -> binary_to_list(Value);
ensure_string(Value) when is_atom(Value) -> atom_to_list(Value);
ensure_string(_) -> undefined.

%% @doc Ensure value is an integer
-spec ensure_integer(term()) -> integer().
ensure_integer(Value) when is_integer(Value) -> Value;
ensure_integer(Value) when is_list(Value) -> list_to_integer(Value);
ensure_integer(Value) when is_binary(Value) -> binary_to_integer(Value);
ensure_integer(_) -> 8443.

%% @doc Ensure value is a boolean
-spec ensure_boolean(term()) -> boolean().
ensure_boolean(true) -> true;
ensure_boolean("true") -> true;
ensure_boolean(<<"true">>) -> true;
ensure_boolean(_) -> false.
