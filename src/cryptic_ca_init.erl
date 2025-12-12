%%% @doc CA Database Initializer
%%%
%%% This gen_server initializes the CA database at application startup.
%%% It's designed to be supervised and ensures the database is ready
%%% before the HTTP server starts accepting requests.
%%%
%%% @author Cryptic Team
%%% @version 1.0.0

-module(cryptic_ca_init).
-behaviour(gen_server).

-include("cryptic_server.hrl").

%% API
-export([start_link/0, get_db_ref/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    db_ref :: term()
}).

%%====================================================================
%% API
%%====================================================================

%% @doc Start the CA initializer.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Get the CA database reference.
-spec get_db_ref() -> {ok, term()} | {error, not_initialized}.
get_db_ref() ->
    gen_server:call(?MODULE, get_db_ref).

%%====================================================================
%% gen_server callbacks
%%====================================================================

%% @doc Initialize the CA database.
init([]) ->
    LogDir =
        case os:getenv("CRYPTIC_SERVER_DIR") of
            false ->
                "logs";
            ServerDir ->
                filename:join([ServerDir, "logs"])
        end,

    %% Set up event handlers for logging (event manager is already started by supervisor)
    cryptic_event_manager:setup_event_handlers(#{
        log_type => server,
        log_dir => LogDir
    }),

    ?info("CA initializer starting...", []),

    %% Create ETS table to store CA database reference
    %% This allows verify_peer callback to access the DB
    ets:new(cryptic_ca_storage, [named_table, set, protected, {read_concurrency, true}]),

    case cryptic_ca_app:init_ca() of
        {ok, DbRef} ->
            ?info("CA database initialized successfully", []),

            %% Store the database reference in ETS for global access
            ets:insert(cryptic_ca_storage, {db_ref, DbRef}),

            %% Initialize CA environment (load certificates and keys)
            case cryptic_ca_store:init_ca_environment() of
                ok ->
                    ?info("CA environment initialized (cert/key loaded)", []),

                    %% Load GPG bootstrap registrations from filesystem
                    %% The bootstrap module handles all logging
                    case cryptic_ca_bootstrap:load_bootstrap_registrations(DbRef) of
                        {ok, _Count} ->
                            ok;
                        {error, BootstrapReason} ->
                            ?warning("Failed to load GPG bootstrap registrations: ~p", [BootstrapReason])
                    end,

                    {ok, #state{db_ref = DbRef}};
                {error, CaEnvReason} ->
                    ?error("Failed to initialize CA environment: ~p", [CaEnvReason]),
                    {stop, {ca_env_init_failed, CaEnvReason}}
            end;
        {error, Reason} ->
            ?error("Failed to initialize CA database: ~p", [Reason]),
            {stop, {ca_init_failed, Reason}}
    end.

handle_call(get_db_ref, _From, #state{db_ref = DbRef} = State) ->
    {reply, {ok, DbRef}, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ?info("CA initializer terminating", []),
    %% Clean up the ETS table
    catch ets:delete(cryptic_ca_storage),
    ok.
