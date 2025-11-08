%% @doc CA application startup and configuration
%%
%% This module handles initialization of the Certificate Authority subsystem
%% including database setup and configuration.
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since October 2025
-module(cryptic_ca_app).

-behaviour(application).

-export([start/2, stop/1]).
-export([init_ca/0, get_ca_db/0]).

-include("cryptic_server.hrl").

%%====================================================================
%% Application Callbacks
%%====================================================================

%% @doc Start the CA application.
%%
%% Initializes the CA database and makes it available to handlers.
%%
%% @param StartType Application start type
%% @param StartArgs Start arguments
%% @returns {ok, Pid} | {error, Reason}
start(_StartType, _StartArgs) ->
    ?info("Starting Cryptic CA application", []),

    %% Initialize CA database
    case init_ca() of
        {ok, DbRef} ->
            ?info("CA database initialized: ~p", [DbRef]),

            %% Initialize CA environment (load certificates and keys)
            case cryptic_ca_store:init_ca_environment() of
                ok ->
                    ?info("CA environment initialized (cert/key loaded)", []),
                    {ok, self()};
                {error, CaReason} ->
                    ?error("Failed to initialize CA environment: ~p", [CaReason]),
                    {error, CaReason}
            end;
        {error, Reason} ->
            ?error("Failed to initialize CA database: ~p", [Reason]),
            {error, Reason}
    end.

%% @doc Stop the CA application.
%%
%% Cleans up CA resources including closing the database.
%%
%% @param State Application state
%% @returns ok
stop(_State) ->
    ?info("Stopping Cryptic CA application", []),

    %% Close CA database if open
    case application:get_env(cryptic, ca_db_ref) of
        {ok, DbRef} ->
            cryptic_ca_store:close(DbRef),
            application:unset_env(cryptic, ca_db_ref),
            ?info("CA database closed", []);
        undefined ->
            ok
    end,

    ok.

%%====================================================================
%% Public API
%%====================================================================

%% @doc Initialize the CA database.
%%
%% Creates or opens the CA database and stores the reference in the
%% application environment for use by handlers.
%%
%% == Configuration ==
%% The database file path can be configured via:
%% - Environment variable: `CRYPTIC_CA_DB_FILE`
%% - Application config: `{cryptic, [{ca_db_file, Path}]}'
%% - Default: `priv/ca/cryptic_ca.db`
%%
%% == Example ==
%% ```
%% {ok, DbRef} = cryptic_ca_app:init_ca(),
%% %% DbRef is now available via application:get_env(cryptic, ca_db_ref)
%% '''
%%
%% @returns {ok, DbRef} | {error, Reason}
-spec init_ca() -> {ok, term()} | {error, term()}.
init_ca() ->
    %% Get database file path from config
    DbFile = get_ca_db_file(),

    ?info("Initializing CA database: ~s", [DbFile]),

    %% Ensure directory exists
    DbDir = filename:dirname(DbFile),
    case filelib:ensure_dir(DbFile) of
        ok ->
            ok;
        {error, Reason} ->
            ?error("Failed to create CA database directory ~s: ~p", [
                DbDir, Reason
            ]),
            throw({error, {db_dir_creation_failed, Reason}})
    end,

    %% Initialize database
    case cryptic_ca_store:init(DbFile) of
        {ok, DbRef} ->
            %% Store reference in application environment
            application:set_env(cryptic, ca_db_ref, DbRef),
            {ok, DbRef};
        {error, InitReason} ->
            ?error("Failed to initialize CA database: ~p", [InitReason]),
            {error, InitReason}
    end.

%% @doc Get the CA database reference.
%%
%% Retrieves the database reference from the application environment.
%%
%% @returns {ok, DbRef} | {error, not_initialized}
-spec get_ca_db() -> {ok, term()} | {error, not_initialized}.
get_ca_db() ->
    case application:get_env(cryptic, ca_db_ref) of
        {ok, DbRef} ->
            {ok, DbRef};
        undefined ->
            {error, not_initialized}
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

%% @doc Get CA database file path from configuration.
-spec get_ca_db_file() -> string().
get_ca_db_file() ->
    %% Try environment variable first
    case os:getenv("CRYPTIC_CA_DB_FILE") of
        false ->
            %% Try application config
            case application:get_env(cryptic, ca_db_file) of
                {ok, Path} ->
                    Path;
                undefined ->
                    %% Use default path
                    PrivDir = code:priv_dir(cryptic),
                    filename:join([PrivDir, "ca", "cryptic_ca.db"])
            end;
        EnvPath ->
            EnvPath
    end.
