-module(cryptic_app).

-behaviour(application).

-export([
    get_config/1,
    get_config/2,
    start/2,
    stop/1
]).

%% @doc Start the cryptic application
%%
%% This callback is invoked when the application is started.
%% Starts the supervisor which will then start the HTTP server.
%% Also initializes the CA subsystem.
%%
%% @param StartType The type of start requested
%% @param StartArgs The start arguments
%% @returns {ok, Pid} | {error, Reason}
start(_StartType, _StartArgs) ->
    %% Initialize CA database
    case cryptic_ca_app:init_ca() of
        {ok, _DbRef} ->
            error_logger:info_msg("CA subsystem initialized successfully"),
            ok;
        {error, Reason} ->
            error_logger:error_msg("Failed to initialize CA subsystem: ~p", [
                Reason
            ]),
            %% Continue anyway - CA features will be unavailable
            ok
    end,

    %% Dependencies are automatically started by OTP based on the 'applications' list
    %% in cryptic.app.src, so we don't need to start them manually here
    cryptic_sup:start_link().

%% @doc Stop the cryptic application
%%
%% This callback is invoked when the application is stopped.
%% OTP will automatically terminate all processes in the supervision tree,
%% but we add additional cleanup here if needed.
%% Also stops the CA subsystem.
%%
%% @param State The state passed from the application controller
%% @returns ok
stop(_State) ->
    %% Log that the application is stopping
    error_logger:info_msg("Stopping CRYPTIC application..."),

    %% Stop CA subsystem
    cryptic_ca_app:stop(undefined),

    ok.

%%
%% @doc Get the relevant Application config
%%
-spec get_config([Key :: atom()]) -> map().
get_config(Keys) ->
    get_config(Keys, #{}).

-spec get_config([Key :: atom()], Map :: map()) -> map().
get_config(Keys, CfgMap) ->
    lists:foldl(
        fun(Key, Map) ->
            case application:get_env(cryptic, Key) of
                {ok, Val} ->
                    maps:put(Key, Val, Map);
                _ ->
                    throw({missing_config, Key})
            end
        end,
        CfgMap,
        Keys
    ).
