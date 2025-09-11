-module(cryptic_app).

-behaviour(application).

-export([start/2, stop/1]).

%% @doc Start the cryptic application
%%
%% This callback is invoked when the application is started.
%% Starts the supervisor which will then start the HTTP server.
%%
%% @param StartType The type of start requested
%% @param StartArgs The start arguments
%% @returns {ok, Pid} | {error, Reason}
start(_StartType, _StartArgs) ->
    %% Dependencies are automatically started by OTP based on the 'applications' list
    %% in cryptic.app.src, so we don't need to start them manually here
    cryptic_sup:start_link().

%% @doc Stop the cryptic application
%%
%% This callback is invoked when the application is stopped.
%% OTP will automatically terminate all processes in the supervision tree,
%% but we add additional cleanup here if needed.
%%
%% @param State The state passed from the application controller
%% @returns ok
stop(_State) ->
    %% Log that the application is stopping
    error_logger:info_msg("Stopping CRYPTIC application..."),
    ok.
