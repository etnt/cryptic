%%%-------------------------------------------------------------------
%% @doc cryptic top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(cryptic_sup).

-behaviour(supervisor).

-export([start_link/0, stop/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional
init([]) ->
    SupFlags =
        #{strategy => one_for_one,
          intensity => 10,
          period => 10},

    %% Start the HTTP server as a child process
    HTTPServerSpec =
        #{id => cryptic_server,
          start => {cryptic_server, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [cryptic_server]},

    ChildSpecs = [HTTPServerSpec],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions

%% @doc Stop the Cryptic application gracefully
stop() ->
    %% The supervisor will automatically terminate all children
    ok.
