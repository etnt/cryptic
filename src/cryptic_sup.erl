%%%-------------------------------------------------------------------
%% @doc Cryptic top level supervisor.
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

    EventManager = #{id => cryptic_event_manager,
                     start => {gen_event, start_link, [{local, cryptic_event_manager}]},
                     modules => dynamic},

    %% Start the HTTP server as a child process
    CrypticServer =
        #{id => cryptic_server,
          start => {cryptic_server, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [cryptic_server]},

    ChildSpecs = [EventManager, CrypticServer],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions

%% @doc Stop the Cryptic application gracefully
stop() ->
    %% The supervisor will automatically terminate all children
    ok.
