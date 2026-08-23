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

    %% CA database initializer (must start after event manager)
    CaInit =
        #{id => cryptic_ca_init,
          start => {cryptic_ca_init, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [cryptic_ca_init]},

    %% CA serial number manager
    CaSerialManager =
        #{id => cryptic_ca_serial,
          start => {cryptic_ca_serial, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [cryptic_ca_serial]},

    %% CA rate limiter
    CaRateLimiter =
        #{id => cryptic_ca_rate_limiter,
          start => {cryptic_ca_rate_limiter, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [cryptic_ca_rate_limiter]},

    %% Web admin session store (ETS-backed sessions + cleanup)
    AdminSession =
        #{id => cryptic_admin_session,
          start => {cryptic_admin_session, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [cryptic_admin_session]},

    %% Certificate expiration monitor
    CertMonitor =
        #{id => cryptic_cert_monitor,
          start => {cryptic_cert_monitor, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [cryptic_cert_monitor]},

    %% Start the HTTP server as a child process (must start after CA init)
    CrypticServer =
        #{id => cryptic_server,
          start => {cryptic_server, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [cryptic_server]},

    ChildSpecs = [EventManager, CaInit, CaSerialManager,
                  CaRateLimiter, AdminSession, CertMonitor, CrypticServer],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions

%% @doc Stop the Cryptic application gracefully
stop() ->
    %% The supervisor will automatically terminate all children
    ok.
