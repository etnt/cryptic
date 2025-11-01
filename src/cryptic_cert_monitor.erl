%% @doc Certificate Expiration Monitor
%%
%% This gen_server monitors certificate expirations and sends warnings
%% when certificates are about to expire. It also automatically marks
%% expired certificates with 'expired' status.
%%
%% == Features ==
%% <ul>
%%   <li>Periodic checks for expiring certificates (configurable interval)</li>
%%   <li>Warning notifications for certificates expiring within threshold</li>
%%   <li>Automatic status update for expired certificates</li>
%%   <li>Audit logging for all expiration events</li>
%% </ul>
%%
%% == Configuration ==
%% ```
%% {cryptic_ca, [
%%     {cert_monitor_interval_secs, 3600},      %% Check every hour
%%     {cert_expiry_warning_days, 2}            %% Warn 2 days before expiry
%% ]}.
%% '''
%%
%% @author Cryptic Development Team
%% @since October 2025
-module(cryptic_cert_monitor).

-behaviour(gen_server).

-include("cryptic_ca.hrl").
-include("cryptic_server.hrl").

%% API
-export([
    start_link/0,
    check_expirations/0,
    get_status/0
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    db_ref :: term(),
    check_interval :: non_neg_integer(),    % seconds
    warning_threshold :: non_neg_integer(), % seconds
    last_check :: non_neg_integer(),        % unix timestamp
    stats :: map()
}).

%%====================================================================
%% API
%%====================================================================

%% @doc Start the certificate monitor server.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Trigger immediate expiration check.
-spec check_expirations() -> ok.
check_expirations() ->
    gen_server:cast(?MODULE, check_now).

%% @doc Get monitor status and statistics.
-spec get_status() -> map().
get_status() ->
    gen_server:call(?MODULE, get_status).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    %% Get database reference from cryptic_ca_init
    DbRef = case cryptic_ca_init:get_db_ref() of
        {ok, Ref} -> Ref;
        {error, Reason} ->
            ?error("Failed to get DB ref in cert_monitor: ~p", [Reason]),
            exit({db_init_failed, Reason})
    end,

    %% Get configuration
    CheckInterval = application:get_env(cryptic_ca, cert_monitor_interval_secs, 3600),
    WarningDays = application:get_env(cryptic_ca, cert_expiry_warning_days, 2),
    WarningThreshold = WarningDays * 24 * 3600,

    ?info("Certificate monitor started: check_interval=~ps, warning_threshold=~p days",
          [CheckInterval, WarningDays]),

    %% Schedule first check
    erlang:send_after(10000, self(), check_expirations), % 10s after startup

    State = #state{
        db_ref = DbRef,
        check_interval = CheckInterval,
        warning_threshold = WarningThreshold,
        last_check = 0,
        stats = #{
            total_checks => 0,
            total_warnings => 0,
            total_expired => 0
        }
    },

    {ok, State}.

handle_call(get_status, _From, State) ->
    Status = #{
        check_interval_secs => State#state.check_interval,
        warning_threshold_days => State#state.warning_threshold div (24 * 3600),
        last_check => State#state.last_check,
        statistics => State#state.stats
    },
    {reply, Status, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(check_now, State) ->
    NewState = perform_check(State),
    {noreply, NewState};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(check_expirations, State) ->
    NewState = perform_check(State),
    
    %% Schedule next check
    erlang:send_after(State#state.check_interval * 1000, self(), check_expirations),
    
    {noreply, NewState};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal functions
%%====================================================================

%% @doc Perform expiration check cycle.
-spec perform_check(#state{}) -> #state{}.
perform_check(State) ->
    DbRef = State#state.db_ref,
    Now = erlang:system_time(second),
    
    ?debug("Starting certificate expiration check", []),
    
    %% Step 1: Mark expired certificates
    ExpiredCount = case cryptic_ca_store:cleanup_expired_certificates(DbRef) of
        {ok, Count} ->
            if
                Count > 0 ->
                    ?info("Marked ~p certificates as expired", [Count]),
                    log_expired_certificates(DbRef, Count);
                true ->
                    ok
            end,
            Count;
        {error, CleanupReason} ->
            ?error("Failed to cleanup expired certificates: ~p", [CleanupReason]),
            0
    end,
    
    %% Step 2: Check for certificates expiring soon
    WarningCount = case cryptic_ca_store:list_expiring_certificates(
                          DbRef, State#state.warning_threshold) of
        {ok, ExpiringCerts} ->
            lists:foreach(
                fun(Cert) -> send_expiry_warning(DbRef, Cert) end,
                ExpiringCerts
            ),
            length(ExpiringCerts);
        {error, ListReason} ->
            ?error("Failed to list expiring certificates: ~p", [ListReason]),
            0
    end,
    
    %% Update statistics
    Stats = State#state.stats,
    NewStats = Stats#{
        total_checks => maps:get(total_checks, Stats, 0) + 1,
        total_warnings => maps:get(total_warnings, Stats, 0) + WarningCount,
        total_expired => maps:get(total_expired, Stats, 0) + ExpiredCount
    },
    
    ?debug("Expiration check complete: expired=~p, warnings=~p", 
           [ExpiredCount, WarningCount]),
    
    State#state{
        last_check = Now,
        stats = NewStats
    }.

%% @doc Send expiry warning for a certificate.
-spec send_expiry_warning(term(), #certificate{}) -> ok.
send_expiry_warning(DbRef, Cert) ->
    Now = erlang:system_time(second),
    TimeLeft = Cert#certificate.expires_at - Now,
    DaysLeft = TimeLeft div (24 * 3600),
    HoursLeft = (TimeLeft rem (24 * 3600)) div 3600,
    
    ?warning("Certificate ~s for user ~s expires in ~p days, ~p hours",
             [Cert#certificate.serial, Cert#certificate.gpg_fp, DaysLeft, HoursLeft]),
    
    %% Log to audit trail
    AuditLog = #audit_log{
        timestamp = Now,
        event_type = <<"certificate_expiry_warning">>,
        gpg_fp = Cert#certificate.gpg_fp,
        invite_id = undefined,
        details = iolist_to_binary(
            io_lib:format("Certificate ~s expires in ~p days, ~p hours", 
                          [Cert#certificate.serial, DaysLeft, HoursLeft])
        ),
        ip_address = undefined
    },
    cryptic_ca_store:insert_audit_log(DbRef, AuditLog),
    
    %% TODO: Send notification to user (email, websocket, etc.)
    %% For now, just log to console
    ok.

%% @doc Log expired certificates to audit trail.
-spec log_expired_certificates(term(), non_neg_integer()) -> ok.
log_expired_certificates(DbRef, Count) ->
    Now = erlang:system_time(second),
    AuditLog = #audit_log{
        timestamp = Now,
        event_type = <<"certificates_auto_expired">>,
        gpg_fp = undefined,
        invite_id = undefined,
        details = iolist_to_binary(
            io_lib:format("Automatically marked ~p certificates as expired", [Count])
        ),
        ip_address = undefined
    },
    cryptic_ca_store:insert_audit_log(DbRef, AuditLog),
    ok.
