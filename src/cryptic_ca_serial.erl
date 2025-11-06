%%%-------------------------------------------------------------------
%%% @doc Certificate serial number management
%%%
%%% Provides atomic serial number generation for X.509 certificates.
%%% Uses ETS for fast in-memory counters with periodic persistence
%%% to esqlite for recovery after restarts.
%%%
%%% Serial numbers are unique, monotonically increasing integers
%%% required for each issued certificate per RFC 5280.
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_ca_serial).

-behaviour(gen_server).

%% API
-export([start_link/0,
         next/0,
         current/0,
         reset/1,
         backup/0,
         restore/1]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2]).

-define(SERVER, ?MODULE).
-define(TABLE, cryptic_ca_serial).
-define(COUNTER_KEY, serial_counter).
-define(BACKUP_INTERVAL, 300000). % 5 minutes

-record(state, {
    db_ref :: reference() | undefined,
    last_backup :: integer()
}).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Start the serial number manager
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Get next serial number (atomic increment)
%% Returns a unique, monotonically increasing integer.
-spec next() -> pos_integer().
next() ->
    case ets:update_counter(?TABLE, ?COUNTER_KEY, {2, 1}) of
        Serial when is_integer(Serial), Serial > 0 ->
            % Notify server to check if backup needed
            gen_server:cast(?SERVER, backup_check),
            Serial;
        _Other ->
            error(serial_counter_failed)
    end.

%% @doc Get current serial number (without incrementing)
-spec current() -> non_neg_integer().
current() ->
    case ets:lookup(?TABLE, ?COUNTER_KEY) of
        [{?COUNTER_KEY, Serial}] -> Serial;
        [] -> 0
    end.

%% @doc Reset serial counter to specific value
%% WARNING: Only use for recovery or migration!
-spec reset(non_neg_integer()) -> ok.
reset(Serial) when is_integer(Serial), Serial >= 0 ->
    gen_server:call(?SERVER, {reset, Serial}).

%% @doc Force immediate backup to database
-spec backup() -> ok | {error, term()}.
backup() ->
    gen_server:call(?SERVER, backup).

%% @doc Restore serial counter from database
-spec restore(reference()) -> ok | {error, term()}.
restore(DbRef) ->
    gen_server:call(?SERVER, {restore, DbRef}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    % Create ETS table for fast atomic counter
    ?TABLE = ets:new(?TABLE, [named_table, public, set,
                               {write_concurrency, true},
                               {read_concurrency, true}]),
    
    % Initialize counter (will be updated from DB if exists)
    ets:insert(?TABLE, {?COUNTER_KEY, 0}),
    
    % Try to restore from database if configured
    % Use the already-initialized CA database connection
    DbRef = case application:get_env(cryptic, ca_db_ref) of
        {ok, Ref} ->
            create_table(Ref),
            restore_from_db(Ref),
            Ref;
        undefined ->
            error_logger:warning_msg(
                "~p: CA database not initialized~n",
                [?MODULE]),
            undefined
    end,

    % Schedule periodic backups
    erlang:send_after(?BACKUP_INTERVAL, self(), periodic_backup),

    {ok, #state{
        db_ref = DbRef,
        last_backup = erlang:system_time(second)
    }}.

handle_call({reset, Serial}, _From, State) ->
    ets:insert(?TABLE, {?COUNTER_KEY, Serial}),
    ok = write_to_db(State#state.db_ref, Serial),
    {reply, ok, State#state{last_backup = erlang:system_time(second)}};

handle_call(backup, _From, State) ->
    Serial = current(),
    Result = write_to_db(State#state.db_ref, Serial),
    {reply, Result, State#state{last_backup = erlang:system_time(second)}};

handle_call({restore, DbRef}, _From, State) ->
    case restore_from_db(DbRef) of
        ok ->
            {reply, ok, State#state{db_ref = DbRef}};
        {error, _} = Error ->
            {reply, Error, State}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(backup_check, State) ->
    % Check if backup needed (every 100 serials or 5 minutes)
    Serial = current(),
    Now = erlang:system_time(second),

    case should_backup(Serial, Now, State#state.last_backup) of
        true ->
            write_to_db(State#state.db_ref, Serial),
            {noreply, State#state{last_backup = Now}};
        false ->
            {noreply, State}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(periodic_backup, State) ->
    Serial = current(),
    write_to_db(State#state.db_ref, Serial),
    
    % Schedule next backup
    erlang:send_after(?BACKUP_INTERVAL, self(), periodic_backup),
    
    {noreply, State#state{last_backup = erlang:system_time(second)}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    % Final backup before shutdown
    Serial = current(),
    write_to_db(State#state.db_ref, Serial),
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private Create serial number table if not exists
create_table(DbRef) ->
    SQL = <<"
        CREATE TABLE IF NOT EXISTS ca_serial_numbers (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            serial_number INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
    ">>,
    
    case esqlite3:exec(DbRef, SQL) of
        ok -> ok;
        {error, Reason} ->
            error_logger:error_msg(
                "~p: Failed to create serial table: ~p~n",
                [?MODULE, Reason]),
            {error, Reason}
    end.

%% @private Restore counter from database
restore_from_db(undefined) ->
    {error, no_database};
restore_from_db(DbRef) ->
    SQL = <<"SELECT serial_number FROM ca_serial_numbers WHERE id = 1">>,
    
    case esqlite3:q(DbRef, SQL) of
        [[Serial]] when is_integer(Serial) ->
            ets:insert(?TABLE, {?COUNTER_KEY, Serial}),
            error_logger:info_msg(
                "~p: Restored serial number: ~p~n",
                [?MODULE, Serial]),
            ok;
        [] ->
            % No saved serial, query the max serial from certificates table
            MaxSerialSQL = <<"SELECT MAX(CAST(serial AS INTEGER)) FROM certificates">>,
            case esqlite3:q(DbRef, MaxSerialSQL) of
                [[MaxSerial]] when is_integer(MaxSerial) ->
                    % Start from next serial
                    NextSerial = MaxSerial + 1,
                    ets:insert(?TABLE, {?COUNTER_KEY, NextSerial}),
                    error_logger:info_msg(
                        "~p: Initialized serial from max certificate serial: ~p~n",
                        [?MODULE, NextSerial]),
                    ok;
                [[null]] ->
                    % No certificates yet, start from 1
                    ets:insert(?TABLE, {?COUNTER_KEY, 1}),
                    error_logger:info_msg(
                        "~p: No certificates found, starting from serial 1~n",
                        [?MODULE]),
                    ok;
                {error, Reason} ->
                    error_logger:error_msg(
                        "~p: Failed to query max serial: ~p, defaulting to 1~n",
                        [?MODULE, Reason]),
                    ets:insert(?TABLE, {?COUNTER_KEY, 1}),
                    ok
            end;
        {error, Reason} ->
            error_logger:error_msg(
                "~p: Failed to restore serial: ~p~n",
                [?MODULE, Reason]),
            {error, Reason}
    end.

%% @private Write serial to database
write_to_db(undefined, _Serial) ->
    ok; % No database configured, skip
write_to_db(DbRef, Serial) ->
    Now = erlang:system_time(second),
    SQL = <<"
        INSERT INTO ca_serial_numbers (id, serial_number, updated_at)
        VALUES (1, ?1, ?2)
        ON CONFLICT(id) DO UPDATE SET
            serial_number = ?1,
            updated_at = ?2
    ">>,
    
    case esqlite3:q(DbRef, SQL, [Serial, Now]) of
        [] -> ok;
        ok -> ok;
        {error, Reason} ->
            error_logger:error_msg(
                "~p: Failed to backup serial ~p: ~p~n",
                [?MODULE, Serial, Reason]),
            {error, Reason}
    end.

%% @private Determine if backup is needed
should_backup(Serial, Now, LastBackup) ->
    % Backup every 100 serials or every 5 minutes
    (Serial rem 100 == 0) orelse (Now - LastBackup >= 300).
