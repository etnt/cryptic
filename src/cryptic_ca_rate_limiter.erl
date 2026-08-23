%%%-------------------------------------------------------------------
%%% @doc Rate limiting middleware for CA operations
%%%
%%% Implements token bucket algorithm with multiple limit dimensions:
%%% - Per-IP address limits (public endpoints)
%%% - Per-GPG fingerprint limits (authenticated operations)
%%% - Per-operation type limits
%%%
%%% Uses ETS for fast in-memory tracking with TTL-based cleanup.
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_ca_rate_limiter).

-behaviour(gen_server).

%% API
-export([
    start_link/0,
    start/0,
    check_limit/3,
    check_limit/4,
    reset_limits/1,
    get_stats/0,
    get_stats/1
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

-define(SERVER, ?MODULE).
% 1 minute
-define(CLEANUP_INTERVAL, 60000).

%% Rate limit policies (default values, configurable via sys.config)
-define(DEFAULT_LIMITS, #{
    %% Invite operations (per GPG fingerprint per day)

    % 10 invites per day
    invite_create => {10, 86400},
    % 100 lists per hour
    invite_list => {100, 3600},
    % 50 revokes per hour
    invite_revoke => {50, 3600},

    %% Registration (per IP per hour)

    % 100 attempts per hour
    register_gpg => {100, 3600},

    %% CSR operations (per GPG fingerprint per hour)

    % 50 CSR requests per hour
    csr => {50, 3600},

    %% Status checks (per IP per hour)

    % 200 status checks per hour
    status => {200, 3600},

    %% Web admin login attempts (per IP)

    % 10 login attempts per 5 minutes
    admin_login => {10, 300}
}).

-record(state, {
    % Operation -> {MaxTokens, WindowSeconds}
    limits :: map(),
    cleanup_timer :: reference()
}).

-record(bucket, {
    % {Identifier, Operation}
    key :: {binary(), atom()},
    % Available tokens
    tokens :: float(),
    % Timestamp of last update
    last_update :: integer(),
    % Maximum tokens
    max_tokens :: integer(),
    % Tokens per second
    refill_rate :: float()
}).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Start the rate limiter (with link)
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Start the rate limiter (without link, for testing)
-spec start() -> {ok, pid()} | {error, term()}.
start() ->
    gen_server:start({local, ?SERVER}, ?MODULE, [], []).

%% @doc Check if operation is allowed for identifier (3-arg version)
%% @param Identifier - IP address or GPG fingerprint (binary)
%% @param Operation - atom() identifying the operation type
%% @param Cost - number of tokens to consume (default 1)
-spec check_limit(binary(), atom(), number()) ->
    {ok, Remaining :: integer()}
    | {error, rate_limited, RetryAfter :: integer()}.
check_limit(Identifier, Operation, Cost) ->
    gen_server:call(?SERVER, {check_limit, Identifier, Operation, Cost}).

%% @doc Check if operation is allowed (4-arg version for backward compatibility)
-spec check_limit(binary(), atom(), number(), map()) ->
    {ok, Remaining :: integer()}
    | {error, rate_limited, RetryAfter :: integer()}.
check_limit(Identifier, Operation, Cost, _Opts) ->
    check_limit(Identifier, Operation, Cost).

%% @doc Reset limits for a specific identifier (for testing/admin)
-spec reset_limits(binary()) -> ok.
reset_limits(Identifier) ->
    gen_server:cast(?SERVER, {reset_limits, Identifier}).

%% @doc Get rate limiting statistics
-spec get_stats() -> map().
get_stats() ->
    gen_server:call(?SERVER, get_stats).

%% @doc Get statistics for specific identifier
-spec get_stats(binary()) -> map().
get_stats(Identifier) ->
    gen_server:call(?SERVER, {get_stats, Identifier}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    %% Create ETS table for buckets
    ets:new(rate_limit_buckets, [named_table, set, protected, {keypos, 2}]),

    %% Load configuration or use defaults
    Limits = load_limits(),

    %% Schedule cleanup
    Timer = erlang:send_after(?CLEANUP_INTERVAL, self(), cleanup),

    {ok, #state{limits = Limits, cleanup_timer = Timer}}.

handle_call({check_limit, Identifier, Operation, Cost}, _From, State) ->
    case maps:get(Operation, State#state.limits, undefined) of
        undefined ->
            %% No limit configured for this operation, allow
            {reply, {ok, unlimited}, State};
        {MaxTokens, WindowSeconds} ->
            Key = {Identifier, Operation},
            Now = erlang:system_time(second),

            %% Get or create bucket
            Bucket =
                case ets:lookup(rate_limit_buckets, Key) of
                    [] ->
                        %% Create new bucket
                        RefillRate = MaxTokens / WindowSeconds,
                        #bucket{
                            key = Key,
                            tokens = MaxTokens,
                            last_update = Now,
                            max_tokens = MaxTokens,
                            refill_rate = RefillRate
                        };
                    [B] ->
                        %% Refill tokens based on time elapsed
                        TimeDelta = Now - B#bucket.last_update,
                        NewTokens = min(
                            B#bucket.max_tokens,
                            B#bucket.tokens + (TimeDelta * B#bucket.refill_rate)
                        ),
                        B#bucket{tokens = NewTokens, last_update = Now}
                end,

            %% Check if enough tokens available
            if
                Bucket#bucket.tokens >= Cost ->
                    %% Consume tokens
                    UpdatedBucket = Bucket#bucket{
                        tokens = Bucket#bucket.tokens - Cost
                    },
                    ets:insert(rate_limit_buckets, UpdatedBucket),
                    Remaining = trunc(UpdatedBucket#bucket.tokens),
                    {reply, {ok, Remaining}, State};
                true ->
                    %% Rate limited - calculate retry after
                    TokensNeeded = Cost - Bucket#bucket.tokens,
                    RetryAfter = ceil(TokensNeeded / Bucket#bucket.refill_rate),
                    {reply, {error, rate_limited, RetryAfter}, State}
            end
    end;
handle_call(get_stats, _From, State) ->
    Stats = #{
        total_buckets => ets:info(rate_limit_buckets, size),
        limits => State#state.limits,
        buckets => get_all_bucket_stats()
    },
    {reply, Stats, State};
handle_call({get_stats, Identifier}, _From, State) ->
    Pattern = #bucket{key = {Identifier, '_'}, _ = '_'},
    Buckets = ets:match_object(rate_limit_buckets, Pattern),
    Stats = lists:map(
        fun(B) ->
            {_Id, Op} = B#bucket.key,
            #{
                operation => Op,
                tokens_available => trunc(B#bucket.tokens),
                max_tokens => B#bucket.max_tokens,
                refill_rate => B#bucket.refill_rate
            }
        end,
        Buckets
    ),
    {reply, #{identifier => Identifier, buckets => Stats}, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({reset_limits, Identifier}, State) ->
    Pattern = #bucket{key = {Identifier, '_'}, _ = '_'},
    ets:match_delete(rate_limit_buckets, Pattern),
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(cleanup, State) ->
    %% Remove stale buckets (fully refilled for 10x window duration)
    Now = erlang:system_time(second),
    % 10 minutes
    StaleThreshold = 600,

    Pattern = #bucket{_ = '_'},
    AllBuckets = ets:match_object(rate_limit_buckets, Pattern),

    lists:foreach(
        fun(Bucket) ->
            TimeSinceUpdate = Now - Bucket#bucket.last_update,
            %% If bucket is full and hasn't been used in a while, remove it
            if
                Bucket#bucket.tokens >= Bucket#bucket.max_tokens andalso
                    TimeSinceUpdate > StaleThreshold ->
                    ets:delete(rate_limit_buckets, Bucket#bucket.key);
                true ->
                    ok
            end
        end,
        AllBuckets
    ),

    %% Schedule next cleanup
    Timer = erlang:send_after(?CLEANUP_INTERVAL, self(), cleanup),
    {noreply, State#state{cleanup_timer = Timer}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    erlang:cancel_timer(State#state.cleanup_timer),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private Load rate limits from configuration or use defaults
load_limits() ->
    case application:get_env(cryptic, ca_rate_limits) of
        {ok, Limits} when is_map(Limits) ->
            maps:merge(?DEFAULT_LIMITS, Limits);
        _ ->
            ?DEFAULT_LIMITS
    end.

%% @private Get statistics for all buckets
get_all_bucket_stats() ->
    Pattern = #bucket{_ = '_'},
    Buckets = ets:match_object(rate_limit_buckets, Pattern),
    lists:map(
        fun(B) ->
            {Id, Op} = B#bucket.key,
            #{
                identifier => Id,
                operation => Op,
                tokens => trunc(B#bucket.tokens),
                max_tokens => B#bucket.max_tokens
            }
        end,
        Buckets
    ).
