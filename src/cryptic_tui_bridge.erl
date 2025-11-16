%%%-------------------------------------------------------------------
%%% @doc
%%% Bridge module between cryptic event bus and Rust TUI.
%%% 
%%% This gen_server subscribes to the cryptic_event_bus and forwards
%%% relevant events to a Rust process via an Erlang port or direct
%%% message passing.
%%%
%%% The bridge filters for events that the TUI needs to display:
%%% - deliver_message: Decrypted messages from peers
%%% - system_message: Status updates
%%% - websocket_message: Server responses (user lists, etc.)
%%% @end
%%%-------------------------------------------------------------------
-module(cryptic_tui_bridge).
-behaviour(gen_server).

%% API
-export([start/3,
         start/4,
         stop/1,
         get_caller_node/0,
         get_recent_messages/3
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("cryptic.hrl").

-define(SERVER, ?MODULE).

-record(state,
        {
         rust_node :: atom() | undefined,
         username :: binary() | undefined,
         passphrase :: binary() | undefined,
         event_filter :: fun((map()) -> boolean()) | undefined,
         engine_pid :: pid() | undefined
        }).

%%%===================================================================
%%% API
%%%===================================================================


%% @doc Start the bridge with the Rust node name
-spec start(atom(), binary(), binary()) -> {ok, pid()} | {error, term()}.
start(RustNode, Username, Passphrase) when is_atom(RustNode) andalso
                                           is_binary(Username) andalso
                                           is_binary(Passphrase) ->
    start(RustNode, Username, Passphrase, undefined).

%% @doc Start the bridge with a custom event filter.
%% If Filter is undefined, a default filter for TUI events is used.
-spec start(atom(), binary(), binary(), fun((map()) -> boolean()) | undefined) ->
    {ok, pid()} | {error, term()}.
start(RustNode, Username, Passphrase, Filter) when is_atom(RustNode) andalso
                                                   is_binary(Username) andalso
                                                   is_binary(Passphrase) ->
    %% FIXME: A hardcoded Server name here means only one instance can run.
    %% This could be improved by allowing multiple instances with unique names.
    gen_server:start({local,?SERVER}, ?MODULE, [RustNode, Username, Passphrase, Filter], []).


-spec get_recent_messages(binary(), binary(), non_neg_integer()) ->
     {ok, binary()} | {error, term()}.
get_recent_messages(CurrentUser, Peer, Limit) ->
    gen_server:call(?SERVER, {get_recent_messages, CurrentUser, Peer, Limit}).

%% @doc Get the calling process's node name.
%% When called via RPC from Rust, this returns the Rust node's name.
%% This works because the RPC mechanism creates a process on the Erlang side
%% that acts as a proxy, and erlang:node(Pid) returns the node of that PID's origin.
-spec get_caller_node() -> atom().
get_caller_node() ->
    %% self() is the RPC handler process, which was spawned to handle the RPC call
    %% We need to find out which node initiated this call
    %% The calling process info contains the group leader which points to the remote node
    case erlang:process_info(self(), group_leader) of
        {group_leader, GL} ->
            erlang:node(GL);
        _ ->
            erlang:node(self())
    end.

%% @doc Stop the bridge process.
-spec stop(pid()) -> ok.
stop(BridgePid) ->
    gen_server:stop(BridgePid).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([RustNode, Username, Passphrase, CustomFilter]) ->
    process_flag(trap_exit, true),
    ?info("~p(~p) Started , RustNode=~p , CustomFilter=~p~n",
          [?MODULE,self(),RustNode, CustomFilter]),
    X = catch erlang:monitor_node(RustNode, true),
    ?dbg("~p: monitor_node result: ~p~n", [?MODULE, X]),

    EnginePid = get_engine_pid(),
    ?dbg("~p: got Engine Pid: ~p~n", [?MODULE, EnginePid]),

    %% Subscribe to event bus with appropriate filter
    Filter = case CustomFilter of
                 undefined -> default_tui_filter();
                 F when is_function(F, 1) -> F;
                 _ ->  default_tui_filter()
    end,

    try
        case
            cryptic_chat_storage:init_storage(binary_to_list(Username),
                                              Passphrase)
        of
            ok ->
                ok;
            {error, StorageReason} ->
                ?error("Failed initialise storage: ~p", [StorageReason]),
                throw({stop, StorageReason})
        end,
        case cryptic_event_bus:subscribe(self(), Filter) of
            ok ->
                ?info("TUI Bridge started, subscribed to event bus",[]),
                {ok, #state{rust_node    = RustNode,
                            username     = Username,
                            passphrase   = Passphrase,
                            engine_pid   = EnginePid,
                            event_filter = Filter}};
            {error, Reason} ->
                ?error("Failed to subscribe to event bus: ~p", [Reason]),
                throw({stop, Reason})
        end
    catch
        throw:{stop,StopReason} ->
            {stop, StopReason}
    end.



handle_call({get_recent_messages,CurrentUser,Peer,Limit} = R, _From, State) ->
    ?dbg("~p:handle_call , ~p~n",[?MODULE,R]),
    Reply =
        cryptic_chat_storage:get_conversation(
            binary_to_list(CurrentUser),
            binary_to_list(Peer),
            Limit,
            State#state.passphrase),
    ?dbg("~p:handle_call , Reply=~p~n",[?MODULE,Reply]),
    {reply, Reply, State};
%%
handle_call(_Request, _From, State) ->
    ?dbg("~p:handle_call got: ~p~n",[?MODULE,_Request]),
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    ?dbg("~p:handle_cast got: ~p~n",[?MODULE,_Msg]),
    {noreply, State}.

%% @doc Handle events from the event bus.
%% Events arrive as: {event, EventMap}
handle_info({event, EventMap}, #state{rust_node = RustTarget} = State) ->
    %% Forward event to Rust process
    case RustTarget of
        undefined ->
            ?warning("No Rust target configured, dropping event: ~p", [EventMap]);
        Pid when is_pid(Pid) ->
            ?dbg("Forward event to Rust PID: ~p", [EventMap]),
            %% Send directly to PID
            Pid ! {tui_event, EventMap};
        NodeName when is_atom(NodeName) ->
            ?dbg("~p Forward event to Rust node: ~p", [self(),NodeName]),
            %% Send to {cryptic_tui, NodeName}
            %% The name 'cryptic_tui' is arbitrary - Rust will receive all messages anyway
            %% We encode the EventMap to JSON here
            {cryptic_tui, NodeName} ! {tui_event, jsx:encode(EventMap)}
    end,
    {noreply, State};
%%
handle_info({nodedown, Node}, #state{rust_node = Node} = State) ->
    ?dbg("~p:handle_info got nodedown from: ~p~n",[?MODULE,Node]),
    {stop, nodedown, State};
%%
handle_info(_Info, State) ->
    ?dbg("~p:handle_info got: ~p~n",[?MODULE,_Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ?dbg("~p: TERMINATING , Reason=~p~n",[?MODULE,_Reason]),
    cryptic_event_bus:unsubscribe(self()),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get_engine_pid() ->
    cryptic_console ! {get_engine_pid, self()},
    receive
        {engine_pid, Pid} ->
            Pid
    after 3000 ->
        ?error("~p: could not get the Engine Pid!~n", [?MODULE]),
        undefined
    end.


%% @doc Default filter for TUI-relevant events.
%% Subscribes to:
%% - deliver_message: Decrypted messages to display
%% - system_message: Status updates
%% - websocket_message: Server responses
default_tui_filter() ->
    fun(Event) ->
        case Event of
            #{type := deliver_message} -> true;
            #{type := system_message} -> true;
            #{type := ca_response} -> true;
            #{type := websocket_message} -> true;
            _ -> false
        end
    end.
