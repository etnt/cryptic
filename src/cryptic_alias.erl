%%% @doc Cryptic Alias - Poor man's chat room functionality
%%%
%%% This module provides alias functionality for sending messages to multiple
%%% users at once. An alias is a named group of users that can be referenced
%%% with the @ symbol when sending messages.
%%%
%%% == Features ==
%%% <ul>
%%%   <li>Create aliases for groups of users</li>
%%%   <li>Add/remove members from aliases</li>
%%%   <li>List all aliases and their members</li>
%%%   <li>Send messages to all alias members with @alias syntax</li>
%%% </ul>
%%%
%%% == Usage Example ==
%%% ```
%%% %% Create aliases
%%% cryptic_alias:initialize(),
%%% cryptic_alias:new("work", ["alice", "bob", "dave"]),
%%% cryptic_alias:new("gym", ["bob", "dave"]),
%%%
%%% %% List aliases
%%% cryptic_alias:list_all(),
%%% %% Returns: [{"work", ["alice", "bob", "dave"]}, {"gym", ["bob", "dave"]}]
%%%
%%% %% Get members of specific alias
%%% cryptic_alias:list("work"),
%%% %% Returns: {ok, ["alice", "bob", "dave"]}
%%%
%%% %% Modify aliases
%%% cryptic_alias:add("work", ["eve"]),
%%% cryptic_alias:rm("gym", ["dave"]),
%%% cryptic_alias:delete("gym")
%%% '''
%%%
%%% @author Cryptic Team
%%% @version 1.0.0

-module(cryptic_alias).

%% API exports
-export([
    initialize/0,
    new/2,
    delete/1,
    add/2,
    rm/2,
    list/1,
    list_all/0,
    is_alias/1,
    get_table/0
]).

%% ETS table name
-define(ALIAS_TABLE, cryptic_aliases).

%%%===================================================================
%%% API Functions
%%%===================================================================

%% @doc Initialize the alias storage
%% Creates an ETS table to hold alias definitions.
%% The table is a set (unique keys) and is public for easy access.
-spec initialize() -> ok | {error, already_exists}.
initialize() ->
    case ets:whereis(?ALIAS_TABLE) of
        undefined ->
            ets:new(?ALIAS_TABLE, [
                named_table,
                set,
                public,
                {read_concurrency, true}
            ]),
            ok;
        _Ref ->
            {error, already_exists}
    end.

%% @doc Create a new alias with given members
%% The alias name should not include the @ symbol.
-spec new(string() | binary(), [string() | binary()]) ->
    ok | {error, alias_exists | invalid_name | invalid_members}.
new(Alias, Members) when is_list(Alias), is_list(Members) ->
    %% Validate alias name
    case validate_alias_name(Alias) of
        ok ->
            %% Normalize members to strings
            NormalizedMembers = normalize_members(Members),
            case NormalizedMembers of
                {error, Reason} ->
                    {error, Reason};
                [] ->
                    {error, invalid_members};
                _ ->
                    %% Check if alias already exists
                    case ets:whereis(?ALIAS_TABLE) of
                        undefined ->
                            {error, not_initialized};
                        _Ref ->
                            case ets:lookup(?ALIAS_TABLE, Alias) of
                                [] ->
                                    %% Store unique members
                                    UniqueMembers = lists:usort(
                                        NormalizedMembers
                                    ),
                                    ets:insert(
                                        ?ALIAS_TABLE, {Alias, UniqueMembers}
                                    ),
                                    ok;
                                [{Alias, _}] ->
                                    {error, alias_exists}
                            end
                    end
            end;
        {error, Reason} ->
            {error, Reason}
    end;
new(Alias, Members) when is_binary(Alias) ->
    new(binary_to_list(Alias), Members);
new(_Alias, _Members) ->
    {error, invalid_name}.

%% @doc Delete an alias
-spec delete(string() | binary()) -> ok | {error, not_found | not_initialized}.
delete(Alias) when is_list(Alias) ->
    case ets:whereis(?ALIAS_TABLE) of
        undefined ->
            {error, not_initialized};
        _Ref ->
            case ets:lookup(?ALIAS_TABLE, Alias) of
                [] ->
                    {error, not_found};
                [{Alias, _}] ->
                    ets:delete(?ALIAS_TABLE, Alias),
                    ok
            end
    end;
delete(Alias) when is_binary(Alias) ->
    delete(binary_to_list(Alias)).

%% @doc Add members to an existing alias
-spec add(string() | binary(), [string() | binary()]) ->
    ok | {error, not_found | invalid_members | not_initialized}.
add(Alias, NewMembers) when is_list(Alias), is_list(NewMembers) ->
    case ets:whereis(?ALIAS_TABLE) of
        undefined ->
            {error, not_initialized};
        _Ref ->
            case ets:lookup(?ALIAS_TABLE, Alias) of
                [] ->
                    {error, not_found};
                [{Alias, CurrentMembers}] ->
                    NormalizedMembers = normalize_members(NewMembers),
                    case NormalizedMembers of
                        {error, Reason} ->
                            {error, Reason};
                        [] ->
                            ok;
                        _ ->
                            %% Merge and deduplicate
                            UpdatedMembers = lists:usort(
                                CurrentMembers ++ NormalizedMembers
                            ),
                            ets:insert(?ALIAS_TABLE, {Alias, UpdatedMembers}),
                            ok
                    end
            end
    end;
add(Alias, NewMembers) when is_binary(Alias) ->
    add(binary_to_list(Alias), NewMembers).

%% @doc Remove members from an alias
-spec rm(string() | binary(), [string() | binary()]) ->
    ok | {error, not_found | not_initialized}.
rm(Alias, MembersToRemove) when is_list(Alias), is_list(MembersToRemove) ->
    case ets:whereis(?ALIAS_TABLE) of
        undefined ->
            {error, not_initialized};
        _Ref ->
            case ets:lookup(?ALIAS_TABLE, Alias) of
                [] ->
                    {error, not_found};
                [{Alias, CurrentMembers}] ->
                    NormalizedRemove = normalize_members(MembersToRemove),
                    case NormalizedRemove of
                        {error, _Reason} ->
                            %% Just ignore invalid members on removal
                            ok;
                        [] ->
                            ok;
                        _ ->
                            %% Remove members
                            UpdatedMembers = CurrentMembers -- NormalizedRemove,
                            ets:insert(?ALIAS_TABLE, {Alias, UpdatedMembers}),
                            ok
                    end
            end
    end;
rm(Alias, MembersToRemove) when is_binary(Alias) ->
    rm(binary_to_list(Alias), MembersToRemove).

%% @doc Get the list of members for a specific alias
-spec list(string() | binary()) ->
    {ok, [string()]} | {error, not_found | not_initialized}.
list(Alias) when is_list(Alias) ->
    case ets:whereis(?ALIAS_TABLE) of
        undefined ->
            {error, not_initialized};
        _Ref ->
            case ets:lookup(?ALIAS_TABLE, Alias) of
                [] ->
                    {error, not_found};
                [{Alias, Members}] ->
                    {ok, Members}
            end
    end;
list(Alias) when is_binary(Alias) ->
    list(binary_to_list(Alias)).

%% @doc List all aliases and their members
-spec list_all() -> [{string(), [string()]}] | {error, not_initialized}.
list_all() ->
    case ets:whereis(?ALIAS_TABLE) of
        undefined ->
            {error, not_initialized};
        _Ref ->
            %% Get all aliases sorted by name
            Aliases = ets:tab2list(?ALIAS_TABLE),
            lists:sort(Aliases)
    end.

%% @doc Check if a name is an alias
-spec is_alias(string() | binary()) -> boolean().
is_alias(Name) when is_list(Name) ->
    case ets:whereis(?ALIAS_TABLE) of
        undefined ->
            false;
        _Ref ->
            case ets:lookup(?ALIAS_TABLE, Name) of
                [] -> false;
                [{Name, _}] -> true
            end
    end;
is_alias(Name) when is_binary(Name) ->
    is_alias(binary_to_list(Name)).

%% @doc Get the ETS table reference (for testing/debugging)
-spec get_table() -> atom().
get_table() ->
    ?ALIAS_TABLE.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%% @doc Validate alias name
%% Alias names must be non-empty, alphanumeric (plus underscore/hyphen)
-spec validate_alias_name(string()) -> ok | {error, invalid_name}.
validate_alias_name([]) ->
    {error, invalid_name};
validate_alias_name(Name) when is_list(Name) ->
    %% Check if all characters are valid (alphanumeric, underscore, hyphen)
    Valid = lists:all(
        fun(C) ->
            (C >= $a andalso C =< $z) orelse
                (C >= $A andalso C =< $Z) orelse
                (C >= $0 andalso C =< $9) orelse
                C == $_ orelse
                C == $-
        end,
        Name
    ),
    case Valid of
        true -> ok;
        false -> {error, invalid_name}
    end.

%% @doc Normalize members to a list of strings
-spec normalize_members([string() | binary()]) ->
    [string()] | {error, invalid_members}.
normalize_members(Members) when is_list(Members) ->
    try
        Normalized = lists:map(
            fun
                (M) when is_binary(M) -> binary_to_list(M);
                (M) when is_list(M) -> M;
                (_) -> throw(invalid_member)
            end,
            Members
        ),
        %% Filter out empty strings
        lists:filter(fun(M) -> M =/= [] end, Normalized)
    catch
        throw:invalid_member ->
            {error, invalid_members}
    end.
