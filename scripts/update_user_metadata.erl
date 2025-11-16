%% -*- erlang -*-
%%% @doc Temporary script to update user metadata in the CA database
%%%
%%% This script can be used to add or update metadata for existing users
%%% who were registered without metadata.
%%%
%%% Usage in Erlang shell:
%%% ```
%%% %% Load the module
%%% c("scripts/update_user_metadata.erl").
%%%
%%% %% Update a single user
%%% update_user_metadata:update_single("ABCD1234...", 
%%%     #{name => "John Doe", team => "Engineering", note => "Team lead"}).
%%%
%%% %% Update multiple users
%%% update_user_metadata:update_batch([
%%%     {"ABCD1234...", #{name => "John Doe", team => "Engineering"}},
%%%     {"EFGH5678...", #{name => "Jane Smith", team => "Security"}}
%%% ]).
%%%
%%% %% List all users without metadata
%%% update_user_metadata:list_users_without_metadata().
%%% ```

-module(update_user_metadata).
-export([
    update_single/2,
    update_batch/1,
    list_users_without_metadata/0,
    list_all_users_metadata/0
]).

%% Get the CA database connection
%% Assumes cryptic_ca_server is running
get_db_conn() ->
    %% Get the database path from application environment
    DbPath = application:get_env(cryptic, ca_db_path, "data/ca/cryptic_ca.db"),
    %% Open a connection (or get existing one from the server)
    %% For safety, we'll open our own connection
    case esqlite3:open(DbPath) of
        {ok, Conn} ->
            {ok, Conn};
        {error, Reason} ->
            {error, {db_open_failed, Reason}}
    end.

%% Close database connection
close_db_conn(Conn) ->
    esqlite3:close(Conn).

%% @doc Update metadata for a single user
%% @param GpgFp The GPG fingerprint of the user (binary or string)
%% @param Metadata Map with keys: name, team, note (all optional)
update_single(GpgFp, Metadata) when is_list(GpgFp) ->
    update_single(list_to_binary(GpgFp), Metadata);
update_single(GpgFp, Metadata) when is_binary(GpgFp), is_map(Metadata) ->
    case get_db_conn() of
        {ok, Conn} ->
            try
                Result = do_update_metadata(Conn, GpgFp, Metadata),
                close_db_conn(Conn),
                Result
            catch
                Class:Error:Stack ->
                    close_db_conn(Conn),
                    {error, {exception, Class, Error, Stack}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Update metadata for multiple users
%% @param UserList List of {GpgFp, Metadata} tuples
update_batch(UserList) when is_list(UserList) ->
    case get_db_conn() of
        {ok, Conn} ->
            try
                Results = lists:map(
                    fun({GpgFp, Metadata}) ->
                        GpgFpBin = if
                            is_list(GpgFp) -> list_to_binary(GpgFp);
                            true -> GpgFp
                        end,
                        {GpgFpBin, do_update_metadata(Conn, GpgFpBin, Metadata)}
                    end,
                    UserList
                ),
                close_db_conn(Conn),
                {ok, Results}
            catch
                Class:Error:Stack ->
                    close_db_conn(Conn),
                    {error, {exception, Class, Error, Stack}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc List all users who have no metadata (NULL or empty JSON)
list_users_without_metadata() ->
    case get_db_conn() of
        {ok, Conn} ->
            try
                SQL = <<"SELECT gpg_fp, registered_by, registered_at FROM gpg_identities "
                        "WHERE metadata IS NULL OR metadata = '' OR metadata = '{}'">>,
                case esqlite3:q(Conn, SQL) of
                    Rows when is_list(Rows) ->
                        close_db_conn(Conn),
                        io:format("~nUsers without metadata:~n"),
                        io:format("~s~n", [string:copies("-", 80)]),
                        lists:foreach(
                            fun([GpgFp, RegisteredBy, RegisteredAt]) ->
                                DateTime = calendar:system_time_to_rfc3339(RegisteredAt, 
                                    [{unit, second}, {offset, "Z"}]),
                                io:format("GPG FP: ~s~n", [GpgFp]),
                                io:format("  Registered by: ~s~n", [RegisteredBy]),
                                io:format("  Registered at: ~s~n~n", [DateTime])
                            end,
                            Rows
                        ),
                        {ok, length(Rows)};
                    {error, Reason} ->
                        close_db_conn(Conn),
                        {error, Reason}
                end
            catch
                Class:Error2:Stack ->
                    close_db_conn(Conn),
                    {error, {exception, Class, Error2, Stack}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc List all users with their current metadata
list_all_users_metadata() ->
    case get_db_conn() of
        {ok, Conn} ->
            try
                SQL = <<"SELECT gpg_fp, metadata, status FROM gpg_identities ORDER BY registered_at DESC">>,
                case esqlite3:q(Conn, SQL) of
                    Rows when is_list(Rows) ->
                        close_db_conn(Conn),
                        io:format("~nAll users and their metadata:~n"),
                        io:format("~s~n", [string:copies("=", 80)]),
                        lists:foreach(
                            fun([GpgFp, Metadata, Status]) ->
                                io:format("GPG FP: ~s [~s]~n", [GpgFp, Status]),
                                case Metadata of
                                    null -> 
                                        io:format("  Metadata: (none)~n~n");
                                    <<>> -> 
                                        io:format("  Metadata: (empty)~n~n");
                                    MetaBin ->
                                        try jsx:decode(MetaBin, [return_maps]) of
                                            MetaMap when is_map(MetaMap) ->
                                                maps:foreach(
                                                    fun(K, V) ->
                                                        io:format("  ~s: ~s~n", [K, V])
                                                    end,
                                                    MetaMap
                                                ),
                                                io:format("~n");
                                            _ ->
                                                io:format("  Metadata: ~s~n~n", [MetaBin])
                                        catch
                                            _:_ ->
                                                io:format("  Metadata: ~s~n~n", [MetaBin])
                                        end
                                end
                            end,
                            Rows
                        ),
                        {ok, length(Rows)};
                    {error, Reason} ->
                        close_db_conn(Conn),
                        {error, Reason}
                end
            catch
                Class:Error:Stack ->
                    close_db_conn(Conn),
                    {error, {exception, Class, Error, Stack}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Internal function to perform the metadata update
do_update_metadata(Conn, GpgFp, Metadata) ->
    %% Convert metadata map to JSON
    JsonMetadata = jsx:encode(Metadata),
    
    %% Update the database
    SQL = <<"UPDATE gpg_identities SET metadata = ?1 WHERE gpg_fp = ?2">>,
    case esqlite3:q(Conn, SQL, [JsonMetadata, GpgFp]) of
        Result when Result =:= [] orelse Result =:= ok ->
            io:format("✓ Updated metadata for ~s~n", [GpgFp]),
            ok;
        {error, Reason} = Error ->
            io:format("✗ Failed to update metadata for ~s: ~p~n", [GpgFp, Reason]),
            Error
    end.
