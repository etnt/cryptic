%%% Simple inline functions to update user metadata
%%% Copy-paste these directly into the Erlang shell of the running server

%% First, define the helper functions:

UpdateMetadata = fun(GpgFp, MetadataMap) when is_binary(GpgFp), is_map(MetadataMap) ->
    DbPath = application:get_env(cryptic, ca_db_path, "data/ca/cryptic_ca.db"),
    {ok, Conn} = esqlite3:open(DbPath),
    JsonMetadata = jsx:encode(MetadataMap),
    SQL = <<"UPDATE gpg_identities SET metadata = ?1 WHERE gpg_fp = ?2">>,
    Result = case esqlite3:q(Conn, SQL, [JsonMetadata, GpgFp]) of
        R when R =:= [] orelse R =:= ok ->
            io:format("✓ Updated metadata for ~s~n", [GpgFp]),
            ok;
        {error, Reason} = Error ->
            io:format("✗ Failed to update metadata for ~s: ~p~n", [GpgFp, Reason]),
            Error
    end,
    esqlite3:close(Conn),
    Result
end.

%% List all users without metadata:
ListNoMetadata = fun() ->
    DbPath = application:get_env(cryptic, ca_db_path, "data/ca/cryptic_ca.db"),
    {ok, Conn} = esqlite3:open(DbPath),
    SQL = <<"SELECT gpg_fp, registered_by, registered_at FROM gpg_identities "
            "WHERE metadata IS NULL OR metadata = '' OR metadata = '{}'">>,
    Rows = case esqlite3:q(Conn, SQL) of
        R when is_list(R) -> R;
        _ -> []
    end,
    esqlite3:close(Conn),
    io:format("~nUsers without metadata (~p total):~n", [length(Rows)]),
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
    Rows
end.

%% List all users with metadata:
ListAllMetadata = fun() ->
    DbPath = application:get_env(cryptic, ca_db_path, "data/ca/cryptic_ca.db"),
    {ok, Conn} = esqlite3:open(DbPath),
    SQL = <<"SELECT gpg_fp, metadata, status FROM gpg_identities ORDER BY registered_at DESC">>,
    Rows = case esqlite3:q(Conn, SQL) of
        R when is_list(R) -> R;
        _ -> []
    end,
    esqlite3:close(Conn),
    io:format("~nAll users (~p total):~n", [length(Rows)]),
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
                    case jsx:decode(MetaBin, [return_maps]) of
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
                    end
            end
        end,
        Rows
    ),
    Rows
end.

%% ========================================
%% USAGE EXAMPLES:
%% ========================================

%% 1. List all users without metadata:
%% ListNoMetadata().

%% 2. Update a single user:
%% UpdateMetadata(<<"ABCD1234...">>, #{
%%     <<"name">> => <<"John Doe">>,
%%     <<"team">> => <<"Engineering">>,
%%     <<"note">> => <<"Team lead">>
%% }).

%% 3. Update multiple users (map over a list):
%% Users = [
%%     {<<"FP1...">>, #{<<"name">> => <<"Alice">>, <<"team">> => <<"Security">>}},
%%     {<<"FP2...">>, #{<<"name">> => <<"Bob">>, <<"team">> => <<"Engineering">>}}
%% ],
%% lists:foreach(fun({GpgFp, Meta}) -> UpdateMetadata(GpgFp, Meta) end, Users).

%% 4. List all users with their metadata:
%% ListAllMetadata().

%% 5. Update based on the list:
%% NoMetaUsers = ListNoMetadata(),
%% %% Then manually create updates for each:
%% [GpgFp1, _, _] = lists:nth(1, NoMetaUsers),
%% UpdateMetadata(GpgFp1, #{<<"name">> => <<"Name Here">>, <<"team">> => <<"Team Here">>}).
