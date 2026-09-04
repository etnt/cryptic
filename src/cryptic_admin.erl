%%% @doc Cryptic Admin - Interactive shell convenience functions
%%%
%%% This module provides admin commands that can be called directly from
%%% the Erlang shell when running the Cryptic server interactively.
%%%
%%% == Quick Start ==
%%% ```
%%% 1> cryptic_admin:help().
%%% 2> cryptic_admin:users().
%%% 3> cryptic_admin:online().
%%% 4> cryptic_admin:status().
%%% '''
%%%
%%% All functions print formatted output to the console and return `ok'.
%%% @end

-module(cryptic_admin).

-include("cryptic_server.hrl").
-include("cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    help/0,
    status/0,
    users/0,
    online/0,
    user/1,
    pending/0,
    pending/1,
    keys/0,
    keys/1,
    connections/0,
    suspend/1,
    reactivate/1,
    certs/1,
    audit/0,
    audit/1
]).

%%%===================================================================
%%% Help
%%%===================================================================

%% @doc Show available admin commands.
-spec help() -> ok.
help() ->
    io:format("~n  Cryptic Server Admin Commands~n"),
    io:format("  ═════════════════════════════~n~n"),
    io:format("  status()          - Server overview (listeners, tables, CA)~n"),
    io:format("  users()           - List all registered users with status~n"),
    io:format("  online()          - List currently connected users~n"),
    io:format("  user(Query)       - Detailed info for a user (name or GPG fp)~n"),
    io:format("  connections()     - Show WebSocket connection details~n"),
    io:format("  pending()         - Summary of queued offline messages~n"),
    io:format("  pending(User)     - Queued messages for a specific user~n"),
    io:format("  keys()            - Summary of uploaded key bundles~n"),
    io:format("  keys(User)        - Key bundle details for a user~n"),
    io:format("  suspend(GpgFp)    - Suspend a user by GPG fingerprint~n"),
    io:format("  reactivate(GpgFp) - Reactivate a suspended user~n"),
    io:format("  certs(GpgFp)      - List certificates for a user~n"),
    io:format("  audit()           - Show recent audit log entries~n"),
    io:format("  audit(N)          - Show last N audit log entries~n"),
    io:format("~n  Arguments accept strings, binaries, or atoms.~n~n"),
    ok.

%%%===================================================================
%%% Server Status
%%%===================================================================

%% @doc Show server overview: listener status, ETS table sizes, CA state.
-spec status() -> ok.
status() ->
    io:format("~n  Cryptic Server Status~n"),
    io:format("  ═════════════════════~n~n"),

    %% Listener
    try ranch:info(cryptic_ws_listener) of
        Info when is_map(Info) ->
            Port = maps:get(port, Info, unknown),
            ActiveConns = ranch:procs(cryptic_ws_listener, connections),
            io:format("  Listener:      running on port ~p~n", [Port]),
            io:format("  Active conns:  ~p~n", [length(ActiveConns)]);
        _ ->
            io:format("  Listener:      not running~n")
    catch
        _:_ ->
            io:format("  Listener:      not running~n")
    end,

    %% ETS tables
    io:format("~n  ETS Tables~n"),
    io:format("  ──────────~n"),
    Tables = [{?CONNECTION_TABLE, "Connections"},
              {?USER_TABLE, "Registered users"},
              {?MESSAGE_TABLE, "Pending messages"},
              {?PREKEY_TABLE, "Prekey entries"}],
    lists:foreach(fun({Table, Label}) ->
        case ets:info(Table, size) of
            undefined ->
                io:format("  ~-20ts  (not created)~n", [Label]);
            Size ->
                io:format("  ~-20ts  ~p~n", [Label, Size])
        end
    end, Tables),

    %% CA status
    io:format("~n  Certificate Authority~n"),
    io:format("  ─────────────────────~n"),
    case get_db_ref() of
        {ok, DbRef} ->
            case cryptic_ca_store:list_gpg_identities(DbRef) of
                {ok, Identities} ->
                    Active = length([I || I <- Identities,
                                         I#gpg_identity.status =:= <<"active">>]),
                    Suspended = length([I || I <- Identities,
                                             I#gpg_identity.status =:= <<"suspended">>]),
                    Revoked = length([I || I <- Identities,
                                           I#gpg_identity.status =:= <<"revoked">>]),
                    io:format("  CA database:   connected~n"),
                    io:format("  Identities:    ~p active, ~p suspended, ~p revoked~n",
                              [Active, Suspended, Revoked]);
                {error, Reason} ->
                    io:format("  CA database:   error (~p)~n", [Reason])
            end;
        {error, _} ->
            io:format("  CA database:   not available~n")
    end,

    %% Database location
    io:format("~n  Paths~n"),
    io:format("  ─────~n"),
    DbPath = filename:absname(get_ca_db_path()),
    io:format("  CA database:     ~ts~n", [DbPath]),
    BootstrapDir = filename:absname(cryptic_ca_bootstrap:get_bootstrap_dir()),
    io:format("  Bootstrap dir:   ~ts~n", [BootstrapDir]),

    %% List bootstrap admin files and names
    print_bootstrap_admins(BootstrapDir),

    io:format("~n"),
    ok.

%%%===================================================================
%%% User Listing
%%%===================================================================

%% @doc List all registered users with their status and online indicator.
-spec users() -> ok.
users() ->
    case get_db_ref() of
        {ok, DbRef} ->
            case cryptic_ca_store:list_gpg_identities(DbRef) of
                {ok, Identities} ->
                    io:format("~n  Registered Users (~p)~n", [length(Identities)]),
                    io:format("  ═══════════════════════~n~n"),
                    print_users_table(DbRef, Identities),
                    io:format("~n");
                {error, Reason} ->
                    io:format("  Error listing users: ~p~n", [Reason])
            end;
        {error, _} ->
            %% Fall back to ETS-only view
            io:format("~n  Registered Users (ETS only, CA not available)~n"),
            io:format("  ═════════════════════════════════════════════~n~n"),
            EtsUsers = ets:tab2list(?USER_TABLE),
            lists:foreach(fun({Username, Timestamp}) ->
                Online = is_online(Username),
                OnlineStr = case Online of true -> "* "; false -> "  " end,
                TimeStr = format_timestamp(Timestamp),
                io:format("  ~ts~-20ts  registered ~ts~n",
                          [OnlineStr, Username, TimeStr])
            end, lists:sort(EtsUsers)),
            io:format("~n  (* = online)~n~n")
    end,
    ok.

%% @doc List currently connected users.
-spec online() -> ok.
online() ->
    Connections = ets:tab2list(?CONNECTION_TABLE),
    case Connections of
        [] ->
            io:format("~n  No users currently online.~n~n");
        _ ->
            io:format("~n  Online Users (~p)~n", [length(Connections)]),
            io:format("  ═════════════════~n~n"),
            lists:foreach(fun({Username, Pid}) ->
                io:format("  ~-24ts  pid=~p~n", [Username, Pid])
            end, lists:sort(Connections)),
            io:format("~n")
    end,
    ok.

%%%===================================================================
%%% User Detail
%%%===================================================================

%% @doc Show detailed info for a user.
%% Query can be a username (string/binary/atom) or GPG fingerprint.
-spec user(string() | binary() | atom()) -> ok.
user(Query) ->
    Q = to_string(Query),
    case get_db_ref() of
        {ok, DbRef} ->
            %% Try as GPG fingerprint first (40 hex chars)
            case try_gpg_lookup(DbRef, Q) of
                {ok, Identity} ->
                    print_user_detail(DbRef, Identity);
                not_found ->
                    %% Try matching by username via certificate CN
                    case find_gpg_by_username(DbRef, Q) of
                        {ok, Identity} ->
                            print_user_detail(DbRef, Identity);
                        not_found ->
                            io:format("~n  User not found: ~ts~n~n", [Q])
                    end
            end;
        {error, _} ->
            %% ETS only fallback
            case ets:lookup(?USER_TABLE, Q) of
                [{Q, Timestamp}] ->
                    io:format("~n  User: ~ts~n", [Q]),
                    io:format("  Registered: ~ts~n", [format_timestamp(Timestamp)]),
                    io:format("  Online:     ~p~n~n", [is_online(Q)]);
                [] ->
                    io:format("~n  User not found: ~ts~n~n", [Q])
            end
    end,
    ok.

%%%===================================================================
%%% Connections
%%%===================================================================

%% @doc Show detailed WebSocket connection info.
-spec connections() -> ok.
connections() ->
    Connections = ets:tab2list(?CONNECTION_TABLE),
    case Connections of
        [] ->
            io:format("~n  No active connections.~n~n");
        _ ->
            io:format("~n  Active Connections (~p)~n", [length(Connections)]),
            io:format("  ══════════════════════~n~n"),
            lists:foreach(fun({Username, Pid}) ->
                Alive = is_process_alive(Pid),
                Info = case Alive of
                    true ->
                        case process_info(Pid, [message_queue_len, memory, reductions]) of
                            undefined -> "  (process info unavailable)";
                            Props ->
                                MsgQ = proplists:get_value(message_queue_len, Props, 0),
                                Mem = proplists:get_value(memory, Props, 0),
                                Reds = proplists:get_value(reductions, Props, 0),
                                lists:flatten(
                                    io_lib:format("msgs=~p mem=~ts reds=~p",
                                                  [MsgQ, format_bytes(Mem), Reds]))
                        end;
                    false ->
                        "(dead process)"
                end,
                io:format("  ~-20ts ~p  ~ts~n", [Username, Pid, Info])
            end, lists:sort(Connections)),
            io:format("~n")
    end,
    ok.

%%%===================================================================
%%% Pending Messages
%%%===================================================================

%% @doc Show a summary of pending (offline) messages per user.
-spec pending() -> ok.
pending() ->
    Messages = ets:tab2list(?MESSAGE_TABLE),
    case Messages of
        [] ->
            io:format("~n  No pending messages.~n~n");
        _ ->
            %% Group by recipient
            Grouped = lists:foldl(fun({_Id, ToUser, _Blob}, Acc) ->
                maps:update_with(ToUser, fun(V) -> V + 1 end, 1, Acc)
            end, #{}, Messages),
            io:format("~n  Pending Messages (~p total)~n", [length(Messages)]),
            io:format("  ══════════════════════════~n~n"),
            maps:foreach(fun(User, Count) ->
                io:format("  ~-24ts  ~p message(s)~n", [User, Count])
            end, Grouped),
            io:format("~n")
    end,
    ok.

%% @doc Show pending messages for a specific user.
-spec pending(string() | binary() | atom()) -> ok.
pending(User) ->
    U = to_string(User),
    Messages = [Blob || {_Id, ToUser, Blob} <- ets:tab2list(?MESSAGE_TABLE),
                        ToUser =:= U],
    case Messages of
        [] ->
            io:format("~n  No pending messages for ~ts.~n~n", [U]);
        _ ->
            io:format("~n  Pending Messages for ~ts (~p)~n", [U, length(Messages)]),
            io:format("  ═══════════════════════════════~n~n"),
            lists:foreach(fun(Blob) ->
                Type = maps:get(<<"message_type">>, Blob,
                       maps:get(<<"type">>, Blob, <<"unknown">>)),
                From = maps:get(<<"from_user">>, Blob, <<"?">>),
                Ts = maps:get(<<"server_timestamp">>, Blob, 0),
                TimeStr = case Ts of
                    0 -> "unknown";
                    _ -> format_timestamp(Ts)
                end,
                io:format("  [~ts] ~ts from ~ts~n", [TimeStr, Type, From])
            end, Messages),
            io:format("~n")
    end,
    ok.

%%%===================================================================
%%% Key Bundles
%%%===================================================================

%% @doc Show a summary of uploaded key material per user.
-spec keys() -> ok.
keys() ->
    AllPrekeys = ets:tab2list(?PREKEY_TABLE),
    %% Extract unique usernames from the prekey table
    UserSet = lists:foldl(fun
        ({{Username, identity}, _}, Acc) -> sets:add_element(Username, Acc);
        ({{Username, signed_prekey, _}, _}, Acc) -> sets:add_element(Username, Acc);
        ({{Username, one_time_prekey, _}, _}, Acc) -> sets:add_element(Username, Acc);
        (_, Acc) -> Acc
    end, sets:new(), AllPrekeys),
    Users = lists:sort(sets:to_list(UserSet)),
    case Users of
        [] ->
            io:format("~n  No key bundles uploaded.~n~n");
        _ ->
            io:format("~n  Key Bundles (~p users)~n", [length(Users)]),
            io:format("  ═════════════════════~n~n"),
            lists:foreach(fun(Username) ->
                HasIdentity = ets:member(?PREKEY_TABLE, {Username, identity}),
                OtpkCount = length([K || {{U, one_time_prekey, _}, _} <- AllPrekeys,
                                          U =:= Username,
                                          K <- [ok]]),
                IdStr = case HasIdentity of true -> "yes"; false -> "no" end,
                io:format("  ~-20ts  identity=~ts  OTPKs=~p~n",
                          [Username, IdStr, OtpkCount])
            end, Users),
            io:format("~n")
    end,
    ok.

%% @doc Show key bundle details for a specific user.
-spec keys(string() | binary() | atom()) -> ok.
keys(User) ->
    U = to_string(User),
    io:format("~n  Key Bundle for ~ts~n", [U]),
    io:format("  ═══════════════════~n~n"),
    case ets:lookup(?PREKEY_TABLE, {U, identity}) of
        [{_, IdentityData}] ->
            io:format("  Identity keys:   uploaded~n"),
            case is_map(IdentityData) of
                true ->
                    maps:foreach(fun(K, _V) ->
                        io:format("    ~p: (present)~n", [K])
                    end, IdentityData);
                false ->
                    io:format("    (binary data)~n")
            end;
        [] ->
            io:format("  Identity keys:   not uploaded~n")
    end,
    AllPrekeys = ets:tab2list(?PREKEY_TABLE),
    OtpkIds = [Id || {{Username, one_time_prekey, Id}, _} <- AllPrekeys,
                      Username =:= U],
    io:format("  One-time prekeys: ~p available~n", [length(OtpkIds)]),
    case OtpkIds of
        [] -> ok;
        Ids when length(Ids) =< 10 ->
            io:format("    IDs: ~p~n", [lists:sort(Ids)]);
        Ids ->
            io:format("    IDs: ~p ... (~p more)~n",
                      [lists:sort(lists:sublist(Ids, 10)),
                       length(Ids) - 10])
    end,
    io:format("~n"),
    ok.

%%%===================================================================
%%% User Management
%%%===================================================================

%% @doc Suspend a user by GPG fingerprint.
-spec suspend(string() | binary() | atom()) -> ok.
suspend(GpgFp) ->
    Fp = to_binary(GpgFp),
    case get_db_ref() of
        {ok, DbRef} ->
            case cryptic_ca_store:update_user_status(DbRef, Fp, <<"suspended">>) of
                ok ->
                    io:format("~n  User ~ts suspended.~n~n", [Fp]);
                {error, Reason} ->
                    io:format("~n  Failed to suspend user: ~p~n~n", [Reason])
            end;
        {error, _} ->
            io:format("~n  CA database not available.~n~n")
    end,
    ok.

%% @doc Reactivate a suspended user by GPG fingerprint.
-spec reactivate(string() | binary() | atom()) -> ok.
reactivate(GpgFp) ->
    Fp = to_binary(GpgFp),
    case get_db_ref() of
        {ok, DbRef} ->
            case cryptic_ca_store:update_user_status(DbRef, Fp, <<"active">>) of
                ok ->
                    io:format("~n  User ~ts reactivated.~n~n", [Fp]);
                {error, Reason} ->
                    io:format("~n  Failed to reactivate user: ~p~n~n", [Reason])
            end;
        {error, _} ->
            io:format("~n  CA database not available.~n~n")
    end,
    ok.

%%%===================================================================
%%% Certificates
%%%===================================================================

%% @doc List certificates for a user by GPG fingerprint.
-spec certs(string() | binary() | atom()) -> ok.
certs(GpgFp) ->
    Fp = to_binary(GpgFp),
    case get_db_ref() of
        {ok, DbRef} ->
            case cryptic_ca_store:list_certificates_by_user(DbRef, Fp) of
                {ok, Certs} ->
                    io:format("~n  Certificates for ~ts (~p)~n", [Fp, length(Certs)]),
                    io:format("  ═════════════════════════════~n~n"),
                    lists:foreach(fun(Cert) ->
                        Serial = Cert#certificate.serial,
                        CertStatus = Cert#certificate.status,
                        IssuedAt = Cert#certificate.issued_at,
                        ExpiresAt = Cert#certificate.expires_at,
                        io:format("  Serial:  ~ts~n", [Serial]),
                        io:format("  Status:  ~ts~n", [CertStatus]),
                        io:format("  Issued:  ~ts~n", [format_timestamp(IssuedAt)]),
                        io:format("  Expires: ~ts~n", [format_timestamp(ExpiresAt)]),
                        case CertStatus of
                            <<"revoked">> ->
                                RevokedAt = Cert#certificate.revoked_at,
                                RevokedBy = Cert#certificate.revoked_by,
                                Reason = Cert#certificate.revoked_reason,
                                io:format("  Revoked: ~ts by ~ts (~ts)~n",
                                          [format_timestamp(RevokedAt),
                                           coalesce(RevokedBy, <<"?">>),
                                           coalesce(Reason, <<"no reason">>)]);
                            _ -> ok
                        end,
                        io:format("~n")
                    end, Certs);
                {error, Reason} ->
                    io:format("~n  Error listing certificates: ~p~n~n", [Reason])
            end;
        {error, _} ->
            io:format("~n  CA database not available.~n~n")
    end,
    ok.

%%%===================================================================
%%% Audit Log
%%%===================================================================

%% @doc Show last 20 audit log entries.
-spec audit() -> ok.
audit() ->
    audit(20).

%% @doc Show last N audit log entries.
-spec audit(pos_integer()) -> ok.
audit(N) when is_integer(N), N > 0 ->
    case get_db_ref() of
        {ok, DbRef} ->
            case cryptic_ca_store:get_audit_logs(DbRef, N, 0) of
                {ok, Logs} ->
                    io:format("~n  Audit Log (last ~p)~n", [N]),
                    io:format("  ════════════════════~n~n"),
                    lists:foreach(fun(Log) ->
                        Ts = Log#audit_log.timestamp,
                        EvType = Log#audit_log.event_type,
                        Fp = coalesce(Log#audit_log.gpg_fp, <<"">>),
                        Details = coalesce(Log#audit_log.details, <<"">>),
                        io:format("  [~ts] ~-24ts ~ts ~ts~n",
                                  [format_timestamp(Ts), EvType, Fp, Details])
                    end, Logs),
                    io:format("~n");
                {error, Reason} ->
                    io:format("~n  Error reading audit log: ~p~n~n", [Reason])
            end;
        {error, _} ->
            io:format("~n  CA database not available.~n~n")
    end,
    ok.

%%%===================================================================
%%% Internal Helpers
%%%===================================================================

%% @private Get the CA database reference from ETS.
-spec get_db_ref() -> {ok, term()} | {error, not_available}.
get_db_ref() ->
    try
        case ets:lookup(cryptic_ca_storage, db_ref) of
            [{db_ref, DbRef}] -> {ok, DbRef};
            [] -> {error, not_available}
        end
    catch
        error:badarg -> {error, not_available}
    end.

%% @private Resolve the CA database file path using the same logic as cryptic_ca_app.
-spec get_ca_db_path() -> string().
get_ca_db_path() ->
    case cryptic_lib:get_server_file("CRYPTIC_CA_DB_FILE", ca_db_file) of
        undefined ->
            case os:getenv("CRYPTIC_SERVER_DIR") of
                false -> "data/ca/cryptic_ca.db";
                ServerDir -> filename:join([ServerDir, "data/ca/cryptic_ca.db"])
            end;
        Path ->
            Path
    end.

%% @private Print bootstrap admin GPG files and the names from their keys.
-spec print_bootstrap_admins(file:filename()) -> ok.
print_bootstrap_admins(Dir) ->
    case file:list_dir(Dir) of
        {ok, Files} ->
            GpgFiles = lists:sort([F || F <- Files, filename:extension(F) =:= ".gpg"]),
            case GpgFiles of
                [] ->
                    io:format("  Bootstrap admins: (none)~n");
                _ ->
                    io:format("~n  Bootstrap Admins (~p)~n", [length(GpgFiles)]),
                    io:format("  ─────────────────~n"),
                    lists:foreach(fun(F) ->
                        FilePath = filename:join(Dir, F),
                        NameStr = case file:read_file(FilePath) of
                            {ok, PubArmor} ->
                                try
                                    case erl_gpg_api:get_key_info(PubArmor, "") of
                                        {ok, KeyInfo} ->
                                            UIDs = maps:get(user_ids, KeyInfo, []),
                                            case UIDs of
                                                [UID | _] ->
                                                    unicode:characters_to_list(UID);
                                                [] ->
                                                    "(no UID)"
                                            end;
                                        _ -> "(unreadable key)"
                                    end
                                catch _:_ -> "(parse error)"
                                end;
                            {error, _} -> "(read error)"
                        end,
                        io:format("    ~ts  ->  ~ts~n", [F, NameStr])
                    end, GpgFiles)
            end;
        {error, enoent} ->
            io:format("  Bootstrap admins: (directory not found)~n");
        {error, _} ->
            io:format("  Bootstrap admins: (unreadable)~n")
    end.

%% @private Check if a chat user is currently connected.
-spec is_online(string()) -> boolean().
is_online(User) when is_list(User) ->
    case ets:lookup(?CONNECTION_TABLE, User) of
        [{_, _Pid}] -> true;
        [] -> false
    end.

%% @private Convert various input types to string.
-spec to_string(string() | binary() | atom()) -> string().
to_string(V) when is_list(V) -> V;
to_string(V) when is_binary(V) -> binary_to_list(V);
to_string(V) when is_atom(V) -> atom_to_list(V).

%% @private Convert various input types to binary.
-spec to_binary(string() | binary() | atom()) -> binary().
to_binary(V) when is_binary(V) -> V;
to_binary(V) when is_list(V) -> list_to_binary(V);
to_binary(V) when is_atom(V) -> atom_to_binary(V, utf8).

%% @private Return the first non-undefined value.
-spec coalesce(term(), term()) -> term().
coalesce(undefined, Default) -> Default;
coalesce(Value, _Default) -> Value.

%% @private Format a unix timestamp to a readable string.
-spec format_timestamp(non_neg_integer() | undefined) -> string().
format_timestamp(undefined) -> "n/a";
format_timestamp(0) -> "n/a";
format_timestamp(Ts) when is_integer(Ts) ->
    try
        DateTime = calendar:system_time_to_universal_time(Ts, second),
        {{Y, Mo, D}, {H, Mi, S}} = DateTime,
        lists:flatten(
            io_lib:format("~4..0B-~2..0B-~2..0B ~2..0B:~2..0B:~2..0BZ",
                          [Y, Mo, D, H, Mi, S]))
    catch
        _:_ -> io_lib:format("~p", [Ts])
    end.

%% @private Format byte count to human-readable string.
-spec format_bytes(non_neg_integer()) -> string().
format_bytes(B) when B < 1024 ->
    integer_to_list(B) ++ "B";
format_bytes(B) when B < 1024 * 1024 ->
    lists:flatten(io_lib:format("~.1fKB", [B / 1024]));
format_bytes(B) ->
    lists:flatten(io_lib:format("~.1fMB", [B / (1024 * 1024)])).

%% @private Print the user table with columns.
-spec print_users_table(term(), [#gpg_identity{}]) -> ok.
print_users_table(DbRef, Identities) ->
    io:format("  ~-16ts ~-10ts ~-6ts ~-8ts ~-22ts ~-22ts  GPG Fingerprint~n",
              ["Name", "Status", "Admin", "Online", "Registered", "Last Seen"]),
    io:format("  ~ts~n", [lists:duplicate(112, $─)]),
    lists:foreach(fun(I) ->
        Fp = I#gpg_identity.gpg_fp,
        UserStatus = I#gpg_identity.status,
        RegAt = I#gpg_identity.registered_at,
        LastSeen = I#gpg_identity.last_seen,

        DisplayName = case get_username_for_gpg(DbRef, Fp) of
            undefined -> "-";
            N -> N
        end,
        AdminStr = case I#gpg_identity.registered_by of
            undefined -> "yes";
            _         -> "-"
        end,
        CertCN = get_cn_from_cert(DbRef, Fp),
        OnlineStr = case CertCN of
            undefined -> "-";
            CN -> case is_online(CN) of true -> "yes"; false -> "no" end
        end,

        StatusStr = binary_to_list(UserStatus),
        RegStr = format_timestamp(RegAt),
        SeenStr = format_timestamp(LastSeen),

        ShortFp = case byte_size(Fp) > 16 of
            true -> binary_to_list(binary:part(Fp, 0, 8)) ++ "..." ++
                    binary_to_list(binary:part(Fp, byte_size(Fp), -8));
            false -> binary_to_list(Fp)
        end,

        io:format("  ~-16ts ~-10ts ~-6ts ~-8ts ~-22ts ~-22ts  ~ts~n",
                  [DisplayName, StatusStr, AdminStr, OnlineStr,
                   RegStr, SeenStr, ShortFp])
    end, Identities),
    ok.

%% @private Resolve a display name for a GPG fingerprint.
%% Tries the GPG key's user ID name first, then falls back to certificate CN.
-spec get_username_for_gpg(term(), binary()) -> string() | undefined.
get_username_for_gpg(DbRef, GpgFp) ->
    case get_name_from_gpg_key(DbRef, GpgFp) of
        {ok, Name} -> Name;
        undefined   -> get_cn_from_cert(DbRef, GpgFp)
    end.

%% @private Extract the human name from the GPG key's user ID.
%% GPG UIDs follow the format "Name <email>" or just "Name".
-spec get_name_from_gpg_key(term(), binary()) -> {ok, string()} | undefined.
get_name_from_gpg_key(DbRef, GpgFp) ->
    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
        {ok, #gpg_identity{gpg_pub_armor = PubArmor}}
          when is_binary(PubArmor), byte_size(PubArmor) > 0 ->
            try
                case erl_gpg_api:get_key_info(PubArmor, "") of
                    {ok, KeyInfo} ->
                        UIDs = maps:get(user_ids, KeyInfo, []),
                        extract_name_from_uids(UIDs);
                    _ ->
                        undefined
                end
            catch
                _:_ -> undefined
            end;
        _ ->
            undefined
    end.

%% @private Extract the name part from a list of GPG user IDs.
-spec extract_name_from_uids([binary()]) -> {ok, string()} | undefined.
extract_name_from_uids([]) ->
    undefined;
extract_name_from_uids([UID | Rest]) ->
    case extract_name_from_uid(UID) of
        {ok, Name} -> {ok, Name};
        undefined  -> extract_name_from_uids(Rest)
    end.

%% @private Extract name from a single UID like "Alice Smith <alice@example.com>".
-spec extract_name_from_uid(binary()) -> {ok, string()} | undefined.
extract_name_from_uid(UID) when is_binary(UID) ->
    S = unicode:characters_to_list(UID),
    case string:split(S, "<") of
        [S] ->
            %% No angle bracket — use the whole UID as the name
            case string:trim(S) of
                [] -> undefined;
                Trimmed -> {ok, Trimmed}
            end;
        [Before, _] ->
            case string:trim(Before) of
                [] -> undefined;
                Name -> {ok, Name}
            end
    end;
extract_name_from_uid(_) ->
    undefined.

%% @private Fall back to extracting the CN from the user's certificate.
-spec get_cn_from_cert(term(), binary()) -> string() | undefined.
get_cn_from_cert(DbRef, GpgFp) ->
    case cryptic_ca_store:list_certificates_by_user(DbRef, GpgFp) of
        {ok, [#certificate{cert_pem = CertPem} | _]} ->
            try
                [{'Certificate', CertDER, not_encrypted}] =
                    public_key:pem_decode(CertPem),
                Cert = public_key:pkix_decode_cert(CertDER, otp),
                TBSCert = Cert#'OTPCertificate'.tbsCertificate,
                Subject = TBSCert#'OTPTBSCertificate'.subject,
                extract_cn(Subject)
            catch
                _:_ -> undefined
            end;
        _ ->
            undefined
    end.

%% @private Extract Common Name from certificate subject.
-spec extract_cn(term()) -> string() | undefined.
extract_cn({rdnSequence, RDNSeq}) ->
    lists:foldl(fun
        (_, Found) when is_list(Found) -> Found;
        (RDNSet, undefined) ->
            lists:foldl(fun
                (_, Found) when is_list(Found) -> Found;
                (#'AttributeTypeAndValue'{
                    type = ?'id-at-commonName',
                    value = {utf8String, CN}}, _) ->
                    binary_to_list(CN);
                (#'AttributeTypeAndValue'{
                    type = ?'id-at-commonName',
                    value = CN}, _) when is_list(CN) ->
                    CN;
                (_, Acc) -> Acc
            end, undefined, RDNSet)
    end, undefined, RDNSeq);
extract_cn(_) ->
    undefined.

%% @private Try looking up a GPG identity by fingerprint.
-spec try_gpg_lookup(term(), string()) -> {ok, #gpg_identity{}} | not_found.
try_gpg_lookup(DbRef, Q) ->
    Bin = list_to_binary(Q),
    case cryptic_ca_store:get_gpg_identity(DbRef, Bin) of
        {ok, Identity} -> {ok, Identity};
        {error, not_found} -> not_found;
        {error, _} -> not_found
    end.

%% @private Find a GPG identity by matching the username from certificates.
-spec find_gpg_by_username(term(), string()) ->
    {ok, #gpg_identity{}} | not_found.
find_gpg_by_username(DbRef, Username) ->
    case cryptic_ca_store:list_gpg_identities(DbRef) of
        {ok, Identities} ->
            lists:foldl(fun
                (_I, {ok, _} = Found) -> Found;
                (I, not_found) ->
                    case get_username_for_gpg(DbRef, I#gpg_identity.gpg_fp) of
                        undefined -> not_found;
                        Username -> {ok, I};
                        _ -> not_found
                    end
            end, not_found, Identities);
        {error, _} ->
            not_found
    end.

%% @private Print detailed user info.
-spec print_user_detail(term(), #gpg_identity{}) -> ok.
print_user_detail(DbRef, I) ->
    Fp = I#gpg_identity.gpg_fp,
    DisplayName = get_username_for_gpg(DbRef, Fp),
    CertCN = get_cn_from_cert(DbRef, Fp),

    io:format("~n  User Detail~n"),
    io:format("  ═══════════~n~n"),
    io:format("  GPG Fingerprint: ~ts~n", [Fp]),
    case DisplayName of
        undefined -> ok;
        N -> io:format("  Name:            ~ts~n", [N])
    end,
    case CertCN of
        undefined -> ok;
        CN -> io:format("  Certificate CN:  ~ts~n", [CN])
    end,
    io:format("  Status:          ~ts~n", [I#gpg_identity.status]),
    IsAdmin = I#gpg_identity.registered_by =:= undefined,
    io:format("  Admin:           ~ts~n", [case IsAdmin of true -> "yes"; false -> "no" end]),
    io:format("  Registered at:   ~ts~n",
              [format_timestamp(I#gpg_identity.registered_at)]),
    io:format("  Last seen:       ~ts~n",
              [format_timestamp(I#gpg_identity.last_seen)]),
    case I#gpg_identity.registered_by of
        undefined -> io:format("  Registered by:   (bootstrap admin)~n");
        By -> io:format("  Registered by:   ~ts~n", [By])
    end,

    %% Metadata
    case I#gpg_identity.metadata of
        undefined -> ok;
        <<>> -> ok;
        MetaBin ->
            try
                Meta = jsx:decode(MetaBin, [return_maps]),
                io:format("  Metadata:~n"),
                maps:foreach(fun(K, V) ->
                    io:format("    ~ts: ~ts~n", [K, V])
                end, Meta)
            catch _:_ ->
                io:format("  Metadata:        (unparseable)~n")
            end
    end,

    %% Online status
    case CertCN of
        undefined ->
            io:format("  Online:          (no certificate)~n");
        CN2 ->
            io:format("  Online:          ~p~n", [is_online(CN2)])
    end,
    io:format("~n"),
    ok.
