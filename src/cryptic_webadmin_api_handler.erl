%% @doc Cryptic Web Admin - REST API HTTP Handler
%%
%% Session-authenticated Cowboy handler backing the web admin single-page
%% app. The concrete endpoint is selected by the route configuration via the
%% handler `State' map (`#{operation => Op}'), mirroring the dispatch style of
%% {@link cryptic_webadmin_auth_handler}. Routes are wired in
%% {@link cryptic_server} (Phase 3).
%%
%% All shared business logic lives in {@link cryptic_admin_core}; this handler
%% is a thin transport adapter that:
%% <ul>
%%   <li>requires a valid session cookie for every request;</li>
%%   <li>enforces a CSRF token (`X-CSRF-Token') on mutating requests;</li>
%%   <li>emits clean REST JSON (not the verbose MCP response envelopes).</li>
%% </ul>
%%
%% Endpoints:
%% <ul>
%%   <li>`GET  /admin/api/users'                    - list users</li>
%%   <li>`GET  /admin/api/users/:fp'                - user detail</li>
%%   <li>`GET  /admin/api/users/:fp/certs'          - user certificates</li>
%%   <li>`POST /admin/api/users/:fp/suspend'        - suspend user</li>
%%   <li>`POST /admin/api/users/:fp/reactivate'     - reactivate user</li>
%%   <li>`POST /admin/api/users/:fp/revoke'         - revoke user</li>
%%   <li>`DELETE /admin/api/users/:fp'              - delete user</li>
%%   <li>`GET  /admin/api/enrollments'              - list enrollments</li>
%%   <li>`POST /admin/api/enrollments'              - create enrollment package</li>
%%   <li>`GET  /admin/api/enrollments/:fp'          - enrollment detail</li>
%%   <li>`GET  /admin/api/audit'                    - recent audit log</li>
%%   <li>`GET  /admin/api/status'                   - server status</li>
%%   <li>`GET  /admin/api/logs'                     - paged server log history</li>
%% </ul>
%%
%% @author Cryptic Development Team
%% @since August 2026
-module(cryptic_webadmin_api_handler).

-export([init/2]).

-include("cryptic_server.hrl").
-include("cryptic_ca.hrl").

-define(DEFAULT_AUDIT_LIMIT, 100).
-define(MAX_AUDIT_LIMIT, 1000).
-define(DEFAULT_LOG_LIMIT, 200).
-define(MAX_LOG_LIMIT, 2000).

init(Req0, State) ->
    Operation = maps:get(operation, State, undefined),
    Method = cowboy_req:method(Req0),
    {StatusCode, BodyMap, Req1} =
        try
            authorize(Operation, Method, Req0)
        catch
            Class:Reason:Stack ->
                ?error("webadmin api handler crashed: ~p:~p~n~p",
                       [Class, Reason, Stack]),
                {500, #{status => <<"error">>, message => <<"internal_server_error">>},
                 Req0}
        end,
    Req2 = cowboy_req:reply(
        StatusCode,
        #{<<"content-type">> => <<"application/json">>},
        jsx:encode(BodyMap),
        Req1
    ),
    {ok, Req2, State}.

%%====================================================================
%% Authorization: session + CSRF gate
%%====================================================================

authorize(Operation, Method, Req0) ->
    CookieValue = session_cookie(Req0),
    case cryptic_admin_session:validate(CookieValue) of
        {ok, User, Csrf} ->
            case is_mutation(Method) of
                true ->
                    case check_csrf(Csrf, Req0) of
                        true -> dispatch(Operation, Method, User, Req0);
                        false ->
                            {403,
                             #{status => <<"error">>, message => <<"csrf_failed">>},
                             Req0}
                    end;
                false ->
                    dispatch(Operation, Method, User, Req0)
            end;
        {error, _} ->
            {401,
             #{status => <<"error">>, message => <<"unauthorized">>},
             Req0}
    end.

is_mutation(<<"POST">>) -> true;
is_mutation(<<"PUT">>) -> true;
is_mutation(<<"PATCH">>) -> true;
is_mutation(<<"DELETE">>) -> true;
is_mutation(_) -> false.

%%====================================================================
%% Operation dispatch
%%====================================================================

dispatch(users, <<"GET">>, _User, Req) ->
    with_db(Req, fun(DbRef) ->
        Filter = query_param(<<"status">>, Req),
        wrap_list(cryptic_admin_core:list_users(DbRef, Filter), users, Req)
    end);
dispatch(user, <<"GET">>, _User, Req) ->
    with_db(Req, fun(DbRef) ->
        Fp = binding_fp(Req),
        case cryptic_admin_core:get_user_info(DbRef, Fp) of
            {ok, Info} ->
                {200, #{status => <<"ok">>, user => Info}, Req};
            {error, Reason} ->
                error_response(404, Reason, Req)
        end
    end);
dispatch(user_certs, <<"GET">>, _User, Req) ->
    with_db(Req, fun(DbRef) ->
        Fp = binding_fp(Req),
        wrap_list(cryptic_admin_core:list_certificates(DbRef, Fp),
                  certificates, Req)
    end);
dispatch(user_suspend, <<"POST">>, User, Req0) ->
    with_body_db(Req0, fun(DbRef, Body, Req1) ->
        Fp = binding_fp(Req1),
        Reason = maps:get(<<"reason">>, Body, <<"No reason provided">>),
        case cryptic_admin_core:suspend_user(DbRef, Fp, User, Reason, peer_ip(Req1)) of
            {ok, Result} ->
                {200, ok_result(Result), Req1};
            {error, Reason2} ->
                error_response(400, Reason2, Req1)
        end
    end);
dispatch(user_reactivate, <<"POST">>, User, Req0) ->
    with_db(Req0, fun(DbRef) ->
        Fp = binding_fp(Req0),
        case cryptic_admin_core:reactivate_user(DbRef, Fp, User, peer_ip(Req0)) of
            {ok, Result} ->
                {200, ok_result(Result), Req0};
            {error, cannot_reactivate_revoked} ->
                {400,
                 #{status => <<"error">>,
                   error => <<"cannot_reactivate_revoked">>,
                   message => <<"Revoked users cannot be reactivated">>},
                 Req0};
            {error, Reason} ->
                error_response(404, Reason, Req0)
        end
    end);
dispatch(user_revoke, <<"POST">>, User, Req0) ->
    with_body_db(Req0, fun(DbRef, Body, Req1) ->
        Fp = binding_fp(Req1),
        Reason = maps:get(<<"reason">>, Body, <<"No reason provided">>),
        case cryptic_admin_core:revoke_user(DbRef, Fp, User, Reason, peer_ip(Req1)) of
            {ok, Result} ->
                {200, ok_result(Result), Req1};
            {error, Reason2} ->
                error_response(400, Reason2, Req1)
        end
    end);
dispatch(user, <<"DELETE">>, User, Req0) ->
    with_db(Req0, fun(DbRef) ->
        Fp = binding_fp(Req0),
        case cryptic_admin_core:delete_user(DbRef, Fp, User, peer_ip(Req0)) of
            {ok, Result} ->
                {200, ok_result(Result), Req0};
            {error, not_found} ->
                error_response(404, not_found, Req0);
            {error, Reason} ->
                error_response(400, Reason, Req0)
        end
    end);
dispatch(enrollments, <<"GET">>, _User, Req) ->
    with_db(Req, fun(DbRef) ->
        Filter = query_param(<<"status">>, Req),
        wrap_list(cryptic_admin_core:list_enrollments(DbRef, Filter),
                  enrollments, Req)
    end);
dispatch(enrollments, <<"POST">>, User, Req0) ->
    with_body_db(Req0, fun(DbRef, Body, Req1) ->
        create_enrollment(DbRef, Body, User, Req1)
    end);
dispatch(enrollment, <<"GET">>, _User, Req) ->
    with_db(Req, fun(DbRef) ->
        Fp = binding_fp(Req),
        case cryptic_admin_core:get_enrollment_info(DbRef, Fp) of
            {ok, Info} ->
                {200, #{status => <<"ok">>, enrollment => Info}, Req};
            {error, Reason} ->
                error_response(404, Reason, Req)
        end
    end);
dispatch(server_hosts, <<"GET">>, _User, Req) ->
    %% Names/IPs the messaging server certificate is valid for, so the admin UI
    %% can offer a constrained "Server host" picker for new enrollments.
    Hosts = case cryptic_enrollment_pkg:server_cert_sans() of
                {ok, Sans} -> Sans;
                {error, _} -> []
            end,
    {200,
     #{status => <<"ok">>,
       hosts => Hosts,
       default => default_server_host()},
     Req};
dispatch(audit, <<"GET">>, _User, Req) ->
    with_db(Req, fun(DbRef) ->
        Limit = audit_limit(Req),
        case cryptic_admin_core:get_audit_log(DbRef, Limit, 0) of
            {ok, Entries} ->
                {200,
                 #{status => <<"ok">>,
                   count => length(Entries),
                   limit => Limit,
                   entries => Entries},
                 Req};
            {error, Reason} ->
                error_response(500, Reason, Req)
        end
    end);
dispatch(status, <<"GET">>, _User, Req) ->
    with_db(Req, fun(DbRef) ->
        {ok, Status} = cryptic_admin_core:server_status(DbRef),
        {200, Status#{status => <<"ok">>}, Req}
    end);
dispatch(logs, <<"GET">>, _User, Req) ->
    Before = log_before(Req),
    Limit = log_limit(Req),
    Level = query_param(<<"level">>, Req),
    case cryptic_webadmin_log:read_page(Before, Limit, Level) of
        {ok, Page} ->
            {200, Page#{status => <<"ok">>}, Req};
        {error, Reason} ->
            error_response(500, Reason, Req)
    end;
dispatch(undefined, _Method, _User, Req) ->
    {404, #{status => <<"error">>, message => <<"not_found">>}, Req};
dispatch(_Operation, _Method, _User, Req) ->
    {405, #{status => <<"error">>, message => <<"method_not_allowed">>}, Req}.

%%====================================================================
%% Enrollment creation
%%====================================================================

create_enrollment(DbRef, Body, User, Req) ->
    case maps:get(<<"username">>, Body, undefined) of
        Username when is_binary(Username), Username =/= <<>> ->
            case maps:get(<<"passphrase">>, Body, undefined) of
                Passphrase when is_binary(Passphrase), byte_size(Passphrase) >= 8 ->
                    Params = build_enrollment_params(DbRef, Username, Passphrase,
                                                     User, Body, Req),
                    do_create_enrollment(Params, Req);
                _ ->
                    {400,
                     #{status => <<"error">>,
                       message => <<"passphrase_too_short">>},
                     Req}
            end;
        _ ->
            {400,
             #{status => <<"error">>, message => <<"username_required">>},
             Req}
    end.

build_enrollment_params(DbRef, Username, Passphrase, User, Body, Req) ->
    Base = #{
        db_ref => DbRef,
        username => Username,
        passphrase => Passphrase,
        actor_id => User,
        ip => peer_ip(Req),
        full_name => opt_binary(<<"full_name">>, Body),
        email => opt_binary(<<"email">>, Body)
    },
    maybe_put_param(expiry_seconds, opt_pos_integer(<<"expiry_seconds">>, Body),
                    maybe_put_param(server_host, opt_binary(<<"server_host">>, Body),
                        maybe_put_param(server_port, opt_pos_integer(<<"server_port">>, Body),
                            Base))).

do_create_enrollment(Params, Req) ->
    try cryptic_enrollment_pkg:create(Params) of
        {ok, Result} ->
            {200,
             #{status => <<"ok">>,
               enrollment_fp => maps:get(enrollment_fp, Result),
               username => maps:get(username, Result),
               package => maps:get(package, Result),
               expires_at => maps:get(expires_at, Result),
               payload_version => maps:get(payload_version, Result)},
             Req};
        {error, Reason} ->
            error_response(400, Reason, Req)
    catch
        Class:CatchReason:Stack ->
            ?error("enrollment creation failed: ~p:~p~n~p",
                   [Class, CatchReason, Stack]),
            error_response(500, <<"enrollment_failed">>, Req)
    end.

opt_binary(Key, Body) ->
    case maps:get(Key, Body, undefined) of
        V when is_binary(V) -> V;
        _ -> undefined
    end.

opt_pos_integer(Key, Body) ->
    case maps:get(Key, Body, undefined) of
        N when is_integer(N), N > 0 -> N;
        _ -> undefined
    end.

maybe_put_param(_Key, undefined, Map) -> Map;
maybe_put_param(Key, Value, Map) -> Map#{Key => Value}.

%%====================================================================
%% Request helpers
%%====================================================================

with_db(Req, Fun) ->
    case application:get_env(cryptic, ca_db_ref) of
        {ok, DbRef} -> Fun(DbRef);
        _ -> error_response(503, <<"ca_unavailable">>, Req)
    end.

with_body_db(Req0, Fun) ->
    with_db(Req0, fun(DbRef) ->
        case read_json_body(Req0) of
            {ok, Body, Req1} -> Fun(DbRef, Body, Req1);
            {error, Req1} ->
                {400, #{status => <<"error">>, message => <<"invalid_json">>}, Req1}
        end
    end).

read_json_body(Req0) ->
    {ok, Raw, Req1} = cowboy_req:read_body(Req0),
    case Raw of
        <<>> -> {ok, #{}, Req1};
        _ ->
            try
                {ok, jsx:decode(Raw, [return_maps]), Req1}
            catch
                _:_ -> {error, Req1}
            end
    end.

wrap_list({ok, Items}, Key, Req) ->
    {200, #{status => <<"ok">>, count => length(Items), Key => Items}, Req};
wrap_list({error, Reason}, _Key, Req) ->
    error_response(500, Reason, Req).

ok_result(Result) ->
    Result#{status => <<"ok">>}.

binding_fp(Req) ->
    cowboy_req:binding(fp, Req).

query_param(Name, Req) ->
    Qs = cowboy_req:parse_qs(Req),
    proplists:get_value(Name, Qs, undefined).

audit_limit(Req) ->
    case query_param(<<"limit">>, Req) of
        undefined -> ?DEFAULT_AUDIT_LIMIT;
        Bin ->
            try binary_to_integer(Bin) of
                N when N > 0, N =< ?MAX_AUDIT_LIMIT -> N;
                N when N > ?MAX_AUDIT_LIMIT -> ?MAX_AUDIT_LIMIT;
                _ -> ?DEFAULT_AUDIT_LIMIT
            catch
                _:_ -> ?DEFAULT_AUDIT_LIMIT
            end
    end.

log_limit(Req) ->
    case query_param(<<"limit">>, Req) of
        undefined -> ?DEFAULT_LOG_LIMIT;
        Bin ->
            try binary_to_integer(Bin) of
                N when N > 0, N =< ?MAX_LOG_LIMIT -> N;
                N when N > ?MAX_LOG_LIMIT -> ?MAX_LOG_LIMIT;
                _ -> ?DEFAULT_LOG_LIMIT
            catch
                _:_ -> ?DEFAULT_LOG_LIMIT
            end
    end.

log_before(Req) ->
    case query_param(<<"before">>, Req) of
        undefined -> 0;
        Bin ->
            try binary_to_integer(Bin) of
                N when N >= 0 -> N;
                _ -> 0
            catch
                _:_ -> 0
            end
    end.

error_response(StatusCode, Reason, Req) ->
    {StatusCode, #{status => <<"error">>, message => to_message(Reason)}, Req}.

to_message(Reason) when is_binary(Reason) -> Reason;
to_message(Reason) when is_atom(Reason) -> atom_to_binary(Reason, utf8);
to_message({server_host_not_in_cert, Host, Sans}) ->
    SanList = case Sans of
                  [] -> <<"(none)">>;
                  _ -> iolist_to_binary(lists:join(<<", ">>, Sans))
              end,
    iolist_to_binary(
        [<<"Server host '">>, Host,
         <<"' is not covered by the server certificate SANs. Valid hosts: ">>,
         SanList]);
to_message(Reason) ->
    iolist_to_binary(io_lib:format("~p", [Reason])).

%%====================================================================
%% Session / CSRF helpers
%%====================================================================

-spec session_cookie(cowboy_req:req()) -> binary() | undefined.
session_cookie(Req) ->
    Cookies = cowboy_req:parse_cookies(Req),
    proplists:get_value(cryptic_admin_session:cookie_name(), Cookies).

-spec check_csrf(binary(), cowboy_req:req()) -> boolean().
check_csrf(ExpectedCsrf, Req) ->
    case cowboy_req:header(<<"x-csrf-token">>, Req) of
        undefined -> false;
        Provided -> constant_time_equal(Provided, ExpectedCsrf)
    end.

-spec constant_time_equal(binary(), binary()) -> boolean().
constant_time_equal(A, B) when is_binary(A), is_binary(B),
                               byte_size(A) =:= byte_size(B) ->
    0 =:=
        lists:foldl(
            fun({X, Y}, Acc) -> Acc bor (X bxor Y) end,
            0,
            lists:zip(binary_to_list(A), binary_to_list(B))
        );
constant_time_equal(_, _) ->
    false.

-spec peer_ip(cowboy_req:req()) -> binary().
peer_ip(Req) ->
    {IpTuple, _Port} = cowboy_req:peer(Req),
    case inet:ntoa(IpTuple) of
        {error, _} -> <<"unknown">>;
        Str -> list_to_binary(Str)
    end.

-spec default_server_host() -> binary().
default_server_host() ->
    case os:getenv("CRYPTIC_PUBLIC_HOST") of
        false -> <<>>;
        "" -> <<>>;
        Env -> list_to_binary(Env)
    end.
