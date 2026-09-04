%% @doc Cryptic Web Admin - Authentication HTTP Handler
%%
%% Cowboy handler for the web admin authentication endpoints. The concrete
%% operation is selected by the route configuration via the handler `State'
%% map (`#{operation => login | logout | session}'), mirroring the dispatch
%% style of {@link cryptic_mcp_admin_handler}. Routes are wired in
%% {@link cryptic_server} (Phase 2).
%%
%% Endpoints:
%% <ul>
%%   <li>`POST /admin/api/login'   - `{username, password}' JSON; on success
%%       sets the session cookie and returns the CSRF token.</li>
%%   <li>`POST /admin/api/logout'  - deletes the current session (CSRF
%%       protected).</li>
%%   <li>`GET  /admin/api/session' - reports whether the request carries a
%%       valid session.</li>
%% </ul>
%%
%% Login attempts are rate limited per client IP via
%% {@link cryptic_ca_rate_limiter} using the `admin_login' policy.
%%
%% @author Cryptic Development Team
%% @since August 2026
-module(cryptic_webadmin_auth_handler).

-export([init/2]).

-include("cryptic_server.hrl").
-include("cryptic_ca.hrl").

-define(COOKIE_PATH, <<"/admin">>).

init(Req0, State) ->
    Operation = maps:get(operation, State, undefined),
    Method = cowboy_req:method(Req0),
    {StatusCode, BodyMap, Req1} =
        try
            handle(Operation, Method, Req0)
        catch
            Class:Reason:Stack ->
                ?error("webadmin auth handler crashed: ~p:~p~n~p", [Class, Reason, Stack]),
                {500, #{status => <<"error">>, message => <<"internal_server_error">>}, Req0}
        end,
    Req2 = cowboy_req:reply(
        StatusCode,
        #{<<"content-type">> => <<"application/json">>},
        jsx:encode(BodyMap),
        Req1
    ),
    {ok, Req2, State}.

%%====================================================================
%% Operation dispatch
%%====================================================================

handle(login, <<"POST">>, Req0) ->
    ClientIp = client_ip(Req0),
    case cryptic_ca_rate_limiter:check_limit(ClientIp, admin_login, 1) of
        {error, rate_limited, RetryAfter} ->
            {429,
             #{status => <<"error">>, message => <<"rate_limited">>,
               retry_after => RetryAfter},
             Req0};
        _Allowed ->
            do_login(Req0)
    end;
handle(logout, <<"POST">>, Req0) ->
    do_logout(Req0);
handle(session, <<"GET">>, Req0) ->
    do_session(Req0);
handle(undefined, _Method, Req0) ->
    {404, #{status => <<"error">>, message => <<"not_found">>}, Req0};
handle(_Operation, _Method, Req0) ->
    {405, #{status => <<"error">>, message => <<"method_not_allowed">>}, Req0}.

%%====================================================================
%% Login
%%====================================================================

do_login(Req0) ->
    {ok, RawBody, Req1} = cowboy_req:read_body(Req0),
    case decode_json(RawBody) of
        {error, _} ->
            {400, #{status => <<"error">>, message => <<"invalid_json">>}, Req1};
        {ok, Body} ->
            Username = maps:get(<<"username">>, Body, undefined),
            Password = maps:get(<<"password">>, Body, undefined),
            case is_binary(Username) andalso is_binary(Password) of
                false ->
                    {400,
                     #{status => <<"error">>, message => <<"missing_credentials">>},
                     Req1};
                true ->
                    authenticate(Username, Password, Req1)
            end
    end.

authenticate(Username, Password, Req0) ->
    case cryptic_admin_auth:verify_password(Username, Password) of
        {ok, Account} ->
            {ok, CookieValue, Csrf} = cryptic_admin_session:create_session(Username),
            _ = update_last_login(Username),
            Req1 = set_session_cookie(CookieValue, Req0),
            {200,
             #{status => <<"ok">>,
               username => Username,
               csrf_token => Csrf,
               must_change_password => must_change_flag(Account)},
             Req1};
        {error, suspended} ->
            {403, #{status => <<"error">>, message => <<"account_suspended">>}, Req0};
        {error, invalid_credentials} ->
            {401, #{status => <<"error">>, message => <<"invalid_credentials">>}, Req0};
        {error, _Reason} ->
            {500, #{status => <<"error">>, message => <<"internal_server_error">>}, Req0}
    end.

%%====================================================================
%% Logout
%%====================================================================

do_logout(Req0) ->
    CookieValue = session_cookie(Req0),
    case cryptic_admin_session:validate(CookieValue) of
        {ok, _User, Csrf} ->
            case check_csrf(Csrf, Req0) of
                true ->
                    ok = cryptic_admin_session:delete(CookieValue),
                    Req1 = clear_session_cookie(Req0),
                    {200, #{status => <<"ok">>}, Req1};
                false ->
                    {403, #{status => <<"error">>, message => <<"csrf_failed">>}, Req0}
            end;
        {error, _} ->
            %% Already logged out / invalid session: clear cookie idempotently.
            Req1 = clear_session_cookie(Req0),
            {200, #{status => <<"ok">>}, Req1}
    end.

%%====================================================================
%% Session status
%%====================================================================

do_session(Req0) ->
    CookieValue = session_cookie(Req0),
    case cryptic_admin_session:validate(CookieValue) of
        {ok, User, Csrf} ->
            {200,
             #{status => <<"ok">>,
               authenticated => true,
               username => User,
               csrf_token => Csrf},
             Req0};
        {error, _} ->
            {401, #{status => <<"error">>, authenticated => false}, Req0}
    end.

%%====================================================================
%% Helpers
%%====================================================================

must_change_flag(#admin_account{must_change_password = 1}) -> true;
must_change_flag(#admin_account{}) -> false.

update_last_login(Username) ->
    case application:get_env(cryptic, ca_db_ref) of
        {ok, DbRef} -> cryptic_ca_store:update_admin_last_login(DbRef, Username);
        _ -> ok
    end.

-spec check_csrf(binary(), cowboy_req:req()) -> boolean().
check_csrf(ExpectedCsrf, Req) ->
    case cowboy_req:header(<<"x-csrf-token">>, Req) of
        undefined -> false;
        Provided -> constant_time_equal(Provided, ExpectedCsrf)
    end.

-spec session_cookie(cowboy_req:req()) -> binary() | undefined.
session_cookie(Req) ->
    Cookies = cowboy_req:parse_cookies(Req),
    proplists:get_value(cryptic_admin_session:cookie_name(), Cookies).

set_session_cookie(Value, Req) ->
    cowboy_req:set_resp_cookie(
        cryptic_admin_session:cookie_name(),
        Value,
        Req,
        cookie_opts(session_ttl())
    ).

clear_session_cookie(Req) ->
    cowboy_req:set_resp_cookie(
        cryptic_admin_session:cookie_name(),
        <<>>,
        Req,
        cookie_opts(0)
    ).

cookie_opts(MaxAge) ->
    #{
        http_only => true,
        secure => true,
        same_site => strict,
        path => ?COOKIE_PATH,
        max_age => MaxAge
    }.

session_ttl() ->
    application:get_env(cryptic, webadmin_session_ttl, 43200).

-spec client_ip(cowboy_req:req()) -> binary().
client_ip(Req) ->
    {IpTuple, _Port} = cowboy_req:peer(Req),
    case inet:ntoa(IpTuple) of
        {error, _} -> <<"unknown">>;
        Str -> list_to_binary(Str)
    end.

decode_json(<<>>) ->
    {ok, #{}};
decode_json(Raw) ->
    try
        {ok, jsx:decode(Raw, [return_maps])}
    catch
        _:_ -> {error, invalid_json}
    end.

-spec constant_time_equal(binary(), binary()) -> boolean().
constant_time_equal(A, B) when is_binary(A), is_binary(B), byte_size(A) =:= byte_size(B) ->
    0 =:=
        lists:foldl(
            fun({X, Y}, Acc) -> Acc bor (X bxor Y) end,
            0,
            lists:zip(binary_to_list(A), binary_to_list(B))
        );
constant_time_equal(_, _) ->
    false.
