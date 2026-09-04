%% @doc Cryptic Web Admin - Session Management
%%
%% ETS-backed server-side sessions for the web administration interface.
%% A `gen_server' owns the session table and a periodic cleanup timer; session
%% reads/writes happen directly in the calling (request) process against the
%% public ETS table for low latency.
%%
%% == Cookies ==
%% The session identifier delivered to the browser is signed with an
%% HMAC-SHA256 key generated fresh at each boot (so all sessions are
%% invalidated on restart). The signed value has the form
%% `Base64Url(Token) ++ "." ++ Base64Url(HMAC(secret, Token))'. Signature
%% verification happens before any ETS lookup, cheaply rejecting tampered or
%% malformed cookies.
%%
%% The handler is responsible for setting the cookie with `HttpOnly',
%% `Secure' and `SameSite=Strict' attributes; this module only produces and
%% validates the signed value and manages session lifetime.
%%
%% == Lifetime ==
%% Sessions expire at an absolute TTL (`webadmin_session_ttl', default 12h)
%% and also on inactivity (`webadmin_session_idle', default 30m). Each
%% successful validation slides the idle deadline forward.
%%
%% @author Cryptic Development Team
%% @since August 2026
-module(cryptic_admin_session).

-behaviour(gen_server).

-include("cryptic_server.hrl").

%% API
-export([
    start_link/0,
    create_session/1,
    validate/1,
    delete/1,
    cookie_name/0
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
-define(TABLE, cryptic_admin_sessions).
-define(SECRET_KEY, {?MODULE, cookie_secret}).
-define(CLEANUP_INTERVAL, 60000).
-define(COOKIE_NAME, <<"cryptic_admin_sid">>).

%% Defaults (seconds).
-define(DEFAULT_TTL, 43200).
-define(DEFAULT_IDLE, 1800).
-define(TOKEN_BYTES, 24).
-define(CSRF_BYTES, 24).

-record(session, {
    token :: binary(),
    username :: binary(),
    csrf :: binary(),
    created_at :: non_neg_integer(),
    last_seen :: non_neg_integer(),
    expires_at :: non_neg_integer()
}).

-record(state, {
    cleanup_timer :: reference()
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Cookie name used for the session identifier.
-spec cookie_name() -> binary().
cookie_name() ->
    ?COOKIE_NAME.

%% @doc Create a new session for Username.
%%
%% Returns the signed cookie value to send to the browser and the CSRF token
%% to return in the login response body.
-spec create_session(binary()) ->
    {ok, CookieValue :: binary(), CsrfToken :: binary()} | {error, term()}.
create_session(Username) when is_binary(Username) ->
    Now = erlang:system_time(second),
    Token = random_b64(?TOKEN_BYTES),
    Csrf = random_b64(?CSRF_BYTES),
    Session = #session{
        token = Token,
        username = Username,
        csrf = Csrf,
        created_at = Now,
        last_seen = Now,
        expires_at = Now + ttl()
    },
    true = ets:insert(?TABLE, Session),
    {ok, sign(Token), Csrf}.

%% @doc Validate a signed session cookie value.
%%
%% On success the idle deadline is refreshed. Expired or idle-timed-out
%% sessions are deleted and rejected.
-spec validate(binary() | undefined) ->
    {ok, Username :: binary(), CsrfToken :: binary()}
    | {error, invalid | expired}.
validate(undefined) ->
    {error, invalid};
validate(CookieValue) when is_binary(CookieValue) ->
    case unsign(CookieValue) of
        {ok, Token} ->
            case ets:lookup(?TABLE, Token) of
                [#session{} = S] ->
                    validate_lifetime(S);
                [] ->
                    {error, invalid}
            end;
        {error, _} ->
            {error, invalid}
    end.

%% @doc Delete the session referenced by a signed cookie value (logout).
-spec delete(binary() | undefined) -> ok.
delete(undefined) ->
    ok;
delete(CookieValue) when is_binary(CookieValue) ->
    case unsign(CookieValue) of
        {ok, Token} ->
            true = ets:delete(?TABLE, Token),
            ok;
        {error, _} ->
            ok
    end.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    ets:new(?TABLE, [named_table, set, public, {keypos, #session.token}]),
    persistent_term:put(?SECRET_KEY, crypto:strong_rand_bytes(32)),
    Timer = erlang:send_after(?CLEANUP_INTERVAL, self(), cleanup),
    {ok, #state{cleanup_timer = Timer}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(cleanup, State) ->
    Now = erlang:system_time(second),
    IdleCutoff = Now - idle(),
    %% Delete sessions past absolute TTL or idle deadline.
    MatchSpec = [
        {#session{expires_at = '$1', last_seen = '$2', _ = '_'},
         [{'orelse', {'=<', '$1', Now}, {'=<', '$2', IdleCutoff}}],
         [true]}
    ],
    _Deleted = ets:select_delete(?TABLE, MatchSpec),
    Timer = erlang:send_after(?CLEANUP_INTERVAL, self(), cleanup),
    {noreply, State#state{cleanup_timer = Timer}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal
%%====================================================================

-spec validate_lifetime(#session{}) ->
    {ok, binary(), binary()} | {error, expired}.
validate_lifetime(#session{token = Token, username = User, csrf = Csrf,
                           last_seen = LastSeen, expires_at = ExpiresAt}) ->
    Now = erlang:system_time(second),
    case Now >= ExpiresAt orelse (Now - LastSeen) >= idle() of
        true ->
            ets:delete(?TABLE, Token),
            {error, expired};
        false ->
            %% Slide the idle deadline; update_element is atomic.
            ets:update_element(?TABLE, Token, {#session.last_seen, Now}),
            {ok, User, Csrf}
    end.

-spec sign(binary()) -> binary().
sign(Token) ->
    Secret = persistent_term:get(?SECRET_KEY),
    Mac = crypto:mac(hmac, sha256, Secret, Token),
    <<(b64(Token))/binary, ".", (b64(Mac))/binary>>.

-spec unsign(binary()) -> {ok, binary()} | {error, bad_signature}.
unsign(Value) ->
    case binary:split(Value, <<".">>) of
        [TokenB64, MacB64] ->
            try
                Token = unb64(TokenB64),
                Mac = unb64(MacB64),
                Secret = persistent_term:get(?SECRET_KEY),
                Expected = crypto:mac(hmac, sha256, Secret, Token),
                case mac_equal(Mac, Expected) of
                    true -> {ok, Token};
                    false -> {error, bad_signature}
                end
            catch
                _:_ -> {error, bad_signature}
            end;
        _ ->
            {error, bad_signature}
    end.

-spec mac_equal(binary(), binary()) -> boolean().
mac_equal(A, B) when is_binary(A), is_binary(B), byte_size(A) =:= byte_size(B) ->
    0 =:=
        lists:foldl(
            fun({X, Y}, Acc) -> Acc bor (X bxor Y) end,
            0,
            lists:zip(binary_to_list(A), binary_to_list(B))
        );
mac_equal(_, _) ->
    false.

-spec random_b64(pos_integer()) -> binary().
random_b64(Bytes) ->
    b64(crypto:strong_rand_bytes(Bytes)).

-spec b64(binary()) -> binary().
b64(Bin) ->
    base64:encode(Bin, #{mode => urlsafe, padding => false}).

-spec unb64(binary()) -> binary().
unb64(Bin) ->
    base64:decode(Bin, #{mode => urlsafe, padding => false}).

-spec ttl() -> pos_integer().
ttl() ->
    application:get_env(cryptic, webadmin_session_ttl, ?DEFAULT_TTL).

-spec idle() -> pos_integer().
idle() ->
    application:get_env(cryptic, webadmin_session_idle, ?DEFAULT_IDLE).
