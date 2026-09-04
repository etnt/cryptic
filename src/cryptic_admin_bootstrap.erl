%% @doc Cryptic Web Admin - initial admin account bootstrap.
%%
%% Seeds the first web-admin account at server boot when none exists. Invoked
%% once from the supervision tree (after {@link cryptic_ca_init} has set up the
%% CA database) via {@link start_link/0}, which performs the work synchronously
%% and returns `ignore' so the supervisor does not keep a process around.
%%
%% The seeding is idempotent: if any admin account already exists it does
%% nothing, so container restarts never clobber or reset an account.
%%
%% Password source, in priority order (matches `docs/WEB-ADMIN-PLAN.md' §9.3):
%% <ol>
%%   <li>`CRYPTIC_ADMIN_PASSWORD_HASH_FILE' - file with a precomputed PBKDF2
%%       hash record (preferred; no plaintext ever enters the container).</li>
%%   <li>`CRYPTIC_ADMIN_PASSWORD_FILE' - file with a plaintext password
%%       (Docker/Podman secret); hashed at boot, flagged must-change.</li>
%%   <li>`CRYPTIC_ADMIN_PASSWORD' - plaintext env var (discouraged); flagged
%%       must-change.</li>
%%   <li>none - a random password is generated, the account is flagged
%%       must-change, and the password is printed once to the log.</li>
%% </ol>
%% The username comes from `CRYPTIC_ADMIN_USER' (default `admin').
%%
%% @author Cryptic Development Team
%% @since August 2026
-module(cryptic_admin_bootstrap).

-include("cryptic.hrl").

-export([start_link/0, run/0]).

-define(DEFAULT_ADMIN_USER, <<"admin">>).
-define(RANDOM_PASSWORD_BYTES, 18).

%%====================================================================
%% Supervised entry point
%%====================================================================

%% @doc Run the bootstrap once, then return `ignore' (no long-lived process).
-spec start_link() -> ignore.
start_link() ->
    try run() of
        _ -> ignore
    catch
        Class:Reason:Stack ->
            ?error("Admin bootstrap crashed: ~p:~p~n~p",
                   [Class, Reason, Stack]),
            ignore
    end.

%%====================================================================
%% Bootstrap logic
%%====================================================================

%% @doc Seed the first admin account if none exists.
-spec run() -> ok.
run() ->
    case cryptic_rpc:count_admins() of
        {ok, 0} ->
            seed(admin_user());
        {ok, N} ->
            ?info("Admin bootstrap: ~p admin account(s) already exist, "
                  "skipping seed", [N]),
            ok;
        {error, Reason} ->
            ?warning("Admin bootstrap: unable to count admin accounts (~p); "
                     "skipping seed", [Reason]),
            ok
    end.

-spec seed(binary()) -> ok.
seed(User) ->
    case password_source() of
        {hash_file, Path} ->
            seed_from_hash_file(User, Path);
        {password_file, Path} ->
            seed_from_password_file(User, Path);
        {password_env, Password} ->
            ?warning("Admin bootstrap: seeding from CRYPTIC_ADMIN_PASSWORD "
                     "env var (discouraged; prefer a mounted secret)", []),
            seed_from_plaintext(User, Password, true);
        none ->
            Password = random_password(),
            case seed_from_plaintext(User, Password, true) of
                ok ->
                    ?warning("Admin bootstrap: no password provided. Generated "
                             "a random password for user '~s': ~s~n"
                             "  >>> Save it now and change it on first login. "
                             "It is not stored and will not be shown again.",
                             [User, Password]),
                    ok;
                _ ->
                    ok
            end
    end.

seed_from_hash_file(User, Path) ->
    case file:read_file(Path) of
        {ok, Record} ->
            report(User, hash_file,
                   cryptic_admin_auth:create_account_from_record(
                       User, Record, #{must_change_password => false}));
        {error, Reason} ->
            ?error("Admin bootstrap: cannot read hash file ~s: ~p",
                   [Path, Reason]),
            ok
    end.

seed_from_password_file(User, Path) ->
    case file:read_file(Path) of
        {ok, Raw} ->
            Password = string:trim(Raw),
            seed_from_plaintext(User, Password, true);
        {error, Reason} ->
            ?error("Admin bootstrap: cannot read password file ~s: ~p",
                   [Path, Reason]),
            ok
    end.

seed_from_plaintext(User, Password, MustChange) ->
    report(User, plaintext,
           cryptic_admin_auth:create_account(
               User, Password, #{must_change_password => MustChange})).

-spec report(binary(), atom(), ok | {error, term()}) -> ok.
report(User, Source, ok) ->
    ?info("Admin bootstrap: created initial admin account '~s' (source: ~p)",
          [User, Source]),
    ok;
report(_User, _Source, {error, already_exists}) ->
    %% Raced with another path or a prior run; nothing to do.
    ok;
report(User, Source, {error, Reason}) ->
    ?error("Admin bootstrap: failed to create admin account '~s' "
           "(source: ~p): ~p", [User, Source, Reason]),
    ok.

%%====================================================================
%% Configuration helpers
%%====================================================================

-spec admin_user() -> binary().
admin_user() ->
    case nonempty_env("CRYPTIC_ADMIN_USER") of
        {ok, User} -> list_to_binary(User);
        error -> ?DEFAULT_ADMIN_USER
    end.

-spec password_source() ->
    {hash_file, string()} | {password_file, string()} |
    {password_env, binary()} | none.
password_source() ->
    case nonempty_env("CRYPTIC_ADMIN_PASSWORD_HASH_FILE") of
        {ok, Path} ->
            {hash_file, Path};
        error ->
            case nonempty_env("CRYPTIC_ADMIN_PASSWORD_FILE") of
                {ok, Path} ->
                    {password_file, Path};
                error ->
                    case nonempty_env("CRYPTIC_ADMIN_PASSWORD") of
                        {ok, Pw} -> {password_env, list_to_binary(Pw)};
                        error -> none
                    end
            end
    end.

-spec nonempty_env(string()) -> {ok, string()} | error.
nonempty_env(Name) ->
    case os:getenv(Name) of
        false -> error;
        "" -> error;
        Value -> {ok, Value}
    end.

%% @doc Generate a URL-safe random password (no padding).
-spec random_password() -> binary().
random_password() ->
    Raw = base64:encode(crypto:strong_rand_bytes(?RANDOM_PASSWORD_BYTES)),
    Url = binary:replace(
            binary:replace(Raw, <<"+">>, <<"-">>, [global]),
            <<"/">>, <<"_">>, [global]),
    binary:replace(Url, <<"=">>, <<"">>, [global]).
