#!/usr/bin/env escript
%%! -noshell
%% @doc Offline admin password hashing helper for Cryptic web admin.
%%
%% Produces a PBKDF2-HMAC-SHA256 hash record that can be fed to the container
%% bootstrap via CRYPTIC_ADMIN_PASSWORD_HASH_FILE, so a plaintext password never
%% needs to enter the running server. The output format matches
%% cryptic_admin_auth:parse_hash_record/1:
%%
%%   pbkdf2_hmac_sha256$<iterations>$<dklen>$<base64-salt>$<base64-hash>
%%
%% Usage:
%%   scripts/cryptic-hash-admin-password.escript             # prompt / read stdin
%%   echo -n 'secret' | scripts/cryptic-hash-admin-password.escript
%%   scripts/cryptic-hash-admin-password.escript 'secret'    # arg (avoid: shell history)
%%
%% The record is written to stdout with a trailing newline. Redirect it into a
%% file mounted read-only into the container.

-define(ITERATIONS, 210000).
-define(DKLEN, 32).
-define(SALT_BYTES, 16).
-define(MIN_LEN, 12).

main(Args) ->
    Password = read_password(Args),
    case byte_size(Password) >= ?MIN_LEN of
        false ->
            io:format(standard_error,
                      "error: password must be at least ~p characters~n",
                      [?MIN_LEN]),
            halt(1);
        true ->
            Salt = crypto:strong_rand_bytes(?SALT_BYTES),
            Hash = crypto:pbkdf2_hmac(sha256, Password, Salt,
                                      ?ITERATIONS, ?DKLEN),
            Record = io_lib:format(
                "pbkdf2_hmac_sha256$~p$~p$~s$~s",
                [?ITERATIONS, ?DKLEN,
                 base64:encode(Salt), base64:encode(Hash)]),
            io:format("~s~n", [Record]),
            halt(0)
    end.

read_password([Arg | _]) when Arg =/= [] ->
    unicode:characters_to_binary(Arg);
read_password(_) ->
    case io:get_line("") of
        eof -> <<>>;
        {error, _} -> <<>>;
        Line -> unicode:characters_to_binary(string:trim(Line))
    end.
