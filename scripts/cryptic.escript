#!/usr/bin/env escript
%% -*- erlang -*-
%% @doc Cryptic Secure Chat

main(_) ->
    %% Add the path to find cryptic modules
    code:add_path("_build/default/lib/cryptic/ebin"),
    
    %% Initialize the client library (starts inets and crypto)
    ok = cryptic_client_lib:init_client(),

    %% Show help
    cryptic_chat:help(),

    %% Start chat
    cryptic_chat:start().
