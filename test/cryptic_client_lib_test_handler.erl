-module(cryptic_client_lib_test_handler).
-behaviour(cowboy_handler).

-export([init/2]).

%%%===================================================================
%%% Test Handler for Client Library Tests
%%%===================================================================

init(Req, upload_prekey) ->
    UserId = binary_to_list(cowboy_req:binding(user_id, Req)),
    {ok, Body, Req2} = cowboy_req:read_body(Req),
    PubBin = parse_prekey_json(Body),
    ets:insert(prekeys_test, {UserId, PubBin}),
    Resp = <<"{\"status\":\"ok\"}">>,
    {ok, cowboy_req:reply(201, 
        #{<<"content-type">> => <<"application/json">>}, 
        Resp, Req2), state};

init(Req, get_prekey) ->
    UserId = cowboy_req:binding(user_id, Req),
    case ets:lookup(prekeys_test, binary_to_list(UserId)) of
        [{UserIdStr, PubBin}] ->
            B64 = base64:encode(PubBin),
            Resp = iolist_to_binary(
                io_lib:format("{\"user_id\":\"~s\",\"pub\":\"~s\"}", 
                    [UserIdStr, B64])),
            {ok, cowboy_req:reply(200, 
                #{<<"content-type">> => <<"application/json">>}, 
                Resp, Req), state};
        [] ->
            ErrorResp = <<"{\"error\":\"user not found\"}">>,
            {ok, cowboy_req:reply(404, 
                #{<<"content-type">> => <<"application/json">>}, 
                ErrorResp, Req), state}
    end;

init(Req, send_blob) ->
    {ok, Body, Req2} = cowboy_req:read_body(Req),
    {From, To, EphemeralB64, NonceB64, CiphB64} = parse_send_json(Body),
    Ephemeral = base64:decode(EphemeralB64),
    Nonce = base64:decode(NonceB64),
    Cipher = base64:decode(CiphB64),
    ets:insert(blobs_test, {To, {From, Ephemeral, Nonce, Cipher}}),
    Resp = <<"{\"status\":\"ok\"}">>,
    {ok, cowboy_req:reply(201, 
        #{<<"content-type">> => <<"application/json">>}, 
        Resp, Req2), state};

init(Req, recv_blobs) ->
    UserId = cowboy_req:binding(user_id, Req),
    UserIdStr = binary_to_list(UserId),
    Blobs = ets:lookup(blobs_test, UserIdStr),
    Items = lists:map(fun({_, {From, Ephemeral, Nonce, Cipher}}) ->
        EphB64 = base64:encode(Ephemeral),
        NonceB64 = base64:encode(Nonce),
        CiphB64 = base64:encode(Cipher),
        iolist_to_binary(
            io_lib:format("{\"from\":\"~s\",\"ephemeral\":\"~s\",\"nonce\":\"~s\",\"cipher\":\"~s\"}", 
                [From, EphB64, NonceB64, CiphB64]))
    end, Blobs),
    
    Resp = case Items of
        [] -> <<"[]">>;
        _ -> 
            ItemsStr = string:join([binary_to_list(Item) || Item <- Items], ","),
            iolist_to_binary(["[", ItemsStr, "]"])
    end,
    
    %% Remove delivered blobs
    lists:foreach(fun({Key, Val}) ->
        ets:delete_object(blobs_test, {Key, Val})
    end, Blobs),
    
    {ok, cowboy_req:reply(200, 
        #{<<"content-type">> => <<"application/json">>}, 
        Resp, Req), state}.

%%%===================================================================
%%% Helper Functions
%%%===================================================================

parse_prekey_json(Body) ->
    S = binary_to_list(Body),
    {match, P} = re:run(S, "\"prekey\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    base64:decode(lists:flatten(lists:nth(1, P))).

parse_send_json(Body) ->
    S = binary_to_list(Body),
    {match, F} = re:run(S, "\"from\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {match, T} = re:run(S, "\"to\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {match, E} = re:run(S, "\"ephemeral\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {match, N} = re:run(S, "\"nonce\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {match, C} = re:run(S, "\"cipher\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {lists:flatten(lists:nth(1, F)),
     lists:flatten(lists:nth(1, T)),
     lists:flatten(lists:nth(1, E)),
     lists:flatten(lists:nth(1, N)),
     lists:flatten(lists:nth(1, C))}.
