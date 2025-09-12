-module(cryptic_handlers).

-behaviour(cowboy_handler).

-export([init/2]).

-include("cryptic.hrl").

%% Handler for uploading prekeys
init(Req, upload_prekey) ->
    try
        UserId = binary_to_list(cowboy_req:binding(user_id, Req)),
        {ok, Body, Req2} = cowboy_req:read_body(Req),
        ?dbg("Upload prekey - UserId: ~p, Body: ~p~n", [UserId, Body]),
        PubBin = parse_prekey_json(Body),
        ets:insert(prekeys, {UserId, PubBin}),
        Resp = <<"{\"status\":\"ok\"}">>,
        {ok, cowboy_req:reply(201, 
            #{<<"content-type">> => <<"application/json">>}, 
            Resp, Req2), state}
    catch
        Error:Reason ->
            ?error("Upload prekey error: ~p:~p~n", [Error, Reason]),
            ErrorResp1 = <<"{\"error\":\"invalid request\"}">>,
            {ok, cowboy_req:reply(400, 
                #{<<"content-type">> => <<"application/json">>}, 
                ErrorResp1, Req), state}
    end;

%% Handler for fetching prekeys
init(Req, get_prekey) ->
    try
        UserId = cowboy_req:binding(user_id, Req),
        ?dbg("Get prekey - UserId: ~s~n", [UserId]),
        case ets:lookup(prekeys, binary_to_list(UserId)) of
            [{UserIdStr, PubBin}] ->
                B64 = base64:encode(PubBin),
                Resp = iolist_to_binary(
                    io_lib:format("{\"user_id\":\"~s\",\"pub\":\"~s\"}", 
                        [UserIdStr, B64])),
                {ok, cowboy_req:reply(200, 
                    #{<<"content-type">> => <<"application/json">>}, 
                    Resp, Req), state};
            [] ->
                ErrorResp2 = <<"{\"error\":\"user not found\"}">>,
                {ok, cowboy_req:reply(404, 
                    #{<<"content-type">> => <<"application/json">>}, 
                    ErrorResp2, Req), state}
        end
    catch
        _:_Error ->
            ErrorResp3 = <<"{\"error\":\"invalid request\"}">>,
            {ok, cowboy_req:reply(400, 
                #{<<"content-type">> => <<"application/json">>}, 
                ErrorResp3, Req), state}
    end;

%% Handler for sending encrypted message blobs
init(Req, send_blob) ->
    try
        {ok, Body, Req2} = cowboy_req:read_body(Req),
        {From, To, EphemeralB64, NonceB64, CiphB64} = parse_send_json(Body),
        Ephemeral = base64:decode(EphemeralB64),
        Nonce = base64:decode(NonceB64),
        Cipher = base64:decode(CiphB64),
        ?dbg("Send blob - From: ~s, To: ~s~n", [From, To]),
        ets:insert(blobs, {To, {From, Ephemeral, Nonce, Cipher}}),
        Resp = <<"{\"status\":\"ok\"}">>,
        {ok, cowboy_req:reply(201, 
            #{<<"content-type">> => <<"application/json">>}, 
            Resp, Req2), state}
    catch
        _:_Error ->
            ErrorResp4 = <<"{\"error\":\"invalid request\"}">>,
            {ok, cowboy_req:reply(400, 
                #{<<"content-type">> => <<"application/json">>}, 
                ErrorResp4, Req), state}
    end;

%% Handler for receiving encrypted message blobs
init(Req, recv_blobs) ->
    try
        UserId = cowboy_req:binding(user_id, Req),
        UserIdStr = binary_to_list(UserId),
        Blobs = ets:lookup(blobs, UserIdStr),
        Items = lists:map(fun({_, {From, Ephemeral, Nonce, Cipher}}) ->
            EphB64 = base64:encode(Ephemeral),
            NonceB64 = base64:encode(Nonce),
            CiphB64 = base64:encode(Cipher),
            ?dbg("Receive blob - From: ~s, To: ~s~n", [From, UserId]),
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
            ets:delete_object(blobs, {Key, Val})
        end, Blobs),

        {ok, cowboy_req:reply(200, 
            #{<<"content-type">> => <<"application/json">>}, 
            Resp, Req), state}
    catch
        _:_Error ->
            ErrorResp5 = <<"{\"error\":\"invalid request\"}">>,
            {ok, cowboy_req:reply(400, 
                #{<<"content-type">> => <<"application/json">>}, 
                ErrorResp5, Req), state}
    end;

%% Handler for listing all users with prekeys
init(Req = #{method := <<"GET">>}, list_users) ->
    try
        %% Get all users from the prekeys table
        AllUsers = ets:tab2list(prekeys),
        UserNames = [UserId || {UserId, _PubKey} <- AllUsers],
        ?dbg("List users - Found users: ~p~n", [UserNames]),
        %% Create JSON response with user list
        UsersJson = case UserNames of
            [] ->
                <<"[]">>;
            _ ->
                UserNamesStr = string:join([io_lib:format("\"~s\"", [User]) || User <- UserNames], ","),
                iolist_to_binary(["[", UserNamesStr, "]"])
        end,

            {ok, cowboy_req:reply(200, 
                #{<<"content-type">> => <<"application/json">>}, 
                UsersJson, Req), state}
    catch
        _:_Error ->
            ErrorResp = <<"{\"error\":\"failed to list users\"}">>,
            {ok, cowboy_req:reply(500, 
                #{<<"content-type">> => <<"application/json">>}, 
                ErrorResp, Req), state}
    end;

%% Handler for peeking at message count without consuming them
init(Req, peek_messages) ->
    try
        UserId = cowboy_req:binding(user_id, Req),
        UserIdStr = binary_to_list(UserId),
        Blobs = ets:lookup(blobs, UserIdStr),
        Count = length(Blobs),
        ?dbg("Peek messages - User: ~s, Count: ~p~n", [UserIdStr, Count]),
        
        CountJson = iolist_to_binary(io_lib:format("{\"count\":~p}", [Count])),
        
        {ok, cowboy_req:reply(200, 
            #{<<"content-type">> => <<"application/json">>}, 
            CountJson, Req), state}
    catch
        _:_Error ->
            ErrorResp = <<"{\"error\":\"failed to peek messages\"}">>,
            {ok, cowboy_req:reply(500, 
                #{<<"content-type">> => <<"application/json">>}, 
                ErrorResp, Req), state}
    end.%% Simple JSON parsing helpers (VERY minimal; assumes no escapes)
parse_prekey_json(Body) ->
    %% Body like {"prekey":"BASE64"}
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
