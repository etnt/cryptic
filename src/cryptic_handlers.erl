-module(cryptic_handlers).

-behaviour(cowboy_handler).

-export([init/2]).

-include_lib("eunit/include/eunit.hrl").

%% Expect JSON bodies; use simple minimal parsing with jiffy (or parse by hand).
%% To keep dependencies minimal, we'll do naive parsing assuming well-formed payloads.

init( Req , upload_prekey ) -> { ok , Body , Req2 } = cowboy_req : read_body( Req ) , { UserId , PubBin } = parse_prekey_json( Body ) , ets : insert( prekeys , { UserId , PubBin } ) , Resp = "{\"status\":\"ok\"}" , { ok , cowboy_req : reply( 201 , #{ { << "content-type" >> , << "application/json" >> } } , Resp , Req2 ) , state } .

    %% Body is JSON with keys: user_id, pub (base64)

init( Req , get_prekey ) -> { UserId , Req2 } = cowboy_req : binding( user_id , Req ) , case ets : lookup( prekeys , UserId ) of [ { UserId , PubBin } ] -> B64 = base64 : encode( PubBin ) , Resp = io_lib : format( "{\"user_id\":\"~s\",\"pub\":\"~s\"}" , [ UserId , B64 ] ) , { ok , cowboy_req : reply( 200 , #{ { << "content-type" >> , << "application/json" >> } } , list_to_binary( Resp ) , Req2 ) , state } ; [ ] -> { ok , cowboy_req : reply( 404 , #{ { << "content-type" >> , << "application/json" >> } } , << "{\"error\":\"not found\"}" >> , Req2 ) , state } end .
    %% path: /get_prekey/<user_id>
init( Req , send_blob ) -> { ok , Body , Req2 } = cowboy_req : read_body( Req ) , { From , To , EphemeralB64 , NonceB64 , CiphB64 } = parse_send_json( Body ) , Ephemeral = base64 : decode( EphemeralB64 ) , Nonce = base64 : decode( NonceB64 ) , Cipher = base64 : decode( CiphB64 ) , ets : insert( blobs , { To , { From , Ephemeral , Nonce , Cipher } } ) , { ok , cowboy_req : reply( 201 , #{ { << "content-type" >> , << "application/json" >> } } , << "{\"status\":\"ok\"}" >> , Req2 ) , state } .

init( Req , recv_blobs ) -> { UserId , Req2 } = cowboy_req : binding( user_id , Req ) , Blobs = ets : lookup( blobs , UserId ) , Items = lists : map( fun ( { _ , { From , Ephemeral , Nonce , Cipher } } ) -> Bep = base64 : encode( Ephemeral ) , Bn = base64 : encode( Nonce ) , Bc = base64 : encode( Cipher ) , io_lib : format( "{\"from\":\"~s\",\"ephemeral\":\"~s\",\"nonce\":\"~s\",\"cipher\":\"~s\"}" , [ From , Bep , Bn , Bc ] ) end , Blobs ) , Resp = "[" ++ string : join( lists : map( fun ( X ) -> lists : flatten( X ) end , Items ) , "," ) ++ "]" , lists : foreach( fun ( { Key , _Val } ) -> ets : delete_object( blobs , { Key , _Val } ) end , Blobs ) , { ok , cowboy_req : reply( 200 , #{ { << "content-type" >> , << "application/json" >> } } , Resp , Req2 ) , state } .

    %% remove delivered blobs

%% Simple JSON parsing helpers (VERY minimal; assumes no escapes)
parse_prekey_json(Body) ->
    %% Body like {"user_id":"alice","pub":"BASE64"}
    S = binary_to_list(Body),
    {_, U} = re:run(S, "\"user_id\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {_, P} = re:run(S, "\"pub\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {lists:flatten(
         lists:nth(1, U)),
     base64:decode(
         lists:flatten(
             lists:nth(1, P)))}.

parse_send_json(Body) ->
    S = binary_to_list(Body),
    {_, F} = re:run(S, "\"from\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {_, T} = re:run(S, "\"to\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {_, E} = re:run(S, "\"ephemeral\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {_, N} = re:run(S, "\"nonce\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {_, C} = re:run(S, "\"cipher\"\\s*:\\s*\"([^\"]+)\"", [{capture, [1], list}]),
    {lists:flatten(
         lists:nth(1, F)),
     lists:flatten(
         lists:nth(1, T)),
     lists:flatten(
         lists:nth(1, E)),
     lists:flatten(
         lists:nth(1, N)),
     lists:flatten(
         lists:nth(1, C))}.
