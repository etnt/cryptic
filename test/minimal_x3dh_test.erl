-module(minimal_x3dh_test).
-include_lib("eunit/include/eunit.hrl").

minimal_x3dh_test() ->
    %% Manual X3DH implementation to verify key operations
    cryptic_lib:initialize(),

    %% Alice's keys (sender)
    AliceKeys = cryptic_lib:generate_client_keys(),
    #{
        identity_dh_private := AliceIdPriv,
        identity_dh_public := AliceIdPub
    } = AliceKeys,

    %% Bob's keys (receiver)
    BobKeys = cryptic_lib:generate_client_keys(),
    #{
        identity_dh_private := BobIdPriv,
        identity_dh_public := BobIdPub,
        signed_prekey_private := BobSpkPriv,
        signed_prekey_public := BobSpkPub,
        one_time_prekeys := [
            #{private := BobOtpkPriv, public := BobOtpkPub} | _
        ]
    } = BobKeys,

    %% Alice generates ephemeral keypair
    {AliceEphPub, AliceEphPriv} = cryptic_lib:gen_keypair(),

    io:format("~n=== Manual X3DH Test ===~n"),
    io:format(
        "Alice Ephemeral: Pub=~p, Priv=~p~n",
        [base64:encode(AliceEphPub), base64:encode(AliceEphPriv)]
    ),

    %% Alice computes DH exchanges
    DH1_Alice = cryptic_lib:scalarmult(AliceEphPriv, BobIdPub),
    DH2_Alice = cryptic_lib:scalarmult(AliceIdPriv, BobSpkPub),
    DH3_Alice = cryptic_lib:scalarmult(AliceEphPriv, BobSpkPub),
    DH4_Alice = cryptic_lib:scalarmult(AliceEphPriv, BobOtpkPub),

    io:format("Alice DH1: ~p~n", [base64:encode(DH1_Alice)]),
    io:format("Alice DH2: ~p~n", [base64:encode(DH2_Alice)]),
    io:format("Alice DH3: ~p~n", [base64:encode(DH3_Alice)]),
    io:format("Alice DH4: ~p~n", [base64:encode(DH4_Alice)]),

    %% Bob computes DH exchanges using Alice's transmitted keys
    DH1_Bob = cryptic_lib:scalarmult(BobIdPriv, AliceEphPub),
    DH2_Bob = cryptic_lib:scalarmult(BobSpkPriv, AliceIdPub),
    DH3_Bob = cryptic_lib:scalarmult(BobSpkPriv, AliceEphPub),
    DH4_Bob = cryptic_lib:scalarmult(BobOtpkPriv, AliceEphPub),

    io:format("Bob DH1: ~p~n", [base64:encode(DH1_Bob)]),
    io:format("Bob DH2: ~p~n", [base64:encode(DH2_Bob)]),
    io:format("Bob DH3: ~p~n", [base64:encode(DH3_Bob)]),
    io:format("Bob DH4: ~p~n", [base64:encode(DH4_Bob)]),

    %% Check if DH values match
    io:format("~n=== DH Comparison ===~n"),
    io:format("DH1 match: ~p~n", [DH1_Alice =:= DH1_Bob]),
    io:format("DH2 match: ~p~n", [DH2_Alice =:= DH2_Bob]),
    io:format("DH3 match: ~p~n", [DH3_Alice =:= DH3_Bob]),
    io:format("DH4 match: ~p~n", [DH4_Alice =:= DH4_Bob]),

    %% All should match
    ?assert(DH1_Alice =:= DH1_Bob),
    ?assert(DH2_Alice =:= DH2_Bob),
    ?assert(DH3_Alice =:= DH3_Bob),
    ?assert(DH4_Alice =:= DH4_Bob).
