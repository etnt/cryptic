%%% @doc Simple X3DH debug test
-module(simple_x3dh_test).

-include_lib("eunit/include/eunit.hrl").

simple_x3dh_test() ->
    %% Setup
    application:ensure_all_started(crypto),
    cryptic_lib:initialize(),

    %% Generate keys
    AliceKeys = cryptic_lib:generate_client_keys(),
    BobKeys = cryptic_lib:generate_client_keys(),

    %% Create Bob's bundle
    #{identity_sign_public := BobIdPub,
      identity_dh_public := BobIdDHPub,
      signed_prekey_public := BobSpkPub,
      signed_prekey_signature := BobSpkSig,
      one_time_prekeys := [BobFirstOtpk | _],
      key_id := BobKeyId} =
        BobKeys,

    BobBundle =
        #{identity_sign_public => BobIdPub,
          identity_dh_public => BobIdDHPub,
          signed_prekey => #{public => BobSpkPub, signature => BobSpkSig},
          one_time_prekey => BobFirstOtpk,
          key_id => BobKeyId},

    %% Alice encrypts
    Message = <<"Test">>,
    {ok, {MessageBlob, MessageId}} =
        cryptic_lib:x3dh_sender_init(AliceKeys, BobBundle, Message),

    %% Debug: Print message blob structure
    io:format("MessageBlob keys: ~p~n", [maps:keys(MessageBlob)]),

    #{metadata := Metadata} = MessageBlob,
    io:format("Metadata keys: ~p~n", [maps:keys(Metadata)]),

    %% Check if required keys are present
    RequiredKeys = [ephemeral_public, sender_identity_dh_public, message_id, otpk_id],
    lists:foreach(fun(Key) ->
                     case maps:is_key(Key, Metadata) of
                         true -> io:format("✓ ~p present~n", [Key]);
                         false -> io:format("✗ ~p MISSING~n", [Key])
                     end
                  end,
                  RequiredKeys),

    %% Bob tries to decrypt
    #{metadata := #{otpk_id := OtpkId}} = MessageBlob,
    {ok, OtpkPriv} = cryptic_lib:find_otpk_private_key(BobKeys, OtpkId),
    #{identity_sign_public := AliceIdPub} = AliceKeys,

    Result = cryptic_lib:x3dh_receiver_decrypt(BobKeys, MessageBlob, AliceIdPub, OtpkPriv),

    case Result of
        {ok, {DecryptedMessage, _}} when DecryptedMessage == Message ->
            io:format("✓ Decryption successful: ~p~n", [DecryptedMessage]);
        {error, Reason} ->
            io:format("✗ Decryption failed: ~p~n", [Reason])
    end,

    ?assertMatch({ok, {Message, MessageId}}, Result).
