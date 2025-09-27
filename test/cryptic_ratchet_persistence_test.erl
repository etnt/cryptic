%%% @doc EUnit tests for Double Ratchet Session Persistence
%%%
%%% This module contains comprehensive tests for the ratchet session persistence
%%% functionality, covering encryption, storage, loading, and error handling.
%%%
%%% @author Cryptic Team
%%% @version 1.0
%%% @since 2025-09-27
-module(cryptic_ratchet_persistence_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

%%%===================================================================
%%% Test Setup and Teardown
%%%===================================================================

setup() ->
    %% Start event manager for debug logging
    case whereis(cryptic_event_manager) of
        undefined ->
            {ok, _Pid} = gen_event:start_link({local, cryptic_event_manager}),
            gen_event:add_handler(cryptic_event_manager, cryptic_console_logger, []);
        _ ->
            ok
    end,
    
    cryptic_lib:initialize(),
    %% Create a temporary directory for tests
    TestDir = "/tmp/cryptic_persistence_test_" ++ integer_to_list(erlang:system_time(second)),
    file:make_dir(TestDir),
    TestDir.

cleanup(TestDir) ->
    %% Remove test directory and all files
    os:cmd("rm -rf " ++ TestDir).

%%%===================================================================
%%% Basic Session Storage Tests
%%%===================================================================

%% Test saving and loading a single ratchet session
basic_save_load_test() ->
    TestDir = setup(),
    try
        %% Create test session data
        SessionData = #{
            sending_chain_key => crypto:strong_rand_bytes(32),
            receiving_chain_key => crypto:strong_rand_bytes(32),
            root_key => crypto:strong_rand_bytes(32),
            send_msg_number => 42,
            recv_msg_number => 13,
            dh_ratchet_step => 7,
            sending_chain_active => true,
            receiving_chain_active => false
        },
        Username = "alice",
        Passphrase = "test_passphrase_123",

        %% Save session
        SaveResult = cryptic_lib:save_ratchet_session(Username, SessionData, Passphrase, TestDir),
        ?assertEqual(ok, SaveResult),

        %% Verify file was created
        SessionFile = filename:join(TestDir, Username ++ ".session"),
        ?assert(filelib:is_file(SessionFile)),

        %% Load session
        LoadResult = cryptic_lib:load_ratchet_session(Username, Passphrase, TestDir),
        ?assertMatch({ok, _}, LoadResult),
        {ok, LoadedData} = LoadResult,

        %% Verify data matches exactly
        ?assertEqual(SessionData, LoadedData)
    after
        cleanup(TestDir)
    end.

%% Test loading non-existent session
load_nonexistent_session_test() ->
    TestDir = setup(),
    try
        Username = "nonexistent_user",
        Passphrase = "any_passphrase",

        %% Try to load non-existent session
        LoadResult = cryptic_lib:load_ratchet_session(Username, Passphrase, TestDir),
        ?assertMatch({error, _}, LoadResult)
    after
        cleanup(TestDir)
    end.

%% Test loading with wrong passphrase
wrong_passphrase_test() ->
    TestDir = setup(),
    try
        SessionData = #{test_key => <<"test_value">>},
        Username = "bob",
        CorrectPassphrase = "correct_pass",
        WrongPassphrase = "wrong_pass",

        %% Save with correct passphrase
        SaveResult = cryptic_lib:save_ratchet_session(Username, SessionData, CorrectPassphrase, TestDir),
        ?assertEqual(ok, SaveResult),

        %% Try to load with wrong passphrase
        LoadResult = cryptic_lib:load_ratchet_session(Username, WrongPassphrase, TestDir),
        ?assertMatch({error, _}, LoadResult)
    after
        cleanup(TestDir)
    end.

%%%===================================================================
%%% Multiple Sessions Tests
%%%===================================================================

%% Test saving and loading multiple sessions
multiple_sessions_test() ->
    TestDir = setup(),
    try
        Passphrase = "shared_passphrase",
        
        %% Create multiple session data sets
        Sessions = [
            {"alice", #{key1 => crypto:strong_rand_bytes(16), counter => 1}},
            {"bob", #{key2 => crypto:strong_rand_bytes(16), counter => 2}},
            {"charlie", #{key3 => crypto:strong_rand_bytes(16), counter => 3}}
        ],

        %% Save all sessions
        lists:foreach(fun({Username, SessionData}) ->
            Result = cryptic_lib:save_ratchet_session(Username, SessionData, Passphrase, TestDir),
            ?assertEqual(ok, Result)
        end, Sessions),

        %% Load each session individually
        lists:foreach(fun({Username, ExpectedData}) ->
            LoadResult = cryptic_lib:load_ratchet_session(Username, Passphrase, TestDir),
            ?assertMatch({ok, _}, LoadResult),
            {ok, LoadedData} = LoadResult,
            ?assertEqual(ExpectedData, LoadedData)
        end, Sessions),

        %% Load all sessions at once
        LoadAllResult = cryptic_lib:load_all_ratchet_sessions(Passphrase, TestDir),
        ?assertMatch({ok, _}, LoadAllResult),
        {ok, AllSessions} = LoadAllResult,

        %% Verify all sessions are present
        ?assertEqual(3, maps:size(AllSessions)),
        lists:foreach(fun({Username, ExpectedData}) ->
            ?assert(maps:is_key(Username, AllSessions)),
            LoadedData = maps:get(Username, AllSessions),
            ?assertEqual(ExpectedData, LoadedData)
        end, Sessions)
    after
        cleanup(TestDir)
    end.

%% Test load_all_ratchet_sessions with empty directory
load_all_empty_directory_test() ->
    TestDir = setup(),
    try
        Passphrase = "any_passphrase",
        
        %% Load from empty directory
        LoadAllResult = cryptic_lib:load_all_ratchet_sessions(Passphrase, TestDir),
        ?assertMatch({ok, _}, LoadAllResult),
        {ok, AllSessions} = LoadAllResult,
        
        %% Should return empty map
        ?assertEqual(#{}, AllSessions)
    after
        cleanup(TestDir)
    end.

%% Test load_all_ratchet_sessions with non-existent directory
load_all_nonexistent_directory_test() ->
    NonExistentDir = "/tmp/cryptic_nonexistent_dir_" ++ integer_to_list(erlang:system_time(second)),
    Passphrase = "any_passphrase",
    
    %% Load from non-existent directory
    LoadAllResult = cryptic_lib:load_all_ratchet_sessions(Passphrase, NonExistentDir),
    ?assertMatch({ok, _}, LoadAllResult),
    {ok, AllSessions} = LoadAllResult,
    
    %% Should return empty map (directory doesn't exist)
    ?assertEqual(#{}, AllSessions).

%%%===================================================================
%%% Session Deletion Tests
%%%===================================================================

%% Test deleting an existing session
delete_existing_session_test() ->
    TestDir = setup(),
    try
        SessionData = #{test_data => <<"delete_me">>},
        Username = "delete_test_user",
        Passphrase = "test_pass",

        %% Save session
        SaveResult = cryptic_lib:save_ratchet_session(Username, SessionData, Passphrase, TestDir),
        ?assertEqual(ok, SaveResult),

        %% Verify it exists
        SessionFile = filename:join(TestDir, Username ++ ".session"),
        ?assert(filelib:is_file(SessionFile)),

        %% Delete session
        DeleteResult = cryptic_lib:delete_ratchet_session(Username, TestDir),
        ?assertEqual(ok, DeleteResult),

        %% Verify it's gone
        ?assertNot(filelib:is_file(SessionFile))
    after
        cleanup(TestDir)
    end.

%% Test deleting non-existent session (should succeed)
delete_nonexistent_session_test() ->
    TestDir = setup(),
    try
        Username = "nonexistent_user",
        
        %% Delete non-existent session (should be ok)
        DeleteResult = cryptic_lib:delete_ratchet_session(Username, TestDir),
        ?assertEqual(ok, DeleteResult)
    after
        cleanup(TestDir)
    end.

%%%===================================================================
%%% Error Handling Tests
%%%===================================================================

%% Test handling invalid directory permissions
invalid_directory_test() ->
    %% Try to save to root directory (should fail due to permissions)
    SessionData = #{test_key => <<"test_value">>},
    Username = "permission_test",
    Passphrase = "test_pass",
    
    %% This should fail due to permission denied
    SaveResult = cryptic_lib:save_ratchet_session(Username, SessionData, Passphrase, "/root/invalid"),
    ?assertMatch({error, _}, SaveResult).

%% Test handling corrupted session files
corrupted_file_test() ->
    TestDir = setup(),
    try
        Username = "corrupted_user",
        Passphrase = "test_pass",
        SessionFile = filename:join(TestDir, Username ++ ".session"),

        %% Create corrupted file
        file:write_file(SessionFile, <<"invalid_encrypted_data_that_cannot_be_decrypted">>),

        %% Try to load corrupted session
        LoadResult = cryptic_lib:load_ratchet_session(Username, Passphrase, TestDir),
        ?assertMatch({error, _}, LoadResult)
    after
        cleanup(TestDir)
    end.

%%%===================================================================
%%% Data Integrity Tests
%%%===================================================================

%% Test with complex session data structures
complex_data_structures_test() ->
    TestDir = setup(),
    try
        %% Create complex nested session data
        ComplexSessionData = #{
            root_key => crypto:strong_rand_bytes(32),
            sending_chain => #{
                key => crypto:strong_rand_bytes(32),
                number => 12345,
                active => true
            },
            receiving_chain => #{
                key => crypto:strong_rand_bytes(32),
                number => 54321,
                active => false
            },
            dh_pair => {
                crypto:strong_rand_bytes(32),  % private key
                crypto:strong_rand_bytes(32)   % public key
            },
            skipped_keys => #{
                <<"chain1">> => [
                    #{msg_number => 1, key => crypto:strong_rand_bytes(32)},
                    #{msg_number => 3, key => crypto:strong_rand_bytes(32)}
                ]
            },
            metadata => #{
                created => erlang:system_time(second),
                version => <<"1.0">>,
                flags => [reliable, authenticated]
            }
        },
        Username = "complex_data_user",
        Passphrase = "complex_test_pass",

        %% Save complex session
        SaveResult = cryptic_lib:save_ratchet_session(Username, ComplexSessionData, Passphrase, TestDir),
        ?assertEqual(ok, SaveResult),

        %% Load and verify complex session
        LoadResult = cryptic_lib:load_ratchet_session(Username, Passphrase, TestDir),
        ?assertMatch({ok, _}, LoadResult),
        {ok, LoadedData} = LoadResult,

        %% Verify complete data integrity
        ?assertEqual(ComplexSessionData, LoadedData)
    after
        cleanup(TestDir)
    end.

%% Test with binary and string passphrase formats
passphrase_format_test() ->
    TestDir = setup(),
    try
        SessionData = #{test_key => <<"passphrase_format_test">>},
        Username = "format_test_user",
        StringPassphrase = "string_passphrase",
        BinaryPassphrase = <<"binary_passphrase">>,

        %% Test string passphrase
        SaveResult1 = cryptic_lib:save_ratchet_session(Username ++ "_str", SessionData, StringPassphrase, TestDir),
        ?assertEqual(ok, SaveResult1),
        
        LoadResult1 = cryptic_lib:load_ratchet_session(Username ++ "_str", StringPassphrase, TestDir),
        ?assertMatch({ok, SessionData}, LoadResult1),

        %% Test binary passphrase
        SaveResult2 = cryptic_lib:save_ratchet_session(Username ++ "_bin", SessionData, BinaryPassphrase, TestDir),
        ?assertEqual(ok, SaveResult2),
        
        LoadResult2 = cryptic_lib:load_ratchet_session(Username ++ "_bin", BinaryPassphrase, TestDir),
        ?assertMatch({ok, SessionData}, LoadResult2)
    after
        cleanup(TestDir)
    end.

%%%===================================================================
%%% File Security Tests
%%%===================================================================

%% Test file permissions are set correctly
file_permissions_test() ->
    TestDir = setup(),
    try
        SessionData = #{security_test => <<"sensitive_data">>},
        Username = "security_test_user",
        Passphrase = "security_pass",

        %% Save session
        SaveResult = cryptic_lib:save_ratchet_session(Username, SessionData, Passphrase, TestDir),
        ?assertEqual(ok, SaveResult),

        %% Check file permissions (should be 600 - rw-------)
        SessionFile = filename:join(TestDir, Username ++ ".session"),
        {ok, FileInfo} = file:read_file_info(SessionFile),
        Mode = FileInfo#file_info.mode,
        
        %% Extract permission bits (last 9 bits)
        Perms = Mode band 8#777,
        
        %% Should be 600 (owner read/write only)
        ?assertEqual(8#600, Perms)
    after
        cleanup(TestDir)
    end.

%%%===================================================================
%%% Performance and Stress Tests
%%%===================================================================

%% Test handling many sessions
many_sessions_test() ->
    TestDir = setup(),
    try
        Passphrase = "stress_test_passphrase",
        NumSessions = 50,
        
        %% Create and save many sessions
        Sessions = lists:map(fun(I) ->
            Username = "user_" ++ integer_to_list(I),
            SessionData = #{
                id => I,
                key => crypto:strong_rand_bytes(32),
                created => erlang:system_time(second)
            },
            SaveResult = cryptic_lib:save_ratchet_session(Username, SessionData, Passphrase, TestDir),
            ?assertEqual(ok, SaveResult),
            {Username, SessionData}
        end, lists:seq(1, NumSessions)),

        %% Load all sessions
        LoadAllResult = cryptic_lib:load_all_ratchet_sessions(Passphrase, TestDir),
        ?assertMatch({ok, _}, LoadAllResult),
        {ok, AllSessions} = LoadAllResult,

        %% Verify count and content
        ?assertEqual(NumSessions, maps:size(AllSessions)),
        lists:foreach(fun({Username, ExpectedData}) ->
            ?assert(maps:is_key(Username, AllSessions)),
            LoadedData = maps:get(Username, AllSessions),
            ?assertEqual(ExpectedData, LoadedData)
        end, Sessions)
    after
        cleanup(TestDir)
    end.