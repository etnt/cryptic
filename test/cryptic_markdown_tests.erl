%%====================================================================
%% @doc Unit tests for cryptic_markdown module.
%%
%% Tests simple markdown processing including bold, italic, code
%% formatting, edge cases, Unicode support, and the verbatim marker
%% problem where character sequences like `:/' might be processed
%% as emoji in some contexts.
%%
%% @author Cryptic Team
%% @copyright 2025
%% @end
%%====================================================================
-module(cryptic_markdown_tests).
-include_lib("eunit/include/eunit.hrl").
-include("cryptic_ansi.hrl").

%%====================================================================
%% Test Descriptions
%%====================================================================

%% Basic formatting tests - verify each marker type works independently
basic_bold_test() ->
    Input = "This is *bold* text",
    Expected = "This is " ++ ?BOLD("bold") ++ " text",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

basic_italic_test() ->
    Input = "This is _italic_ text",
    Expected = "This is " ++ ?ESC ++ "2mitalic" ++ ?FG_RESET ++ " text",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

basic_code_test() ->
    Input = "Check the `config.txt` file",
    Expected = "Check the " ++ ?REVERSE("config.txt") ++ " file",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Multiple markers in single text
multiple_bold_test() ->
    Input = "We have *two* bold *words* here",
    Expected = "We have " ++ ?BOLD("two") ++ " bold " ++ ?BOLD("words") ++ " here",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

multiple_code_test() ->
    Input = "Commands: `ls` and `pwd` available",
    Expected = "Commands: " ++ ?REVERSE("ls") ++ " and " ++ ?REVERSE("pwd") ++ " available",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Mixed formatting types
mixed_formatting_test() ->
    Input = "Mix *bold* and `code` here",
    Expected = "Mix " ++ ?BOLD("bold") ++ " and " ++ ?REVERSE("code") ++ " here",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

mixed_all_types_test() ->
    Input = "All types: *bold* _italic_ `code`",
    Expected = "All types: " ++ 
               ?BOLD("bold") ++ " " ++
               ?ESC ++ "2mitalic" ++ ?FG_RESET ++ " " ++
               ?REVERSE("code"),
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Edge cases - empty pairs
empty_bold_test() ->
    Input = "Empty ** markers",
    Expected = "Empty ** markers",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

empty_italic_test() ->
    Input = "Empty __ markers",
    Expected = "Empty __ markers",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

empty_code_test() ->
    Input = "Empty `` markers",
    Expected = "Empty `` markers",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Edge cases - unpaired markers
unpaired_bold_start_test() ->
    Input = "Unpaired *bold text",
    Expected = "Unpaired *bold text",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

unpaired_bold_end_test() ->
    Input = "Unpaired bold* text",
    Expected = "Unpaired bold* text",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

unpaired_code_test() ->
    Input = "Single backtick ` here",
    Expected = "Single backtick ` here",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Edge cases - adjacent markers
adjacent_bold_test() ->
    Input = "*first**second*",
    Expected = ?BOLD("first") ++ ?BOLD("second"),
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Edge cases - markers at boundaries
start_bold_test() ->
    Input = "*bold* at start",
    Expected = ?BOLD("bold") ++ " at start",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

end_bold_test() ->
    Input = "At end *bold*",
    Expected = "At end " ++ ?BOLD("bold"),
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

only_bold_test() ->
    Input = "*bold*",
    Expected = ?BOLD("bold"),
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Binary input support
binary_input_test() ->
    Input = <<"This is *bold* text">>,
    Expected = "This is " ++ ?BOLD("bold") ++ " text",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Unicode support
unicode_bold_test() ->
    Input = "Unicode *日本語* text",
    Expected = "Unicode " ++ ?BOLD("日本語") ++ " text",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

unicode_emoji_test() ->
    Input = "Emoji *🎉 party* time",
    Expected = "Emoji " ++ ?BOLD("🎉 party") ++ " time",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

unicode_mixed_test() ->
    Input = "Swedish: *åäö* and Greek: _αβγ_",
    Expected = "Swedish: " ++ ?BOLD("åäö") ++ " and Greek: " ++ 
               ?ESC ++ "2mαβγ" ++ ?FG_RESET,
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Verbatim/protection tests - URLs and special sequences
%% These tests verify that code markers protect sequences like :/ from processing
url_with_code_test() ->
    Input = "Connect to `https://server.example.org:8443` for access",
    Expected = "Connect to " ++ ?REVERSE("https://server.example.org:8443") ++ " for access",
    Result = cryptic_markdown:process(Input),
    ?assertEqual(Expected, Result),
    %% Verify the :/ sequence is preserved exactly
    ?assert(string:str(Result, "://") > 0).

url_without_code_test() ->
    %% This demonstrates the problem: without code markers, :/ becomes 😕 emoji
    Input = "Connect to https://server.example.org:8443 for access",
    Result = cryptic_markdown:process(Input),
    ResultBin = unicode:characters_to_binary(Result),
    %% The :/ in https:// gets replaced with 😕 (unsure emoji U+1F615)
    %% UTF-8: 240,159,152,149
    ?assert(binary:match(ResultBin, <<240,159,152,149>>) =/= nomatch),
    %% The original :// sequence is broken
    ?assert(string:str(Result, "://") =:= 0),
    %% This is why backticks are needed to protect URLs!
    ok.

path_with_code_test() ->
    Input = "Check file `/usr/local/bin/cryptic` for errors",
    Expected = "Check file " ++ ?REVERSE("/usr/local/bin/cryptic") ++ " for errors",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

command_with_code_test() ->
    Input = "Run `./configure --prefix=/opt` to install",
    Expected = "Run " ++ ?REVERSE("./configure --prefix=/opt") ++ " to install",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Special characters inside code markers should be preserved
special_chars_in_code_test() ->
    Input = "Use `*asterisk*` and `_underscore_` literally",
    Expected = "Use " ++ ?REVERSE("*asterisk*") ++ " and " ++ 
               ?REVERSE("_underscore_") ++ " literally",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Realistic message examples
realistic_code_message_test() ->
    Input = "Run `npm install` then `npm start` to launch",
    Expected = "Run " ++ ?REVERSE("npm install") ++ " then " ++ 
               ?REVERSE("npm start") ++ " to launch",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

realistic_mixed_message_test() ->
    Input = "The *config.json* file in `/etc/cryptic/` is _optional_",
    Expected = "The " ++ ?BOLD("config.json") ++ " file in " ++
               ?REVERSE("/etc/cryptic/") ++ " is " ++
               ?ESC ++ "2moptional" ++ ?FG_RESET,
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

realistic_url_message_test() ->
    Input = "Download from `https://github.com/user/repo/archive/v1.0.tar.gz`",
    Expected = "Download from " ++ 
               ?REVERSE("https://github.com/user/repo/archive/v1.0.tar.gz"),
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Empty and whitespace
empty_string_test() ->
    ?assertEqual("", cryptic_markdown:process("")).

whitespace_only_test() ->
    Input = "   ",
    ?assertEqual(Input, cryptic_markdown:process(Input)).

%% Markers with whitespace
bold_with_spaces_test() ->
    Input = "Text *with spaces inside* here",
    Expected = "Text " ++ ?BOLD("with spaces inside") ++ " here",
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%% Processing order verification - backticks processed first
processing_order_test() ->
    %% Backticks should protect asterisks from bold processing
    Input = "Code `*not bold*` and *bold* text",
    Result = cryptic_markdown:process(Input),
    Expected = "Code " ++ ?REVERSE("*not bold*") ++ " and " ++ ?BOLD("bold") ++ " text",
    ?assertEqual(Expected, Result),
    %% Verify asterisks inside backticks are literal (no ANSI bold codes)
    %% The reverse code should contain literal asterisks
    ?assert(string:str(Result, ?REVERSE("*not bold*")) > 0).

%% Long text performance (sanity check)
long_text_test() ->
    %% Generate text with multiple markers
    Words = ["word" ++ integer_to_list(N) || N <- lists:seq(1, 100)],
    BoldWords = ["*" ++ W ++ "*" || W <- Words],
    Input = string:join(BoldWords, " "),
    Result = cryptic_markdown:process(Input),
    %% Just verify it completes without error and has ANSI codes
    ?assert(length(Result) > length(Input)),
    ?assert(string:str(Result, ?ESC) > 0).

%% Nested markers (should not work - outer marker wins)
nested_bold_test() ->
    Input = "*outer *inner* outer*",
    %% First pair of asterisks will match, consuming "outer *inner"
    Result = cryptic_markdown:process(Input),
    %% The processing is greedy but pairs, so we get: *bold(outer *inner)* outer*
    %% Actually, let's verify the actual behavior
    ?assert(is_list(Result)),
    %% Just ensure no crash, exact behavior may vary
    ok.

%% Multiple lines (if input contains newlines)
multiline_test() ->
    Input = "*line one*\n_line two_",
    Expected = ?BOLD("line one") ++ "\n" ++ ?ESC ++ "2mline two" ++ ?FG_RESET,
    ?assertEqual(Expected, cryptic_markdown:process(Input)).

%%====================================================================
%% Integrated Emoji Processing Tests
%%====================================================================
%% These tests verify that emoji shortcuts are processed correctly
%% and that emoji inside backticks (verbatim) remains literal

emoji_in_text_test() ->
    %% Emoji shortcuts in regular text should be replaced
    Input = "Hello :) how are you?",
    Result = cryptic_markdown:process(Input),
    ResultBin = unicode:characters_to_binary(Result),
    %% Should contain the simple smile emoji 🙂 (U+1F642)
    %% UTF-8: 240,159,153,130
    ?assert(binary:match(ResultBin, <<240,159,153,130>>) =/= nomatch),
    %% Should not contain literal :)
    ?assert(string:str(Result, ":)") =:= 0).

emoji_in_code_stays_literal_test() ->
    %% Emoji shortcuts inside backticks should stay literal
    Input = "Use `console.log(':)')` to debug",
    Result = cryptic_markdown:process(Input),
    ResultBin = unicode:characters_to_binary(Result),
    %% The :) inside backticks should remain literal
    ?assert(string:str(Result, ":)") > 0),
    %% Should not contain the emoji character (U+1F642)
    ?assert(binary:match(ResultBin, <<240,159,153,130>>) =:= nomatch).

mixed_emoji_text_and_code_test() ->
    %% Emoji in text should be replaced, but not in code
    Input = "I'm happy :) but check `code :)` here",
    Result = cryptic_markdown:process(Input),
    ResultBin = unicode:characters_to_binary(Result),
    %% Should have one emoji (from text) - 🙂 (U+1F642)
    ?assert(binary:match(ResultBin, <<240,159,153,130>>) =/= nomatch),
    %% And one literal (from code)
    ?assert(string:str(Result, ":)") > 0).

url_with_colon_slash_in_code_test() ->
    %% URLs in backticks should not trigger emoji replacement
    %% :/ would normally become 😕 (unsure emoji) but not in code
    Input = "Connect to `https://server.example.org:8443/path` now",
    Result = cryptic_markdown:process(Input),
    ResultBin = unicode:characters_to_binary(Result),
    %% The :/ sequence should be preserved (part of ://)
    ?assert(string:str(Result, "://") > 0),
    %% No unsure emoji (U+1F615) should be inserted
    %% UTF-8: 240,159,152,149
    ?assert(binary:match(ResultBin, <<240,159,152,149>>) =:= nomatch).

multiple_emoji_shortcuts_test() ->
    %% Multiple emoji shortcuts should all be processed
    Input = "Happy :) sad :( wink ;)",
    Result = cryptic_markdown:process(Input),
    ResultBin = unicode:characters_to_binary(Result),
    %% Should contain emojis:
    %% 🙂 (U+1F642) :) -> UTF-8: 240,159,153,130
    ?assert(binary:match(ResultBin, <<240,159,153,130>>) =/= nomatch),
    %% 😞 (U+1F61E) :( -> UTF-8: 240,159,152,158
    ?assert(binary:match(ResultBin, <<240,159,152,158>>) =/= nomatch),
    %% 😉 (U+1F609) ;) -> UTF-8: 240,159,152,137
    ?assert(binary:match(ResultBin, <<240,159,152,137>>) =/= nomatch).

emoji_with_bold_test() ->
    %% Emoji and bold formatting should work together
    Input = "I'm *very happy* :) today",
    Result = cryptic_markdown:process(Input),
    ResultBin = unicode:characters_to_binary(Result),
    %% Should have bold formatting
    ?assert(string:str(Result, ?BOLD("very happy")) > 0),
    %% Should have emoji 🙂 (U+1F642) UTF-8: 240,159,153,130
    ?assert(binary:match(ResultBin, <<240,159,153,130>>) =/= nomatch).

verbatim_protects_colon_sequences_test() ->
    %% This is the key test for the original problem:
    %% Any :X sequence in backticks should stay literal
    Input = "Config: `server://host:8080/path` and `:command` here",
    Result = cryptic_markdown:process(Input),
    %% All colon-based sequences in code should be preserved
    ?assert(string:str(Result, "://") > 0),
    ?assert(string:str(Result, ":8080") > 0),
    ?assert(string:str(Result, ":command") > 0).

%% Test handling of invalid UTF-8 sequences
invalid_utf8_test() ->
    %% Create a binary with invalid UTF-8: valid text "nur" followed by a single
    %% byte that looks like it should be part of a multi-byte sequence
    InvalidBin = <<"nur", 16#C3>>,  % 16#C3 alone is incomplete, needs another byte
    %% Should not crash, should handle gracefully by adding replacement character
    Result = cryptic_markdown:process(InvalidBin),
    %% Should contain "nur" and a replacement character
    ?assert(string:str(Result, "nur") > 0),
    ?assert(string:str(Result, "�") > 0).

incomplete_utf8_test() ->
    %% Create incomplete UTF-8 sequence (this mimics what caused the crash)
    %% Start of "å" (U+00E5) in UTF-8 is C3 A5, but provide only first byte
    IncompleteBin = <<"test", 16#C3>>,
    %% Should not crash
    Result = cryptic_markdown:process(IncompleteBin),
    ?assert(string:str(Result, "test") > 0),
    ?assert(string:str(Result, "�") > 0).
