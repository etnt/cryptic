%%====================================================================
%% @doc Markdown text formatting processor for Cryptic messages.
%%
%% This module provides simple markdown-style formatting support for
%% text messages in the Cryptic chat application. It converts common
%% markdown syntax into ANSI terminal escape codes for display.
%%
%% == Supported Formatting ==
%%
%% <ul>
%%   <li>`*text*' - Bold text (ANSI bold attribute)</li>
%%   <li>`_text_' - Italic/dim text (ANSI dim/faint attribute)</li>
%%   <li>Backtick text backtick - Code/reverse video (ANSI reverse video)</li>
%% </ul>
%%
%% == Processing Order ==
%%
%% Formatting is applied in the following order to avoid conflicts:
%% <ol>
%%   <li>Backticks (code markers) - Processed first</li>
%%   <li>Asterisks (`*bold*') - Processed second</li>
%%   <li>Underscores (`_italic_') - Processed last</li>
%% </ol>
%%
%% == Examples ==
%%
%% <pre>
%% 1> cryptic_markdown:process("This is *bold* text").
%% "This is \e[1mbold\e[0m text"
%%
%% 2> cryptic_markdown:process("Check the config.txt file").
%% "Check \e[7mconfig.txt\e[0m file"
%%
%% 3> cryptic_markdown:process("I'm _not sure_ about this").
%% "I'm \e[2mnot sure\e[0m about this"
%%
%% 4> cryptic_markdown:process("Mix *bold* and code!").
%% "Mix \e[1mbold\e[0m and \e[7mcode\e[0m!"
%% </pre>
%%
%% == Edge Cases ==
%%
%% <ul>
%%   <li>Empty pairs (e.g., `**', `__', two backticks) are left unchanged</li>
%%   <li>Unpaired markers (e.g., `*text') are left unchanged</li>
%%   <li>Nested markers of the same type are not supported</li>
%%   <li>Different marker types can be mixed in the same text</li>
%% </ul>
%%
%% @author Torbjörn Törnkvist
%% @copyright 2025
%% @end
%%====================================================================
-module(cryptic_markdown).
-export([process/1]).
-include("cryptic_ansi.hrl").

%% @doc Process simple markdown formatting in text.
%%
%% Converts markdown-style formatting markers into ANSI escape codes.
%% Supports bold (`*text*'), italic (`_text_'), and code (backtick markers).
%%
%% The function accepts both binary and string input and always returns
%% a string with embedded ANSI escape sequences.
%%
%% Processing order: backticks are processed first and their content is
%% protected from further processing (true verbatim). Then emoji replacement
%% and markdown formatting (asterisks/underscores) are applied only to text
%% segments, not code segments.
%%
%% Unpaired markers (start without end) are left unchanged in the output.
%%
%% @param Input The text to process (binary or string with Unicode support)
%% @returns A string with markdown converted to ANSI formatting codes
%%
%% @end
-spec process(binary() | string()) -> string().
process(Input) ->
    Str = to_string(Input),
    %% Process backticks first, protecting content from further processing
    %% Returns a list of {text, Text} | {code, Text} segments
    Segments = process_backticks_segments(Str),
    %% Process emoji, asterisks and underscores only on text segments
    FinalSegments = lists:map(fun
        ({code, CodeText}) -> 
            %% Code segments are verbatim - already formatted, no further processing
            %% This means emoji shortcuts like :) inside backticks stay literal
            CodeText;
        ({text, PlainText}) -> 
            %% Text segments get emoji replacement first, then bold/italic processing
            %% Convert to binary for emoji processing
            PlainBin = unicode:characters_to_binary(PlainText),
            EmojiText = cryptic_emoji:replace_all(PlainBin),
            %% Convert back to string for markdown formatting
            EmojiStr = unicode:characters_to_list(EmojiText),
            Text1 = process_asterisks(EmojiStr),
            Text2 = process_underscores(Text1),
            Text2
    end, Segments),
    lists:flatten(FinalSegments).

%% @private
%% @doc Convert input to Unicode string format.
%% Handles both binary (UTF-8 encoded) and string inputs.
to_string(Bin) when is_binary(Bin) ->
    unicode:characters_to_list(Bin);
to_string(Str) when is_list(Str) ->
    Str.

%% @private
%% @doc Process backtick markers and return segments.
%% Returns a list of {text, Text} | {code, FormattedCode} tuples.
%% Code segments are already formatted and should not be processed further.
process_backticks_segments(Str) ->
    process_backticks_segments(Str, [], [], text).

%% State machine for backtick processing:
%% text - accumulating normal text
%% {code, Acc} - accumulating code content
process_backticks_segments([], TextAcc, Segments, text) ->
    %% End of string while in text mode
    case TextAcc of
        [] -> lists:reverse(Segments);
        _ -> lists:reverse([{text, lists:reverse(TextAcc)} | Segments])
    end;
process_backticks_segments([], CodeAcc, Segments, {code, _}) ->
    %% End of string with unpaired backtick - treat as literal
    %% Add the opening backtick and accumulated content as text
    %% CodeAcc is in reverse order, so reverse it first
    UnpairedText = [$` | lists:reverse(CodeAcc)],
    case Segments of
        [] -> 
            [{text, UnpairedText}];
        [{text, PrevText} | Rest] ->
            %% Merge with previous text segment
            lists:reverse([{text, PrevText ++ UnpairedText} | Rest]);
        [{code, _} | _] = AllSegs ->
            %% Previous segment was code, add new text segment
            lists:reverse([{text, UnpairedText} | AllSegs])
    end;
process_backticks_segments([$` | Rest], TextAcc, Segments, text) ->
    %% Start of code section
    NewSegments = case TextAcc of
        [] -> Segments;
        _ -> [{text, lists:reverse(TextAcc)} | Segments]
    end,
    process_backticks_segments(Rest, [], NewSegments, {code, []});
process_backticks_segments([$` | Rest], CodeAcc, Segments, {code, _}) ->
    %% End of code section
    CodeText = lists:reverse(CodeAcc),
    case CodeText of
        [] ->
            %% Empty code pair `` - treat as literal text
            NewSegments = case Segments of
                [{text, PrevText} | RestSegs] ->
                    [{text, PrevText ++ "``"} | RestSegs];
                _ ->
                    [{text, "``"} | Segments]
            end,
            process_backticks_segments(Rest, [], NewSegments, text);
        _ ->
            %% Format code and add as code segment
            FormattedCode = ?REVERSE(CodeText),
            process_backticks_segments(Rest, [], [{code, FormattedCode} | Segments], text)
    end;
process_backticks_segments([Char | Rest], Acc, Segments, Mode) ->
    %% Accumulate character
    process_backticks_segments(Rest, [Char | Acc], Segments, Mode).

%% @private
%% @doc Process asterisk markers (`*bold*') into bold formatting.
%% Converts text enclosed in asterisks to ANSI bold text.
process_asterisks(Str) ->
    process_pattern(Str, $*, fun(Text) -> ?BOLD(Text) end).

%% @private
%% @doc Process underscore markers (`_italic_') into dim/italic formatting.
%% Converts text enclosed in underscores to ANSI dim/faint text.
%% Note: True italic is not widely supported in terminals, so dim is used.
process_underscores(Str) ->
    process_pattern(Str, $_, fun(Text) -> ?ESC ++ "2m" ++ Text ++ ?FG_RESET end).

%% @private
%% @doc Generic pattern processor for paired delimiter markers.
%%
%% Processes a string looking for paired delimiters and applies formatting
%% to the text between them. Handles edge cases like empty pairs and
%% unpaired delimiters (which are left as literal text).
%%
%% @param Str The string to process
%% @param Delimiter The character to use as delimiter (e.g., $*, $_)
%% @param FormatFun Function to apply to delimited text
%% @returns Processed string with formatting applied
process_pattern(Str, Delimiter, FormatFun) ->
    process_pattern(Str, Delimiter, FormatFun, [], false).

%% @private
%% @doc Internal recursive pattern processor with state tracking.
%%
%% State machine that tracks whether we're inside or outside delimiters:
%% <ul>
%%   <li>`false' - Outside any delimiters, in normal text</li>
%%   <li>`{start, Acc}' - Inside delimiters, accumulating text</li>
%% </ul>
%%
%% If we reach end of string with unpaired delimiter, we restore it as literal text.
%%
%% @param Str Remaining string to process
%% @param Delim The delimiter character
%% @param FormatFun Formatting function to apply
%% @param Acc Accumulator for processed output
%% @param InDelim State: false or {start, TextAccumulator}
process_pattern([], _Delim, _FormatFun, Acc, false) ->
    lists:reverse(Acc);
process_pattern([], Delim, _FormatFun, Acc, {start, StartAcc}) ->
    %% Unpaired delimiter at end - restore as literal
    %% StartAcc is reversed, so we need to reverse it and prepend the delimiter
    RestoredText = [Delim | lists:reverse(StartAcc)],
    %% Now append this to our accumulated output (which is also reversed)
    lists:reverse(Acc) ++ RestoredText;
process_pattern([Char | Rest], Delim, FormatFun, Acc, InDelim) when
    Char =:= Delim
->
    case InDelim of
        false ->
            %% Start of delimited section - begin collecting content
            process_pattern(Rest, Delim, FormatFun, Acc, {start, []});
        {start, StartAcc} ->
            %% End of delimited section - extract text and format it
            DelimitedText = lists:reverse(StartAcc),
            case DelimitedText of
                [] ->
                    %% Empty delimiter pair, keep as literal (e.g., **)
                    process_pattern(
                        Rest, Delim, FormatFun, [Delim, Delim | Acc], false
                    );
                _ ->
                    %% Format the text
                    Formatted = FormatFun(DelimitedText),
                    process_pattern(
                        Rest,
                        Delim,
                        FormatFun,
                        lists:reverse(Formatted) ++ Acc,
                        false
                    )
            end
    end;
process_pattern([Char | Rest], Delim, FormatFun, Acc, InDelim) ->
    case InDelim of
        false ->
            %% Normal text
            process_pattern(Rest, Delim, FormatFun, [Char | Acc], false);
        {start, StartAcc} ->
            %% Inside delimited section, keep collecting
            process_pattern(
                Rest, Delim, FormatFun, Acc, {start, [Char | StartAcc]}
            )
    end.
