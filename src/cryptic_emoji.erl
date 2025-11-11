-module(cryptic_emoji).
-export([replace_all/1]).
-include("cryptic_emoji.hrl").

%% Replace common ASCII emoticons in a UTF-8 binary.
-spec replace_all(binary() | string()) -> binary().
replace_all(Input) ->
    Bin = to_binary(Input),
    %% Order matters: handle longer/ambiguous forms first
    lists:foldl(
        fun({ASCII, EMOJI}, B) ->
            replace(B, ASCII, EMOJI)
        end,
        Bin,
        emojis()
    ).

emojis() ->
    [
        {<<"(y)" / utf8>>, ?EMOJI_THUMBS_UP},
        {<<":-)"/utf8>>, ?EMOJI_SMILE},
        {<<":)"/utf8>>, ?EMOJI_SIMPLE_SMILE},
        {<<":-D"/utf8>>, ?EMOJI_GRIN},
        {<<":D"/utf8>>, ?EMOJI_GRIN},
        {<<";-)"/utf8>>, ?EMOJI_WINK},
        {<<";)"/utf8>>, ?EMOJI_WINK},
        {<<":-P"/utf8>>, ?EMOJI_TONGUE},
        {<<":P"/utf8>>, ?EMOJI_TONGUE},
        {<<":-("/utf8>>, ?EMOJI_SAD},
        {<<":("/utf8>>, ?EMOJI_SAD},
        {<<":/"/utf8>>, ?EMOJI_UNSURE},
        {<<":o"/utf8>>, ?EMOJI_SURPRISED},
        {<<":O"/utf8>>, ?EMOJI_SURPRISED},
        {<<":*"/utf8>>, ?EMOJI_KISS},
        {<<":|"/utf8>>, ?EMOJI_NEUTRAL},
        {unicode:characters_to_binary("https😕"), "https:/"}
    ].

to_binary(Bin) when is_binary(Bin) -> Bin;
to_binary(Str) when is_list(Str) -> unicode:characters_to_binary(Str).

%% replace/3: simple global binary replace (non-overlapping)
-spec replace(binary(), binary(), string()) -> binary().
replace(Bin, Pattern, ReplacementUnicode) ->
    %% ReplacementUnicode is already a Unicode string (list of codepoints)
    %% Convert it to UTF-8 binary - handle potential errors
    Replacement =
        case unicode:characters_to_binary(ReplacementUnicode) of
            Result when is_binary(Result) -> Result;
            _ ->
                %% Fallback: assume it's already a string, convert each char
                unicode:characters_to_binary(ReplacementUnicode, unicode)
        end,
    do_replace(Bin, Pattern, Replacement, <<>>).

do_replace(<<>>, _Pattern, _Replacement, Acc) ->
    Acc;
do_replace(Bin, Pattern, Replacement, Acc) ->
    case binary:match(Bin, Pattern) of
        {Pos, Len} ->
            <<Head:Pos/binary, _Match:Len/binary, Rest/binary>> = Bin,
            do_replace(
                Rest,
                Pattern,
                Replacement,
                <<Acc/binary, Head/binary, Replacement/binary>>
            );
        nomatch ->
            <<Acc/binary, Bin/binary>>
    end.
