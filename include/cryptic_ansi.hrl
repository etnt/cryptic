%%====================================================================
%% ANSI Escape Sequence Macros for Erlang Terminal Applications
%%====================================================================
%% Author: Your Name
%% License: Apache 2.0
%% Description:
%%   A set of convenient macros for controlling terminal output using
%%   ANSI escape sequences.  Includes cursor movement, screen control,
%%   color styling, alternate screen buffer support, and text effects.
%%====================================================================

%%------------------------------
%% Base escape prefix
%%------------------------------
-define(ESC, "\e[").

%%------------------------------
%% Cursor movement
%%------------------------------
-define(MVTO_ROW_COL(R, C), ?ESC ++ integer_to_list(R) ++ ";" ++ integer_to_list(C) ++ "H").
-define(CURSOR_UP(N),       ?ESC ++ integer_to_list(N) ++ "A").
-define(CURSOR_DOWN(N),     ?ESC ++ integer_to_list(N) ++ "B").
-define(CURSOR_RIGHT(N),    ?ESC ++ integer_to_list(N) ++ "C").
-define(CURSOR_LEFT(N),     ?ESC ++ integer_to_list(N) ++ "D").

%%------------------------------
%% Screen control
%%------------------------------
-define(CLEAR_SCREEN,       ?ESC ++ "2J").
-define(CLEAR_LINE,         ?ESC ++ "2K").
-define(SCROLL_UP(N),       ?ESC ++ integer_to_list(N) ++ "S").
-define(SCROLL_DOWN(N),     ?ESC ++ integer_to_list(N) ++ "T").

%%------------------------------
%% Alternate screen buffer
%%------------------------------
-define(ALT_SCREEN_ON,      ?ESC ++ "?1049h").
-define(ALT_SCREEN_OFF,     ?ESC ++ "?1049l").

%%------------------------------
%% Cursor visibility
%%------------------------------
-define(HIDE_CURSOR,        ?ESC ++ "?25l").
-define(SHOW_CURSOR,        ?ESC ++ "?25h").

%%------------------------------
%% Color codes
%%------------------------------
-define(FG_BLACK_CODE,   "30").
-define(FG_RED_CODE,     "31").
-define(FG_GREEN_CODE,   "32").
-define(FG_YELLOW_CODE,  "33").
-define(FG_BLUE_CODE,    "34").
-define(FG_MAGENTA_CODE, "35").
-define(FG_CYAN_CODE,    "36").
-define(FG_WHITE_CODE,   "37").

-define(BG_BLACK_CODE,   "40").
-define(BG_RED_CODE,     "41").
-define(BG_GREEN_CODE,   "42").
-define(BG_YELLOW_CODE,  "43").
-define(BG_BLUE_CODE,    "44").
-define(BG_MAGENTA_CODE, "45").
-define(BG_CYAN_CODE,    "46").
-define(BG_WHITE_CODE,   "47").

-define(FG_RESET_CODE,   "0m").
-define(FG_RESET, ?ESC ++ ?FG_RESET_CODE).

%%------------------------------
%% Foreground-only color wrappers
%%------------------------------
-define(FG_BLACK(S),   ?ESC ++ ?FG_BLACK_CODE   ++ "m" ++ S ++ ?FG_RESET).
-define(FG_RED(S),     ?ESC ++ ?FG_RED_CODE     ++ "m" ++ S ++ ?FG_RESET).
-define(FG_GREEN(S),   ?ESC ++ ?FG_GREEN_CODE   ++ "m" ++ S ++ ?FG_RESET).
-define(FG_YELLOW(S),  ?ESC ++ ?FG_YELLOW_CODE  ++ "m" ++ S ++ ?FG_RESET).
-define(FG_BLUE(S),    ?ESC ++ ?FG_BLUE_CODE    ++ "m" ++ S ++ ?FG_RESET).
-define(FG_MAGENTA(S), ?ESC ++ ?FG_MAGENTA_CODE ++ "m" ++ S ++ ?FG_RESET).
-define(FG_CYAN(S),    ?ESC ++ ?FG_CYAN_CODE    ++ "m" ++ S ++ ?FG_RESET).
-define(FG_WHITE(S),   ?ESC ++ ?FG_WHITE_CODE   ++ "m" ++ S ++ ?FG_RESET).

%%------------------------------
%% Background-only color wrappers
%%------------------------------
-define(BG_BLACK(S),   ?ESC ++ ?BG_BLACK_CODE   ++ "m" ++ S ++ ?FG_RESET).
-define(BG_RED(S),     ?ESC ++ ?BG_RED_CODE     ++ "m" ++ S ++ ?FG_RESET).
-define(BG_GREEN(S),   ?ESC ++ ?BG_GREEN_CODE   ++ "m" ++ S ++ ?FG_RESET).
-define(BG_YELLOW(S),  ?ESC ++ ?BG_YELLOW_CODE  ++ "m" ++ S ++ ?FG_RESET).
-define(BG_BLUE(S),    ?ESC ++ ?BG_BLUE_CODE    ++ "m" ++ S ++ ?FG_RESET).
-define(BG_MAGENTA(S), ?ESC ++ ?BG_MAGENTA_CODE ++ "m" ++ S ++ ?FG_RESET).
-define(BG_CYAN(S),    ?ESC ++ ?BG_CYAN_CODE    ++ "m" ++ S ++ ?FG_RESET).
-define(BG_WHITE(S),   ?ESC ++ ?BG_WHITE_CODE   ++ "m" ++ S ++ ?FG_RESET).

%%------------------------------
%% Foreground + Background combined
%%------------------------------
-define(FG_RED_BG_WHITE(S),     ?ESC ++ ?FG_RED_CODE     ++ ";" ++ ?BG_WHITE_CODE   ++ "m" ++ S ++ ?FG_RESET).
-define(FG_GREEN_BG_WHITE(S),   ?ESC ++ ?FG_GREEN_CODE   ++ ";" ++ ?BG_WHITE_CODE   ++ "m" ++ S ++ ?FG_RESET).
-define(FG_BLUE_BG_WHITE(S),    ?ESC ++ ?FG_BLUE_CODE    ++ ";" ++ ?BG_WHITE_CODE   ++ "m" ++ S ++ ?FG_RESET).
-define(FG_YELLOW_BG_BLACK(S),  ?ESC ++ ?FG_YELLOW_CODE  ++ ";" ++ ?BG_BLACK_CODE   ++ "m" ++ S ++ ?FG_RESET).
-define(FG_BLACK_BG_YELLOW(S),  ?ESC ++ ?FG_BLACK_CODE   ++ ";" ++ ?BG_YELLOW_CODE  ++ "m" ++ S ++ ?FG_RESET).
-define(FG_WHITE_BG_RED(S),     ?ESC ++ ?FG_WHITE_CODE   ++ ";" ++ ?BG_RED_CODE     ++ "m" ++ S ++ ?FG_RESET).
-define(FG_WHITE_BG_BLUE(S),    ?ESC ++ ?FG_WHITE_CODE   ++ ";" ++ ?BG_BLUE_CODE    ++ "m" ++ S ++ ?FG_RESET).
-define(FG_BLACK_BG_GREEN(S),   ?ESC ++ ?FG_BLACK_CODE   ++ ";" ++ ?BG_GREEN_CODE   ++ "m" ++ S ++ ?FG_RESET).
-define(FG_BLACK_BG_CYAN(S),    ?ESC ++ ?FG_BLACK_CODE   ++ ";" ++ ?BG_CYAN_CODE    ++ "m" ++ S ++ ?FG_RESET).

%%------------------------------
%% Text effects
%%------------------------------
-define(BOLD(S),      ?ESC ++ "1m" ++ S ++ ?FG_RESET).
-define(UNDERLINE(S), ?ESC ++ "4m" ++ S ++ ?FG_RESET).
-define(REVERSE(S),   ?ESC ++ "7m" ++ S ++ ?FG_RESET).
