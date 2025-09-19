-ifndef(_CRYPTIC_HRL).
-define(_CRYPTIC_HRL, true).

-define(log_event(Level, Msg), cryptic_event_manager:notify(Level, Msg)).

-define(error(Fs, As), ?log_event(error, {Fs, As})).
-define(warning(Fs, As), ?log_event(warning, {Fs, As})).
-define(info(Fs, As), ?log_event(info, {Fs, As})).

%% Return: {FmtStr, Args} as event handler is expecting it.
-define(dbg_str(Mod, Line, Fs, As),
    {"~s ~p(~p): " ++ Fs, [
        calendar:system_time_to_rfc3339(
            erlang:system_time(millisecond),
            [
                {unit, millisecond},
                {time_designator, $\s}
            ]
        ),
        Mod,
        Line
        | As
    ]}
).

-define(dbg(Fs, As), ?log_event(debug, ?dbg_str(?MODULE, ?LINE, Fs, As))).

-define(msg_in(Fs, As), ?log_event(in, {Fs, As})).
-define(msg_out(Fs, As), ?log_event(out, {Fs, As})).

-endif.
