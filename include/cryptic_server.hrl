-ifndef(_CRYPTIC_SERVER_HRL).
-define(_CRYPTIC_SERVER_HRL, true).

%% ETS tables
-define(CONNECTION_TABLE, cryptic_connections).
-define(PREKEY_TABLE, cryptic_prekeys).
-define(MESSAGE_TABLE, cryptic_messages).
-define(USER_TABLE, cryptic_users).


%% We have our own versions of these log macros in order
%% to not be dependant on including cryptic.hrl.
-define(log_event(Level, Msg), cryptic_event_manager:notify(Level, Msg)).

-define(error(Fs, As), ?log_event(error, {Fs, As})).
-define(warning(Fs, As), ?log_event(warning, {Fs, As})).
-define(info(Fs, As), ?log_event(info, {Fs, As})).
-define(debug(Fs, As), ?log_event(debug, {Fs, As})).

-define(msg_in(Fs, As), ?log_event(in, {Fs, As})).
-define(msg_out(Fs, As), ?log_event(out, {Fs, As})).

-endif.
