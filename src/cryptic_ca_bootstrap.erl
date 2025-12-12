%% @doc CA Bootstrap - Load GPG registrations from filesystem
%%
%% This module handles bootstrapping GPG fingerprints for users with existing
%% client certificates but no GPG info in their certificates.
%%
%% Users place files in priv/ca/bootstrap/ with the format:
%%   &lt;filename>.gpg
%%
%% Each file contains the armored GPG public key. The server loads these
%% on startup and associates the GPG fingerprint with the certificate fingerprint.
%%
%% @author Cryptic Development Team
%% @since November 2025
-module(cryptic_ca_bootstrap).

-include("cryptic_server.hrl").
-include("../include/cryptic_ca.hrl").

-export([
    load_bootstrap_registrations/1,
    process_bootstrap_file/2,
    get_bootstrap_dir/0
]).

%% @doc Get the bootstrap directory path
-spec get_bootstrap_dir() -> file:filename().
get_bootstrap_dir() ->
    cryptic_lib:get_server_file(
        "CRYPTIC_BOOTSTRAP_DIR",
        bootstrap_dir
    ).

%% @doc Load all GPG bootstrap registrations from filesystem
%%
%% Scans the bootstrap directory for .gpg files and registers each
%% GPG public key with the CA database.
%%
%% File naming convention: &lt;any-identifier>.gpg
%% File contents: Armored GPG public key
%%
%% @param DbRef Database connection reference
%% @returns {ok, RegisteredCount} | {error, Reason}
-spec load_bootstrap_registrations(term()) -> {ok, non_neg_integer()} | {error, term()}.
load_bootstrap_registrations(DbRef) ->
    BootstrapDir = get_bootstrap_dir(),

    ?info("Loading GPG bootstrap registrations from ~s", [BootstrapDir]),

    %% Ensure directory exists
    case filelib:ensure_dir(filename:join(BootstrapDir, "dummy")) of
        ok ->
            case file:list_dir(BootstrapDir) of
                {ok, Files} ->
                    GpgFiles = [F || F <- Files, filename:extension(F) =:= ".gpg"],
                    ?info("Found ~p GPG bootstrap files", [length(GpgFiles)]),
                    process_bootstrap_files(DbRef, BootstrapDir, GpgFiles, 0);
                {error, enoent} ->
                    ?info("Bootstrap directory does not exist, skipping", []),
                    {ok, 0};
                {error, Reason} = Error ->
                    ?error("Failed to list bootstrap directory: ~p", [Reason]),
                    Error
            end;
        {error, Reason} = Error ->
            ?error("Failed to create bootstrap directory: ~p", [Reason]),
            Error
    end.

%% @private Process all bootstrap files
-spec process_bootstrap_files(term(), file:filename(), [file:filename()], non_neg_integer()) ->
    {ok, non_neg_integer()} | {error, term()}.
process_bootstrap_files(_DbRef, _BootstrapDir, [], Count) ->
    case Count of
        0 ->
            ?info("Bootstrap complete: no new GPG keys registered (all existing keys were already registered)", []);
        _ ->
            ?info("Successfully registered ~p new GPG key(s) from bootstrap", [Count])
    end,
    {ok, Count};
process_bootstrap_files(DbRef, BootstrapDir, [File | Rest], Count) ->
    FilePath = filename:join(BootstrapDir, File),
    case process_bootstrap_file(DbRef, FilePath) of
        {ok, registered} ->
            process_bootstrap_files(DbRef, BootstrapDir, Rest, Count + 1);
        {ok, already_registered} ->
            ?info("GPG key from ~s already registered, skipping", [File]),
            process_bootstrap_files(DbRef, BootstrapDir, Rest, Count);
        {error, Reason} ->
            ?warning("Failed to process bootstrap file ~s: ~p", [File, Reason]),
            %% Continue processing other files
            process_bootstrap_files(DbRef, BootstrapDir, Rest, Count)
    end.

%% @doc Process a single bootstrap file
%%
%% Reads the GPG public key from the file, computes the fingerprint,
%% and registers it in the database.
%%
%% @param DbRef Database connection reference
%% @param FilePath Path to the .gpg file
%% @returns {ok, registered} | {ok, already_registered} | {error, Reason}
-spec process_bootstrap_file(term(), file:filename()) ->
    {ok, registered} | {ok, already_registered} | {error, term()}.
process_bootstrap_file(DbRef, FilePath) ->
    case file:read_file(FilePath) of
        {ok, GpgPubArmored} ->
            %% Compute GPG fingerprint
            case cryptic_ca_gpg:compute_fingerprint(GpgPubArmored) of
                {ok, GpgFp} ->
                    %% Check if already registered
                    case cryptic_ca_store:get_gpg_identity(DbRef, GpgFp) of
                        {ok, _Identity} ->
                            ?debug("GPG fingerprint ~s already registered", [GpgFp]),
                            {ok, already_registered};
                        {error, not_found} ->
                            %% Register the GPG identity
                            register_gpg_identity(DbRef, GpgFp, GpgPubArmored, FilePath);
                        {error, Reason} = Error ->
                            ?error("Failed to check GPG identity ~s: ~p", [GpgFp, Reason]),
                            Error
                    end;
                {error, Reason} = Error ->
                    ?error("Failed to compute fingerprint for ~s: ~p", [FilePath, Reason]),
                    Error
            end;
        {error, Reason} = Error ->
            ?error("Failed to read bootstrap file ~s: ~p", [FilePath, Reason]),
            Error
    end.

%% @private Register GPG identity in database
-spec register_gpg_identity(term(), binary(), binary(), file:filename()) ->
    {ok, registered} | {error, term()}.
register_gpg_identity(DbRef, GpgFp, GpgPubArmored, FilePath) ->
    %% Bootstrap keys are trusted since they require filesystem access
    %% No additional verification needed
    Identity = #gpg_identity{
        gpg_fp = GpgFp,
        gpg_pub_armor = GpgPubArmored,
        status = <<"active">>,
        registered_by = undefined,  % Bootstrap user has no admin
        registered_at = erlang:system_time(second),
        last_seen = erlang:system_time(second),
        metadata = iolist_to_binary(["{\"source\":\"bootstrap\",\"file\":\"", 
                                     filename:basename(FilePath), "\"}"])
    },

    case cryptic_ca_store:insert_gpg_identity(DbRef, Identity) of
        ok ->
            ?info("Registered GPG identity from bootstrap: ~s (from ~s)", 
                  [GpgFp, filename:basename(FilePath)]),

            %% Log the registration
            AuditLog = #audit_log{
                timestamp = erlang:system_time(second),
                event_type = <<"gpg_bootstrap_registered">>,
                gpg_fp = GpgFp,
                invite_id = undefined,
                details = iolist_to_binary(["Loaded from ", filename:basename(FilePath)]),
                ip_address = <<"filesystem">>
            },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),

            {ok, registered};
        {error, Reason} = Error ->
            ?error("Failed to insert GPG identity ~s: ~p", [GpgFp, Reason]),
            Error
    end.
