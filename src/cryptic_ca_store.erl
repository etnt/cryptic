%% @doc Cryptic CA Store - SQLite Storage for GPG Registry
%%
%% This module provides persistent storage for the GPG-based Certificate
%% Authority system, GPG identities, and audit logs.
%%
%% == Features ==
%% <ul>
%%   <li>SQLite-based persistent storage for CA data</li>
%%   <li>Optional encryption for sensitive data (GPG keys)</li>
%%   <li>Transaction support for atomic operations</li>
%%   <li>Indexed lookups for fingerprints</li>
%% </ul>
%%
%% == Database Schema ==
%% See init/1 for full schema definition
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since October 2025
-module(cryptic_ca_store).

-include("cryptic_ca.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    init/1,
    close/1,
    open_db/1,
    create_tables/1,

    %% CA certificate operations
    load_ca_cert/0,
    load_ca_key/0,
    init_ca_environment/0,

    %% GPG identity operations
    insert_gpg_identity/2,
    get_gpg_identity/2,
    update_last_seen/2,
    list_gpg_identities/1,
    register_user/5,
    update_user_status/3,

    %% Certificate operations
    insert_certificate/2,
    get_certificate/2,
    list_certificates_by_user/2,
    update_certificate_status/3,
    revoke_certificate/4,
    list_expiring_certificates/2,
    cleanup_expired_certificates/1,

    %% Audit operations
    insert_audit_log/2,
    get_audit_logs/3,

    %% Database inspection (for debugging)
    list_tables/1,
    describe_table/2,
    inspect_db/0
]).

-include("cryptic_server.hrl").

%% esqlite3 connection reference
-type db_ref() :: tuple().
-type gpg_fingerprint() :: binary().
-type unix_timestamp() :: non_neg_integer().

%%====================================================================
%% API
%%====================================================================

%% @doc Initialize database connection and create tables if needed
-spec init(file:filename()) -> {ok, db_ref()} | {error, term()}.
init(DbFile) ->
    ?info("Initializing CA storage at ~s", [DbFile]),

    %% Ensure directory exists
    DbDir = filename:dirname(DbFile),
    case filelib:ensure_dir(filename:join(DbDir, "dummy")) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} ->
            ?error("Failed to create DB directory ~s: ~p", [DbDir, Reason]),
            exit({error, {dir_creation_failed, Reason}})
    end,

    %% Open database connection
    case esqlite3:open(DbFile) of
        {ok, Conn} ->
            %% Set pragmas for better performance and safety
            ok = esqlite3:exec(Conn, "PRAGMA journal_mode=WAL;"),
            ok = esqlite3:exec(Conn, "PRAGMA synchronous=NORMAL;"),
            ok = esqlite3:exec(Conn, "PRAGMA foreign_keys=ON;"),

            %% Create tables
            case create_tables(Conn) of
                ok ->
                    ?info("CA storage initialized successfully", []),
                    {ok, Conn};
                {error, CreateReason} = CreateError ->
                    ?error("Failed to create tables: ~p", [CreateReason]),
                    esqlite3:close(Conn),
                    CreateError
            end;
        {error, OpenReason} = OpenError ->
            ?error("Failed to open database ~s: ~p", [DbFile, OpenReason]),
            OpenError
    end.

%% @doc Close database connection
-spec close(db_ref()) -> ok.
close(Conn) ->
    esqlite3:close(Conn).

%% @doc Open database connection (for use by other modules)
-spec open_db(file:filename()) -> {ok, db_ref()} | {error, term()}.
open_db(DbFile) ->
    case esqlite3:open(DbFile) of
        {ok, Conn} ->
            ok = esqlite3:exec(Conn, "PRAGMA journal_mode=WAL;"),
            ok = esqlite3:exec(Conn, "PRAGMA synchronous=NORMAL;"),
            ok = esqlite3:exec(Conn, "PRAGMA foreign_keys=ON;"),
            {ok, Conn};
        Error ->
            Error
    end.

%%====================================================================
%% CA Certificate Operations
%%====================================================================

%% @doc Initialize CA environment by loading certificates and keys
%%
%% Reads CA certificate and private key from files specified in
%% application configuration, parses them, and stores in application
%% environment for use by certificate issuance.
%%
%% This should be called during application startup.
%%
%% Configuration:
%% ```
%% {cryptic_ca, [
%%     {ca_cert_file, "CA/certs/ca.crt"},
%%     {ca_key_file, "CA/private/ca.key"}
%% ]}.
%% '''
-spec init_ca_environment() -> ok | {error, term()}.
init_ca_environment() ->
    try
        {ok, CACert} = load_ca_cert(),
        {ok, CAKey} = load_ca_key(),
        
        application:set_env(cryptic, ca_cert, CACert),
        application:set_env(cryptic, ca_key, CAKey),
        
        ?info("CA environment initialized successfully", []),
        ok
    catch
        ErrorType:ErrorReason:Stack ->
            ?error("Failed to initialize CA environment: ~p:~p~n~p",
                   [ErrorType, ErrorReason, Stack]),
            {error, {ca_init_failed, ErrorReason}}
    end.

%% @doc Load CA certificate from PEM file
%%
%% Reads and parses the CA root certificate. Returns an OTPCertificate
%% record that can be used for certificate operations.
-spec load_ca_cert() -> {ok, #'OTPCertificate'{}} | {error, term()}.
load_ca_cert() ->
    case application:get_env(cryptic, ca_cert_file) of
        {ok, CertFile} ->
            case file:read_file(CertFile) of
                {ok, CertPEM} ->
                    try
                        [{_, CertDER, _}] = public_key:pem_decode(CertPEM),
                        Cert = public_key:pkix_decode_cert(CertDER, otp),
                        {ok, Cert}
                    catch
                        _:Reason ->
                            ?error("Failed to parse CA certificate ~s: ~p",
                                   [CertFile, Reason]),
                            {error, {cert_parse_failed, Reason}}
                    end;
                {error, Reason} = Error ->
                    ?error("Failed to read CA certificate ~s: ~p",
                           [CertFile, Reason]),
                    Error
            end;
        undefined ->
            {error, ca_cert_file_not_configured}
    end.

%% @doc Load CA private key from PEM file
%%
%% Reads and parses the CA private key. Returns an ECPrivateKey
%% record for ECDSA keys or RSAPrivateKey for RSA keys.
%%
%% The key must match the algorithm used in the CA certificate.
-spec load_ca_key() -> {ok, tuple()} | {error, term()}.
load_ca_key() ->
    case application:get_env(cryptic, ca_key_file) of
        {ok, KeyFile} ->
            case file:read_file(KeyFile) of
                {ok, KeyPEM} ->
                    try
                        [KeyEntry | _] = public_key:pem_decode(KeyPEM),
                        Key = public_key:pem_entry_decode(KeyEntry),
                        {ok, Key}
                    catch
                        _:Reason ->
                            ?error("Failed to parse CA private key ~s: ~p",
                                   [KeyFile, Reason]),
                            {error, {key_parse_failed, Reason}}
                    end;
                {error, Reason} = Error ->
                    ?error("Failed to read CA private key ~s: ~p",
                           [KeyFile, Reason]),
                    Error
            end;
        undefined ->
            {error, ca_key_file_not_configured}
    end.

%% @doc Create database tables
-spec create_tables(db_ref()) -> ok | {error, term()}.
create_tables(Conn) ->
    
    GpgIdentitiesTable =
        <<
            "\n"
            "        CREATE TABLE IF NOT EXISTS gpg_identities (\n"
            "            gpg_fp TEXT PRIMARY KEY,\n"
            "            gpg_pub_armor TEXT NOT NULL,\n"
            "            status TEXT NOT NULL CHECK(status IN (\n"
            "                'active',\n"
            "                'suspended',\n"
            "                'revoked'\n"
            "            )),\n"
            "            registered_by TEXT,\n"
            "            registered_at INTEGER NOT NULL,\n"
            "            last_seen INTEGER NOT NULL,\n"
            "            metadata TEXT\n"
            "        )\n"
            "    "
        >>,

    AuditLogTable =
        <<
            "\n"
            "        CREATE TABLE IF NOT EXISTS audit_log (\n"
            "            id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            "            timestamp INTEGER NOT NULL,\n"
            "            event_type TEXT NOT NULL,\n"
            "            gpg_fp TEXT,\n"
            "            details TEXT,\n"
            "            ip_address TEXT\n"
            "        )\n"
            "    "
        >>,

    CertificatesTable =
        <<
            "\n"
            "        CREATE TABLE IF NOT EXISTS certificates (\n"
            "            serial TEXT PRIMARY KEY,\n"
            "            gpg_fp TEXT NOT NULL,\n"
            "            issued_at INTEGER NOT NULL,\n"
            "            expires_at INTEGER NOT NULL,\n"
            "            status TEXT NOT NULL DEFAULT 'active',\n"
            "            revoked_at INTEGER,\n"
            "            revoked_by TEXT,\n"
            "            revoked_reason TEXT,\n"
            "            cert_pem TEXT NOT NULL\n"
            "        )\n"
            "    "
        >>,

    %% Create indexes
    Indexes = [
        <<"CREATE INDEX IF NOT EXISTS idx_gpg_status ON gpg_identities(status)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_gpg_registered_by ON gpg_identities(registered_by)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_certs_gpg_fp ON certificates(gpg_fp)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_certs_expires ON certificates(expires_at)">>,
        <<"CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates(status)">>
    ],

    try
        ok = esqlite3:exec(Conn, GpgIdentitiesTable),
        ok = esqlite3:exec(Conn, AuditLogTable),
        ok = esqlite3:exec(Conn, CertificatesTable),
        lists:foreach(fun(Idx) -> ok = esqlite3:exec(Conn, Idx) end, Indexes),
        ok
    catch
        ErrorType:ErrorReason:_Stack ->
            ?error("Failed to create tables: ~p:~p", [
                ErrorType, ErrorReason
            ]),
            {error, {table_creation_failed, ErrorReason}}
    end.

%%====================================================================
%% GPG Identity Operations
%%====================================================================

%% @doc Insert a new GPG identity into the registry.
%%
%% Registers a new user's GPG key in the system. The status field indicates
%% how the identity was verified:
%% <ul>
%%   <li>`verified_bootstrap' - Manually added by admin</li>
%%   <li>`pending' - Awaiting verification</li>
%%   <li>`revoked' - Identity has been revoked</li>
%% </ul>
%%
%% == Example ==
%% ```
%% Identity = #gpg_identity{
%%     gpg_fp = <<"ABCD1234...">>,
%%     gpg_pub_armor = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%     status = <<"verified_bootstrap">>,
%%     registered_at = erlang:system_time(second),
%%     last_seen = erlang:system_time(second)
%% },
%% ok = cryptic_ca_store:insert_gpg_identity(Conn, Identity).
%% '''
%%
%% @param Conn Database connection reference
%% @param Identity The GPG identity record to insert
%% @returns `ok' on success, `{error, Reason}' on failure (e.g., duplicate fingerprint, FK violation)
-spec insert_gpg_identity(db_ref(), #gpg_identity{}) -> ok | {error, term()}.
insert_gpg_identity(Conn, #gpg_identity{} = Identity) ->
    SQL =
        <<
            "INSERT INTO gpg_identities \n"
            "             (gpg_fp, gpg_pub_armor, status, registered_by, registered_at, last_seen, metadata) \n"
            "             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        >>,
    Params = [
        Identity#gpg_identity.gpg_fp,
        Identity#gpg_identity.gpg_pub_armor,
        Identity#gpg_identity.status,
        Identity#gpg_identity.registered_by,
        Identity#gpg_identity.registered_at,
        Identity#gpg_identity.last_seen,
        Identity#gpg_identity.metadata
    ],

    case esqlite3:q(Conn, SQL, Params) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to insert GPG identity ~s: ~p", [
                Identity#gpg_identity.gpg_fp, Reason
            ]),
            Error
    end.

%% @doc Retrieve a GPG identity by fingerprint.
%%
%% Fetches complete identity information including the public key armor,
%% verification status, and registration metadata.
%%
%% == Example ==
%% ```
%% case cryptic_ca_store:get_gpg_identity(Conn, <<"ABCD1234...">>) of
%%     {ok, Identity} ->
%%         io:format("Status: ~s~n", [Identity#gpg_identity.status]);
%%     {error, not_found} ->
%%         io:format("Unknown fingerprint~n")
%% end.
%% '''
%%
%% @param Conn Database connection reference
%% @param GpgFp The GPG fingerprint to look up
%% @returns `{ok, Identity}' if found, `{error, not_found}' if not found, or `{error, Reason}' on database error
-spec get_gpg_identity(db_ref(), gpg_fingerprint()) ->
    {ok, #gpg_identity{}} | {error, not_found} | {error, term()}.
get_gpg_identity(Conn, GpgFp) ->
    SQL =
        <<
            "SELECT gpg_fp, gpg_pub_armor, status, registered_by, registered_at, last_seen, metadata \n"
            "             FROM gpg_identities WHERE gpg_fp = ?1"
        >>,

    case esqlite3:q(Conn, SQL, [GpgFp]) of
        [[Fp, PubKey, Status, RegisteredBy, RegAt, LastSeen, Metadata]] ->
            {ok, #gpg_identity{
                gpg_fp = Fp,
                gpg_pub_armor = PubKey,
                status = Status,
                registered_by = RegisteredBy,
                registered_at = RegAt,
                last_seen = LastSeen,
                metadata = Metadata
            }};
        Result when Result =:= [] orelse Result =:= ok ->
            {error, not_found};
        {error, Reason} = Error ->
            ?error("Failed to get GPG identity ~s: ~p", [GpgFp, Reason]),
            Error
    end.

%% @doc Update the last seen timestamp for a GPG identity.
%%
%% Records the current time as the last activity time for this identity.
%% Useful for tracking active users and detecting inactive accounts.
%%
%% The timestamp is automatically set to `erlang:system_time(second)'.
%%
%% == Example ==
%% ```
%% %% Called when user authenticates or performs an action
%% ok = cryptic_ca_store:update_last_seen(Conn, UserFingerprint).
%% '''
%%
%% @param Conn Database connection reference
%% @param GpgFp The GPG fingerprint to update
%% @returns `ok' on success (even if fingerprint doesn't exist), `{error, Reason}' on database error
-spec update_last_seen(db_ref(), gpg_fingerprint()) -> ok | {error, term()}.
update_last_seen(Conn, GpgFp) ->
    Now = erlang:system_time(second),
    SQL = <<"UPDATE gpg_identities SET last_seen = ?1 WHERE gpg_fp = ?2">>,
    case esqlite3:q(Conn, SQL, [Now, GpgFp]) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to update last_seen for ~s: ~p", [GpgFp, Reason]),
            Error
    end.

%% @doc List all GPG identities in the registry.
%%
%% Returns all registered identities in reverse chronological order
%% (most recently registered first). Includes identities in all states:
%% verified, pending, and revoked.
%%
%% For filtered lists (e.g., only verified identities), use the result
%% and filter based on the status field.
%%
%% == Example ==
%% ```
%% {ok, Identities} = cryptic_ca_store:list_gpg_identities(Conn),
%% Verified = lists:filter(
%%     fun(I) ->
%%         lists:member(I#gpg_identity.status,
%%                      [<<"verified_boottraps">>, <<"verified_bootstrap">>])
%%     end,
%%     Identities
%% ).
%% '''
%%
%% @param Conn Database connection reference
%% @returns `{ok, [Identity]}' with list of all identities (may be empty), or `{error, Reason}' on database error
-spec list_gpg_identities(db_ref()) ->
    {ok, [#gpg_identity{}]} | {error, term()}.
list_gpg_identities(Conn) ->
    SQL =
        <<
            "SELECT gpg_fp, gpg_pub_armor, status, registered_by, registered_at, last_seen, metadata \n"
            "             FROM gpg_identities ORDER BY registered_at DESC"
        >>,

    case esqlite3:q(Conn, SQL) of
        Rows when is_list(Rows) ->
            Identities = lists:map(
                fun([Fp, Pub, St, RegBy, Reg, Last, Meta]) ->
                    #gpg_identity{
                        gpg_fp = Fp,
                        gpg_pub_armor = Pub,
                        status = St,
                        registered_by = RegBy,
                        registered_at = Reg,
                        last_seen = Last,
                        metadata = Meta
                    }
                end,
                Rows
            ),
            {ok, Identities};
        {error, Reason} = Error ->
            ?error("Failed to list GPG identities: ~p", [Reason]),
            Error
    end.

%% @doc Register a new user (admin-mediated registration).
%%
%% This is the primary user onboarding function in the admin-mediated flow.
%% An admin explicitly registers a user's GPG public key, which allows that
%% user to subsequently request certificates via /ca/v1/csr.
%%
%% == Example ==
%% ```
%% GpgPubKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----...">>,
%% Metadata = <<"{\"name\":\"Bob Smith\",\"team\":\"Engineering\"}">>,
%% ok = cryptic_ca_store:register_user(Conn, <<"ABCD1234...">>, 
%%                                     GpgPubKey, <<"ADMIN_FP">>, Metadata).
%% '''
%%
%% @param Conn Database connection reference
%% @param GpgFp The GPG fingerprint to register
%% @param GpgPubArmor The armored GPG public key
%% @param RegisteredBy GPG fingerprint of admin performing registration
%% @param Metadata Optional JSON metadata (name, team, notes, etc.)
%% @returns `ok' on success, `{error, Reason}' on failure
-spec register_user(db_ref(), gpg_fingerprint(), binary(), gpg_fingerprint(), binary() | undefined) ->
    ok | {error, term()}.
register_user(Conn, GpgFp, GpgPubArmor, RegisteredBy, Metadata) ->
    Now = erlang:system_time(second),
    Identity = #gpg_identity{
        gpg_fp = GpgFp,
        gpg_pub_armor = GpgPubArmor,
        status = <<"active">>,
        registered_by = RegisteredBy,
        registered_at = Now,
        last_seen = Now,
        metadata = Metadata
    },
    insert_gpg_identity(Conn, Identity).

%% @doc Update a user's status (suspend, revoke, reactivate).
%%
%% Changes the status of a registered user. Status transitions:
%% - active → suspended: Temporarily disable user access
%% - suspended → active: Reactivate suspended user
%% - active/suspended → revoked: Permanently disable user (irreversible)
%%
%% == Example ==
%% ```
%% %% Suspend a user
%% ok = cryptic_ca_store:update_user_status(Conn, <<"ABCD1234...">>, <<"suspended">>).
%% 
%% %% Revoke a user
%% ok = cryptic_ca_store:update_user_status(Conn, <<"ABCD1234...">>, <<"revoked">>).
%% '''
%%
%% @param Conn Database connection reference
%% @param GpgFp The GPG fingerprint to update
%% @param NewStatus One of: &lt;&lt;"active">>, &lt;&lt;"suspended">>, &lt;&lt;"revoked">>
%% @returns `ok' on success, `{error, Reason}' on failure
-spec update_user_status(db_ref(), gpg_fingerprint(), binary()) -> ok | {error, term()}.
update_user_status(Conn, GpgFp, NewStatus) ->
    SQL = <<"UPDATE gpg_identities SET status = ?1 WHERE gpg_fp = ?2">>,
    case esqlite3:q(Conn, SQL, [NewStatus, GpgFp]) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to update user status for ~s: ~p", [GpgFp, Reason]),
            Error
    end.

%%====================================================================
%% Audit Operations
%%====================================================================

%% @doc Insert an audit log entry.
%%
%% Records a security-relevant event in the audit log for compliance and
%% forensic purposes. Events include identity registration, revocations, etc.
%%
%% The details field typically contains JSON-encoded additional information
%% about the event.
%%
%% @param Conn Database connection reference
%% @param Log The audit log entry to insert
%% @returns `ok' on success, `{error, Reason}' on failure
-spec insert_audit_log(db_ref(), #audit_log{}) -> ok | {error, term()}.
insert_audit_log(Conn, #audit_log{} = Log) ->
    SQL =
        <<
            "INSERT INTO audit_log (timestamp, event_type, gpg_fp, details, ip_address) \n"
            "             VALUES (?1, ?2, ?3, ?4, ?5)"
        >>,
    Params = [
        Log#audit_log.timestamp,
        Log#audit_log.event_type,
        Log#audit_log.gpg_fp,
        Log#audit_log.details,
        Log#audit_log.ip_address
    ],

    case esqlite3:q(Conn, SQL, Params) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to insert audit log: ~p", [Reason]),
            Error
    end.

%% @doc Retrieve audit logs within a time range.
%%
%% Fetches audit log entries between two Unix timestamps (inclusive).
%% Results are returned in reverse chronological order (most recent first).
%%
%% Useful for generating audit reports, investigating security incidents,
%% or compliance reviews.
%%
%% == Example ==
%% ```
%% %% Get logs from the last 24 hours
%% Now = erlang:system_time(second),
%% OneDayAgo = Now - 86400,
%% {ok, Logs} = cryptic_ca_store:get_audit_logs(Conn, OneDayAgo, Now),
%% lists:foreach(
%%     fun(Log) ->
%%         io:format("~s: ~s~n", [Log#audit_log.event_type, Log#audit_log.gpg_fp])
%%     end,
%%     Logs
%% ).
%% '''
%%
%% @param Conn Database connection reference
%% @param FromTimestamp Start of time range (Unix timestamp in seconds, inclusive)
%% @param ToTimestamp End of time range (Unix timestamp in seconds, inclusive)
%% @returns `{ok, [Log]}' with list of audit logs (may be empty), or `{error, Reason}' on database error
-spec get_audit_logs(db_ref(), unix_timestamp(), unix_timestamp()) ->
    {ok, [#audit_log{}]} | {error, term()}.
get_audit_logs(Conn, FromTimestamp, ToTimestamp) ->
    SQL =
        <<
            "SELECT timestamp, event_type, gpg_fp, details, ip_address \n"
            "             FROM audit_log \n"
            "             WHERE timestamp >= ?1 AND timestamp <= ?2 \n"
            "             ORDER BY timestamp DESC"
        >>,

    case esqlite3:q(Conn, SQL, [FromTimestamp, ToTimestamp]) of
        Rows when is_list(Rows) ->
            Logs = lists:map(
                fun([Ts, Evt, Fp, Det, Ip]) ->
                    #audit_log{
                        timestamp = Ts,
                        event_type = Evt,
                        gpg_fp = Fp,
                        details = Det,
                        ip_address = Ip
                    }
                end,
                Rows
            ),
            {ok, Logs};
        {error, Reason} = Error ->
            ?error("Failed to get audit logs: ~p", [Reason]),
            Error
    end.

%%====================================================================
%% Certificate Operations
%%====================================================================

%% @doc Insert a certificate into the database.
%%
%% Records a newly issued certificate for tracking expiration, revocation,
%% and renewal history. Called immediately after issuing a certificate.
%%
%% @param Conn Database connection reference
%% @param Cert The certificate record to insert
%% @returns `ok' on success, `{error, Reason}' on failure
-spec insert_certificate(db_ref(), #certificate{}) -> ok | {error, term()}.
insert_certificate(Conn, #certificate{} = Cert) ->
    SQL = <<"
        INSERT INTO certificates 
            (serial, gpg_fp, issued_at, expires_at, status, cert_pem)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
    ">>,
    
    Params = [
        Cert#certificate.serial,
        Cert#certificate.gpg_fp,
        Cert#certificate.issued_at,
        Cert#certificate.expires_at,
        Cert#certificate.status,
        Cert#certificate.cert_pem
    ],
    
    case esqlite3:q(Conn, SQL, Params) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to insert certificate ~s: ~p", [Cert#certificate.serial, Reason]),
            Error
    end.

%% @doc Get a certificate by serial number.
%%
%% Retrieves full certificate details including revocation status.
%%
%% @param Conn Database connection reference
%% @param Serial Certificate serial number
%% @returns `{ok, Certificate}' or `{error, not_found}'
-spec get_certificate(db_ref(), binary()) -> {ok, #certificate{}} | {error, term()}.
get_certificate(Conn, Serial) ->
    SQL = <<"
        SELECT serial, gpg_fp, issued_at, expires_at, status, 
               revoked_at, revoked_by, revoked_reason, cert_pem
        FROM certificates
        WHERE serial = ?1
    ">>,
    
    case esqlite3:q(Conn, SQL, [Serial]) of
        [[S, Fp, Issued, Expires, Status, RevokedAt, RevokedBy, Reason, Pem]] ->
            {ok, #certificate{
                serial = S,
                gpg_fp = Fp,
                issued_at = Issued,
                expires_at = Expires,
                status = Status,
                revoked_at = RevokedAt,
                revoked_by = RevokedBy,
                revoked_reason = Reason,
                cert_pem = Pem
            }};
        [] ->
            {error, not_found};
        {error, Reason} = Error ->
            ?error("Failed to get certificate ~s: ~p", [Serial, Reason]),
            Error
    end.

%% @doc List all certificates for a user.
%%
%% Returns all certificates (active, expired, revoked) for the given GPG fingerprint,
%% sorted by issue date (most recent first).
%%
%% @param Conn Database connection reference
%% @param GpgFp GPG fingerprint
%% @returns `{ok, [Certificate]}' or `{error, Reason}'
-spec list_certificates_by_user(db_ref(), binary()) -> {ok, [#certificate{}]} | {error, term()}.
list_certificates_by_user(Conn, GpgFp) ->
    SQL = <<"
        SELECT serial, gpg_fp, issued_at, expires_at, status,
               revoked_at, revoked_by, revoked_reason, cert_pem
        FROM certificates
        WHERE gpg_fp = ?1
        ORDER BY issued_at DESC
    ">>,
    
    case esqlite3:q(Conn, SQL, [GpgFp]) of
        Rows when is_list(Rows) ->
            Certs = lists:map(fun([S, Fp, Issued, Expires, Status, RevokedAt, RevokedBy, Reason, Pem]) ->
                #certificate{
                    serial = S,
                    gpg_fp = Fp,
                    issued_at = Issued,
                    expires_at = Expires,
                    status = Status,
                    revoked_at = RevokedAt,
                    revoked_by = RevokedBy,
                    revoked_reason = Reason,
                    cert_pem = Pem
                }
            end, Rows),
            {ok, Certs};
        {error, Reason} = Error ->
            ?error("Failed to list certificates for ~s: ~p", [GpgFp, Reason]),
            Error
    end.

%% @doc Update certificate status.
%%
%% Changes certificate status (e.g., from 'active' to 'expired').
%% This is typically called by the expiration monitoring process.
%%
%% @param Conn Database connection reference
%% @param Serial Certificate serial number
%% @param NewStatus New status ('active' | 'expired' | 'revoked')
%% @returns `ok' or `{error, Reason}'
-spec update_certificate_status(db_ref(), binary(), binary()) -> ok | {error, term()}.
update_certificate_status(Conn, Serial, NewStatus) ->
    SQL = <<"UPDATE certificates SET status = ?1 WHERE serial = ?2">>,
    
    case esqlite3:q(Conn, SQL, [NewStatus, Serial]) of
        Result when Result =:= [] orelse Result =:= ok ->
            ok;
        {error, Reason} = Error ->
            ?error("Failed to update certificate status ~s: ~p", [Serial, Reason]),
            Error
    end.

%% @doc Revoke a certificate.
%%
%% Marks certificate as revoked with reason and admin who performed revocation.
%% Also records audit log entry.
%%
%% @param Conn Database connection reference
%% @param Serial Certificate serial number
%% @param RevokedBy GPG fingerprint of admin revoking certificate
%% @param Reason Revocation reason
%% @returns `ok' or `{error, Reason}'
-spec revoke_certificate(db_ref(), binary(), binary(), binary()) -> ok | {error, term()}.
revoke_certificate(Conn, Serial, RevokedBy, Reason) ->
    Now = erlang:system_time(second),
    SQL = <<"
        UPDATE certificates 
        SET status = 'revoked', 
            revoked_at = ?1, 
            revoked_by = ?2, 
            revoked_reason = ?3
        WHERE serial = ?4
    ">>,
    
    case esqlite3:q(Conn, SQL, [Now, RevokedBy, Reason, Serial]) of
        Result when Result =:= [] orelse Result =:= ok ->
            %% Log to audit trail
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"certificate_revoked">>,
                gpg_fp = RevokedBy,
                details = iolist_to_binary(io_lib:format("Revoked cert ~s: ~s", [Serial, Reason])),
                ip_address = undefined
            },
            insert_audit_log(Conn, AuditLog),
            ok;
        {error, ErrorReason} = Error ->
            ?error("Failed to revoke certificate ~s: ~p", [Serial, ErrorReason]),
            Error
    end.

%% @doc List certificates expiring within the given number of seconds.
%%
%% Returns all active certificates that will expire within the specified
%% time window. Used by expiration monitoring to send warnings.
%%
%% @param Conn Database connection reference
%% @param WithinSeconds Time window in seconds (e.g., 172800 for 2 days)
%% @returns `{ok, [Certificate]}' or `{error, Reason}'
-spec list_expiring_certificates(db_ref(), non_neg_integer()) -> 
    {ok, [#certificate{}]} | {error, term()}.
list_expiring_certificates(Conn, WithinSeconds) ->
    Now = erlang:system_time(second),
    ExpiryThreshold = Now + WithinSeconds,
    
    SQL = <<"
        SELECT serial, gpg_fp, issued_at, expires_at, status,
               revoked_at, revoked_by, revoked_reason, cert_pem
        FROM certificates
        WHERE status = 'active' 
          AND expires_at <= ?1 
          AND expires_at > ?2
        ORDER BY expires_at ASC
    ">>,
    
    case esqlite3:q(Conn, SQL, [ExpiryThreshold, Now]) of
        Rows when is_list(Rows) ->
            Certs = lists:map(fun([S, Fp, Issued, Expires, Status, RevokedAt, RevokedBy, Reason, Pem]) ->
                #certificate{
                    serial = S,
                    gpg_fp = Fp,
                    issued_at = Issued,
                    expires_at = Expires,
                    status = Status,
                    revoked_at = RevokedAt,
                    revoked_by = RevokedBy,
                    revoked_reason = Reason,
                    cert_pem = Pem
                }
            end, Rows),
            {ok, Certs};
        {error, Reason} = Error ->
            ?error("Failed to list expiring certificates: ~p", [Reason]),
            Error
    end.

%% @doc Clean up expired certificates.
%%
%% Updates status of expired certificates from 'active' to 'expired'.
%% Should be called periodically by background maintenance process.
%%
%% @param Conn Database connection reference
%% @returns `{ok, Count}' where Count is number of certificates marked expired
-spec cleanup_expired_certificates(db_ref()) -> {ok, non_neg_integer()} | {error, term()}.
cleanup_expired_certificates(Conn) ->
    Now = erlang:system_time(second),
    SQL = <<"
        UPDATE certificates 
        SET status = 'expired' 
        WHERE status = 'active' AND expires_at <= ?1
    ">>,
    
    case esqlite3:q(Conn, SQL, [Now]) of
        Result when Result =:= [] orelse Result =:= ok ->
            %% SQLite doesn't return row count directly, so we query
            CountSQL = <<"SELECT changes()">>,
            case esqlite3:q(Conn, CountSQL) of
                [[Count]] -> {ok, Count};
                _ -> {ok, 0}
            end;
        {error, Reason} = Error ->
            ?error("Failed to cleanup expired certificates: ~p", [Reason]),
            Error
    end.

%%====================================================================
%% Database Inspection Functions (for debugging)
%%====================================================================

%% @doc List all tables in the database.
%%
%% Returns the names of all tables in the SQLite database, which is useful
%% for interactive debugging and understanding the database schema.
%%
%% == Example ==
%% ```
%% %% From the Erlang shell:
%% DbRef = cryptic_ca_init:get_db_ref().
%% {ok, Tables} = cryptic_ca_store:list_tables(DbRef).
%% io:format("Tables: ~p~n", [Tables]).
%% '''
%%
%% @param Conn Database connection reference
%% @returns `{ok, [TableName]}' where TableName is a binary, or `{error, Reason}'
-spec list_tables(db_ref()) -> {ok, [binary()]} | {error, term()}.
list_tables(Conn) ->
    SQL = <<"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name">>,
    case esqlite3:q(Conn, SQL) of
        Rows when is_list(Rows) ->
            Tables = [Name || [Name] <- Rows],
            {ok, Tables};
        {error, Reason} = Error ->
            ?error("Failed to list tables: ~p", [Reason]),
            Error
    end.

%% @doc Show the CREATE TABLE statement for a specific table.
%%
%% Returns the SQL schema definition for the specified table, useful for
%% understanding table structure, columns, and constraints.
%%
%% == Example ==
%% ```
%% DbRef = cryptic_ca_init:get_db_ref().
%% {ok, Schema} = cryptic_ca_store:describe_table(DbRef, &lt;&lt;"certificates">>).
%% io:format("~s~n", [Schema]).
%% '''
%%
%% @param Conn Database connection reference
%% @param TableName Name of the table (as a binary)
%% @returns `{ok, CreateStatement}' where CreateStatement is a binary, or `{error, Reason}'
-spec describe_table(db_ref(), binary()) -> {ok, binary()} | {error, term()}.
describe_table(Conn, TableName) ->
    SQL = <<"SELECT sql FROM sqlite_master WHERE type='table' AND name = ?1">>,
    case esqlite3:q(Conn, SQL, [TableName]) of
        [[CreateSQL]] ->
            {ok, CreateSQL};
        [] ->
            {error, {table_not_found, TableName}};
        {error, Reason} = Error ->
            ?error("Failed to describe table ~s: ~p", [TableName, Reason]),
            Error
    end.

%% @doc Inspect the database and print a summary to stdout.
%%
%% This is a convenience function for quick database inspection from the
%% Erlang shell. It retrieves the database reference, lists all tables,
%% and shows the schema and row count for each table.
%%
%% Note: This function uses cryptic_ca_init:get_db_ref() to get the database
%% reference, so the CA init service must be running.
%%
%% == Example ==
%% ```
%% %% From the Erlang shell (after server is running):
%% cryptic_ca_store:inspect_db().
%% '''
%%
%% @returns `ok' on success, or `{error, Reason}' on failure
-spec inspect_db() -> ok | {error, term()}.
inspect_db() ->
    case cryptic_ca_init:get_db_ref() of
        {ok, Conn} ->
            io:format("~n=== CA Database Inspection ===~n~n", []),
            case list_tables(Conn) of
                {ok, Tables} ->
                    io:format("Tables (~p total):~n", [length(Tables)]),
                    lists:foreach(
                        fun(TableName) ->
                            %% Show table name and row count
                            CountSQL = iolist_to_binary([<<"SELECT COUNT(*) FROM ">>, TableName]),
                            Count = case esqlite3:q(Conn, CountSQL) of
                                [[N]] -> N;
                                _ -> unknown
                            end,
                            io:format("~n  - ~s (~p rows)~n", [TableName, Count]),

                            %% Show schema
                            case describe_table(Conn, TableName) of
                                {ok, Schema} ->
                                    io:format("    Schema: ~s~n", [Schema]);
                                {error, SchemaErr} ->
                                    io:format("    Error getting schema: ~p~n", [SchemaErr])
                            end
                        end,
                        Tables
                    ),
                    io:format("~n=== End of Database Inspection ===~n~n", []),
                    ok;
                {error, Reason} ->
                    io:format("Error listing tables: ~p~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Error getting database reference: ~p~n", [Reason]),
            {error, Reason}
    end.
