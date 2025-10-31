%% @doc Cryptic GPG Registry - GPG Identity Operations
%%
%% This module provides higher-level GPG identity registry operations,
%% wrapping the storage layer with business logic and common queries.
%%
%% @author Cryptic Development Team
%% @version 1.0.0
%% @since October 2025
-module(cryptic_gpg_registry).

-include("cryptic_ca.hrl").

-export([
    register_gpg_identity/5,
    register_bootstrap_identity/3,
    get_identity/2,
    verify_identity_status/2,
    list_all_identities/1,
    list_verified_identities/1,
    list_pending_identities/1,
    revoke_identity/2,
    update_last_seen/2
]).

-include("cryptic_server.hrl").

-type db_ref() :: pid().
-type gpg_fingerprint() :: binary().
-type status() :: verified_via_invite | verified_bootstrap | pending | revoked.

%%====================================================================
%% API
%%====================================================================

%% @doc Register a new GPG identity via invite token.
%%
%% This function is called during the onboarding process when a new user
%% consumes an invite token. It creates a verified GPG identity record
%% with full audit trail tracking.
%%
%% The identity will be marked with status `verified_via_invite', indicating
%% it was validated through the invitation system. This provides traceability
%% of who invited whom.
%%
%% == Workflow ==
%% <ol>
%%   <li>User provides GPG public key and valid invite token</li>
%%   <li>System calls this function to register the identity</li>
%%   <li>Identity is stored with verification status</li>
%%   <li>Audit log entry is created for compliance</li>
%% </ol>
%%
%% == Example ==
%% ```
%% %% After validating and consuming an invite
%% ok = cryptic_gpg_registry:register_gpg_identity(
%%     DbRef,
%%     <<"ABCD1234...">>,  % New user's fingerprint
%%     <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,  % Their public key
%%     <<"EFGH5678...">>,  % Inviter's fingerprint
%%     <<"inv-550e8400-...">>  % The consumed invite ID
%% ).
%% '''
%%
%% @param DbRef Database connection reference
%% @param GpgFp GPG fingerprint of the new user (40-char hex string)
%% @param GpgPubArmor ASCII-armored GPG public key
%% @param InviterFp GPG fingerprint of the user who created the invite
%% @param InviteId The invite ID that was consumed for this registration
%% @returns `ok' on success, `{error, Reason}' on failure (e.g., duplicate fingerprint)
-spec register_gpg_identity(
    db_ref(), gpg_fingerprint(), binary(), gpg_fingerprint(), binary()
) ->
    ok | {error, term()}.
register_gpg_identity(DbRef, GpgFp, GpgPubArmor, InviterFp, InviteId) ->
    Now = erlang:system_time(second),
    Identity = #gpg_identity{
        gpg_fp = GpgFp,
        gpg_pub_armor = GpgPubArmor,
        status = <<"verified_via_invite">>,
        inviter_fp = InviterFp,
        registered_at = Now,
        last_seen = Now,
        invite_id = InviteId
    },

    case cryptic_ca_store:insert_gpg_identity(DbRef, Identity) of
        ok ->
            ?info("Registered GPG identity ~s via invite ~s", [
                GpgFp, InviteId
            ]),

            %% Log audit trail
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"gpg_register_via_invite">>,
                gpg_fp = GpgFp,
                invite_id = InviteId,
                details = jsx:encode(#{
                    <<"inviter_fp">> => InviterFp
                }),
                ip_address = undefined
            },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),
            ok;
        {error, RegistrationReason} = RegistrationError ->
            ?error("Failed to register GPG identity ~s: ~p", [
                GpgFp, RegistrationReason
            ]),
            RegistrationError
    end.

%% @doc Register a bootstrap GPG identity for initial system setup.
%%
%% This function is used to manually register the first administrator(s)
%% who already have TLS certificates. Bootstrap identities are marked as
%% verified without requiring an invite token, since they represent the
%% initial trust anchors of the system.
%%
%% Use this function sparingly and only during initial system setup or when
%% manually adding administrators. All other users should be onboarded via
%% the invitation system.
%%
%% == When to Use ==
%% <ul>
%%   <li>Initial system setup - registering the first admin</li>
%%   <li>Emergency admin access - when invite system is unavailable</li>
%%   <li>Migrating existing users - with proper authorization</li>
%% </ul>
%%
%% == Security Considerations ==
%% Bootstrap registration bypasses the invitation workflow. Ensure proper
%% authentication and authorization checks are performed before calling
%% this function.
%%
%% == Example ==
%% ```
%% %% Register the first administrator
%% ok = cryptic_gpg_registry:register_bootstrap_identity(
%%     DbRef,
%%     <<"ADMIN1234...">>,
%%     <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>
%% ).
%% '''
%%
%% @param DbRef Database connection reference
%% @param GpgFp GPG fingerprint of the bootstrap user
%% @param GpgPubArmor ASCII-armored GPG public key
%% @returns `ok' on success, `{error, Reason}' on failure (e.g., duplicate fingerprint)
-spec register_bootstrap_identity(db_ref(), gpg_fingerprint(), binary()) ->
    ok | {error, term()}.
register_bootstrap_identity(DbRef, GpgFp, GpgPubArmor) ->
    Now = erlang:system_time(second),
    Identity = #gpg_identity{
        gpg_fp = GpgFp,
        gpg_pub_armor = GpgPubArmor,
        status = <<"verified_bootstrap">>,
        inviter_fp = undefined,
        registered_at = Now,
        last_seen = Now,
        invite_id = undefined
    },

    case cryptic_ca_store:insert_gpg_identity(DbRef, Identity) of
        ok ->
            ?info("Registered bootstrap GPG identity ~s", [GpgFp]),

            %% Log audit trail
            AuditLog = #audit_log{
                timestamp = Now,
                event_type = <<"gpg_register_bootstrap">>,
                gpg_fp = GpgFp,
                invite_id = undefined,
                details = jsx:encode(#{
                    <<"method">> => <<"bootstrap">>
                }),
                ip_address = undefined
            },
            cryptic_ca_store:insert_audit_log(DbRef, AuditLog),
            ok;
        {error, BootstrapReason} = BootstrapError ->
            ?error(
                "Failed to register bootstrap GPG identity ~s: ~p",
                [GpgFp, BootstrapReason]
            ),
            BootstrapError
    end.

%% @doc Retrieve a GPG identity by fingerprint.
%%
%% This is a simple wrapper around the storage layer that retrieves
%% complete identity information including verification status, registration
%% time, and associated metadata.
%%
%% == Example ==
%% ```
%% case cryptic_gpg_registry:get_identity(DbRef, <<"ABCD1234...">>) of
%%     {ok, Identity} ->
%%         io:format("User status: ~s~n", [Identity#gpg_identity.status]),
%%         io:format("Registered: ~p~n", [Identity#gpg_identity.registered_at]);
%%     {error, not_found} ->
%%         io:format("Unknown fingerprint~n")
%% end.
%% '''
%%
%% @param DbRef Database connection reference
%% @param GpgFp GPG fingerprint to look up
%% @returns `{ok, Identity}' if found, `{error, not_found}' if not found, or `{error, Reason}' on database error
-spec get_identity(db_ref(), gpg_fingerprint()) ->
    {ok, #gpg_identity{}} | {error, not_found} | {error, term()}.
get_identity(DbRef, GpgFp) ->
    cryptic_ca_store:get_gpg_identity(DbRef, GpgFp).

%% @doc Verify the status of a GPG identity.
%%
%% Returns the verification status as an atom for easier pattern matching
%% in business logic. This is useful for access control decisions and
%% authorization checks.
%%
%% == Status Values ==
%% <ul>
%%   <li>`verified_via_invite' - User joined through invite system</li>
%%   <li>`verified_bootstrap' - Manually registered administrator</li>
%%   <li>`pending' - Awaiting verification (not yet implemented)</li>
%%   <li>`revoked' - Identity has been revoked</li>
%% </ul>
%%
%% == Example ==
%% ```
%% case cryptic_gpg_registry:verify_identity_status(DbRef, UserFp) of
%%     {ok, verified_via_invite} ->
%%         grant_user_access();
%%     {ok, verified_bootstrap} ->
%%         grant_admin_access();
%%     {ok, revoked} ->
%%         deny_access();
%%     {error, not_found} ->
%%         unknown_user()
%% end.
%% '''
%%
%% @param DbRef Database connection reference
%% @param GpgFp GPG fingerprint to check
%% @returns `{ok, Status}' where Status is an atom, or `{error, not_found}'/`{error, Reason}'
-spec verify_identity_status(db_ref(), gpg_fingerprint()) ->
    {ok, status()} | {error, not_found} | {error, term()}.
verify_identity_status(DbRef, GpgFp) ->
    case get_identity(DbRef, GpgFp) of
        {ok, Identity} ->
            Status =
                case Identity#gpg_identity.status of
                    <<"verified_via_invite">> -> verified_via_invite;
                    <<"verified_bootstrap">> -> verified_bootstrap;
                    <<"pending">> -> pending;
                    <<"revoked">> -> revoked;
                    Other -> Other
                end,
            {ok, Status};
        {error, _Reason} = Error ->
            Error
    end.

%% @doc List all GPG identities in the registry.
%%
%% Returns all registered identities regardless of status. This is useful
%% for administrative interfaces showing all users in the system.
%%
%% For filtered lists (e.g., only active users), see
%% {@link list_verified_identities/1} or {@link list_pending_identities/1}.
%%
%% == Example ==
%% ```
%% {ok, AllUsers} = cryptic_gpg_registry:list_all_identities(DbRef),
%% io:format("Total users: ~p~n", [length(AllUsers)]).
%% '''
%%
%% @param DbRef Database connection reference
%% @returns `{ok, [Identity]}' with all identities, or `{error, Reason}' on database error
-spec list_all_identities(db_ref()) ->
    {ok, [#gpg_identity{}]} | {error, term()}.
list_all_identities(DbRef) ->
    cryptic_ca_store:list_gpg_identities(DbRef).

%% @doc List all verified GPG identities.
%%
%% Returns only identities with verified status (either via invite or bootstrap).
%% This excludes pending and revoked identities, providing a list of active,
%% trusted users in the system.
%%
%% This is useful for:
%% <ul>
%%   <li>Displaying active users in UI</li>
%%   <li>Access control lists</li>
%%   <li>Audit reports of verified users</li>
%% </ul>
%%
%% == Example ==
%% ```
%% {ok, VerifiedUsers} = cryptic_gpg_registry:list_verified_identities(DbRef),
%% ActiveCount = length(VerifiedUsers),
%% io:format("~p active verified users~n", [ActiveCount]).
%% '''
%%
%% @param DbRef Database connection reference
%% @returns `{ok, [Identity]}' with verified identities only, or `{error, Reason}' on error
-spec list_verified_identities(db_ref()) ->
    {ok, [#gpg_identity{}]} | {error, term()}.
list_verified_identities(DbRef) ->
    case list_all_identities(DbRef) of
        {ok, Identities} ->
            Verified = lists:filter(
                fun(Identity) ->
                    case Identity#gpg_identity.status of
                        <<"verified_via_invite">> -> true;
                        <<"verified_bootstrap">> -> true;
                        _ -> false
                    end
                end,
                Identities
            ),
            {ok, Verified};
        {error, _Reason} = Error ->
            Error
    end.

%% @doc List all pending GPG identities.
%%
%% Returns identities that are awaiting verification. In the current
%% implementation, this is primarily for future use - the invitation
%% system immediately verifies users upon successful invite consumption.
%%
%% This function may be useful for:
%% <ul>
%%   <li>Manual approval workflows (future feature)</li>
%%   <li>Administrative review queues</li>
%%   <li>Monitoring unverified registrations</li>
%% </ul>
%%
%% == Example ==
%% ```
%% {ok, PendingUsers} = cryptic_gpg_registry:list_pending_identities(DbRef),
%% case length(PendingUsers) of
%%     0 -> io:format("No pending approvals~n");
%%     N -> io:format("~p users awaiting verification~n", [N])
%% end.
%% '''
%%
%% @param DbRef Database connection reference
%% @returns `{ok, [Identity]}' with pending identities only, or `{error, Reason}' on error
-spec list_pending_identities(db_ref()) ->
    {ok, [#gpg_identity{}]} | {error, term()}.
list_pending_identities(DbRef) ->
    case list_all_identities(DbRef) of
        {ok, Identities} ->
            Pending = lists:filter(
                fun(Identity) ->
                    Identity#gpg_identity.status =:= <<"pending">>
                end,
                Identities
            ),
            {ok, Pending};
        {error, _Reason} = Error ->
            Error
    end.

%% @doc Revoke a GPG identity.
%%
%% Marks an identity as revoked, preventing it from being used for
%% authentication or authorization. The identity remains in the database
%% for audit purposes but is effectively disabled.
%%
%% Common reasons for revocation:
%% <ul>
%%   <li>User account termination</li>
%%   <li>Security compromise of private key</li>
%%   <li>Administrative action</li>
%%   <li>Policy violation</li>
%% </ul>
%%
%% == Audit Trail ==
%% This operation creates an audit log entry recording the revocation,
%% including the previous status for forensic analysis.
%%
%% == Example ==
%% ```
%% %% Revoke a compromised identity
%% case cryptic_gpg_registry:revoke_identity(DbRef, <<"ABCD1234...">>) of
%%     ok ->
%%         io:format("Identity revoked successfully~n"),
%%         notify_security_team();
%%     {error, not_found} ->
%%         io:format("Identity does not exist~n")
%% end.
%% '''
%%
%% @param DbRef Database connection reference
%% @param GpgFp GPG fingerprint to revoke
%% @returns `ok' on success, `{error, not_found}' if identity doesn't exist, or `{error, Reason}' on database error
-spec revoke_identity(db_ref(), gpg_fingerprint()) -> ok | {error, term()}.
revoke_identity(DbRef, GpgFp) ->
    case get_identity(DbRef, GpgFp) of
        {ok, Identity} ->
            %% Update the identity status
            Sql =
                <<"UPDATE gpg_identities SET status = 'revoked' WHERE gpg_fp = ?">>,
            case esqlite3:q(DbRef, Sql, [GpgFp]) of
                [] ->
                    ?info("Revoked GPG identity ~s", [GpgFp]),

                    %% Log audit trail
                    Now = erlang:system_time(second),
                    AuditLog = #audit_log{
                        timestamp = Now,
                        event_type = <<"gpg_revoke">>,
                        gpg_fp = GpgFp,
                        invite_id = Identity#gpg_identity.invite_id,
                        details = jsx:encode(#{
                            <<"previous_status">> =>
                                Identity#gpg_identity.status
                        }),
                        ip_address = undefined
                    },
                    cryptic_ca_store:insert_audit_log(DbRef, AuditLog),
                    ok;
                {error, RevokeReason} = RevokeError ->
                    ?error(
                        "Failed to revoke GPG identity ~s: ~p",
                        [GpgFp, RevokeReason]
                    ),
                    RevokeError
            end;
        {error, not_found} ->
            {error, not_found};
        {error, _Reason} = Error ->
            Error
    end.

%% @doc Update the last_seen timestamp for a GPG identity.
%%
%% Automatically records the current UTC timestamp to track when an identity
%% was last active. This is typically called during authentication or when
%% processing messages from the user.
%%
%% == Use Cases ==
%% <ul>
%%   <li>Track active vs. inactive users</li>
%%   <li>Identify stale accounts for cleanup</li>
%%   <li>Security monitoring for unusual access patterns</li>
%%   <li>Compliance reporting on user activity</li>
%% </ul>
%%
%% == Automatic Timestamp ==
%% The timestamp is automatically set to the current time - you don't
%% provide it as a parameter. This ensures consistency and prevents
%% timestamp manipulation.
%%
%% == Example ==
%% ```
%% %% Update last_seen after successful authentication
%% case authenticate_user(GpgFp) of
%%     {ok, _User} ->
%%         cryptic_gpg_registry:update_last_seen(DbRef, GpgFp),
%%         {ok, authenticated};
%%     {error, _} = Err ->
%%         Err
%% end.
%% '''
%%
%% @param DbRef Database connection reference
%% @param GpgFp GPG fingerprint to update
%% @returns `ok' on success, `{error, not_found}' if identity doesn't exist, or `{error, Reason}' on database error
-spec update_last_seen(db_ref(), gpg_fingerprint()) -> ok | {error, term()}.
update_last_seen(DbRef, GpgFp) ->
    cryptic_ca_store:update_last_seen(DbRef, GpgFp).

%%====================================================================
%% Internal functions
%%====================================================================
