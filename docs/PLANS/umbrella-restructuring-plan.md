# Cryptic Umbrella Project Restructuring Plan

**Status:** Planning  
**Date:** 10 October 2025  
**Author:** Cryptic Team  
**Target Completion:** TBD

## Executive Summary

This document outlines the plan to restructure the Cryptic codebase from a monolithic single-application structure into a multi-application umbrella project. This will improve code organization, enable independent deployment of components, and facilitate future development.

## Current State Analysis

### Current Directory Structure
```
cryptic/
├── src/                          # All source code mixed together
│   ├── cryptic_server.erl        # Server code
│   ├── cryptic_console.erl       # Console client code
│   ├── cryptic_engine.erl        # Core engine code
│   ├── cryptic_lib.erl           # Library code
│   ├── cryptic_ws_ui.erl         # NCurses client code
│   └── ... (50+ modules)
├── include/                      # Shared headers
├── c_src/                        # NIF code
├── test/                         # All tests mixed
├── priv/                         # Runtime resources
└── rebar.config                  # Single config
```

### Problems with Current Structure

1. **Tight Coupling**: Server, client, and library code are intermingled
2. **Deployment Complexity**: Can't deploy server without client code and vice versa
3. **Dependency Management**: All dependencies loaded for all use cases
4. **Testing Difficulty**: Hard to test components in isolation
5. **Code Navigation**: Difficult to find relevant modules in large flat structure
6. **Release Management**: Can't version components independently

## Target State Architecture

### Proposed Directory Structure

```
cryptic/                          # Root umbrella project
├── rebar.config                  # Root configuration
├── apps/                         # All applications
│   │
│   ├── cryptic_lib/             # Foundation: Cryptographic primitives
│   │   ├── src/
│   │   │   ├── cryptic_lib.app.src
│   │   │   ├── cryptic_lib.erl           # Main library module
│   │   │   ├── cryptic_nif.erl           # NIF interface
│   │   │   ├── cryptic_messages.erl      # Message encoding/decoding
│   │   │   └── cryptic_key_derivation.erl
│   │   ├── include/
│   │   │   ├── cryptic.hrl               # Main header
│   │   │   └── cryptic_ansi.hrl          # ANSI escape codes
│   │   ├── c_src/
│   │   │   ├── cryptic_nif.c
│   │   │   └── Makefile
│   │   ├── priv/
│   │   │   └── cryptic_nif.so
│   │   └── rebar.config
│   │
│   ├── cryptic_core/            # Core: Engine and protocol logic
│   │   ├── src/
│   │   │   ├── cryptic_core.app.src
│   │   │   ├── cryptic_engine.erl        # Main engine
│   │   │   ├── cryptic_ratchet_engine.erl
│   │   │   ├── cryptic_double_ratchet.erl
│   │   │   ├── cryptic_key_ratchet.erl
│   │   │   ├── cryptic_chat_storage.erl
│   │   │   ├── cryptic_event_manager.erl
│   │   │   ├── cryptic_console_logger.erl
│   │   │   ├── cryptic_file_logger.erl
│   │   │   └── cryptic_msg_logger.erl
│   │   ├── test/
│   │   │   ├── cryptic_double_ratchet_test.erl
│   │   │   ├── cryptic_key_ratchet_test.erl
│   │   │   └── ...
│   │   └── rebar.config
│   │
│   ├── cryptic_server/          # Server: WebSocket server
│   │   ├── src/
│   │   │   ├── cryptic_server.app.src
│   │   │   ├── cryptic_server_app.erl    # Application callback
│   │   │   ├── cryptic_server_sup.erl    # Supervisor
│   │   │   ├── cryptic_server.erl        # Main server logic
│   │   │   ├── cryptic_ws_handler.erl    # WebSocket handler
│   │   │   ├── cryptic_room_manager.erl
│   │   │   └── cryptic_room_handlers.erl
│   │   ├── priv/
│   │   │   └── static/                   # Web assets if needed
│   │   ├── config/
│   │   │   ├── sys.config
│   │   │   └── vm.args
│   │   ├── test/
│   │   │   └── cryptic_server_test.erl
│   │   └── rebar.config
│   │
│   ├── cryptic_console/         # Console: Terminal client
│   │   ├── src/
│   │   │   ├── cryptic_console.app.src
│   │   │   ├── cryptic_console.erl       # Main console
│   │   │   ├── cryptic_console_callbacks.erl
│   │   │   ├── cryptic_shell.erl         # Enhanced shell
│   │   │   ├── cryptic_ws_client.erl     # WebSocket client
│   │   │   └── cryptic_client_lib.erl
│   │   ├── config/
│   │   │   ├── client.config
│   │   │   └── vm.args
│   │   ├── test/
│   │   │   └── cryptic_console_test.erl
│   │   └── rebar.config
│   │
│   └── cryptic_ncurses/         # NCurses: Full-screen UI client
│       ├── src/
│       │   ├── cryptic_ncurses.app.src
│       │   ├── cryptic_ws_ui.erl         # Main UI
│       │   ├── cryptic_ui_screen.erl     # Screen management
│       │   └── cryptic_ncurses_callbacks.erl
│       ├── config/
│       │   └── client.config
│       ├── test/
│       │   └── cryptic_ncurses_test.erl
│       └── rebar.config
│
├── config/                       # Shared configuration
│   ├── sys.config.example
│   └── vm.args.example
│
├── scripts/                      # Executable scripts
│   ├── cryptic                   # Main CLI (dispatches to subcommands)
│   ├── cryptic_server            # Server launcher
│   └── cryptic_console           # Console launcher
│
├── CA/                           # Certificate authority (shared)
├── docs/                         # Documentation
├── test/                         # Integration tests
└── _build/                       # Build output
```

## Application Breakdown

### 1. cryptic_lib (Foundation Library)

**Purpose:** Core cryptographic primitives and utilities - no processes, pure library

**Modules:**
- `cryptic_lib.erl` - Main API
- `cryptic_nif.erl` - NIF interface to libsodium/monocypher
- `cryptic_messages.erl` - Message encoding/decoding
- `cryptic_key_derivation.erl` - Key derivation functions

**Dependencies:**
- `kernel`
- `stdlib`

**Artifacts:**
- Library application (can be used by any client)
- NIF shared object (`priv/cryptic_nif.so`)

**Notes:**
- No supervision tree
- Stateless functions only
- Can be published to hex.pm independently

### 2. cryptic_core (Core Engine)

**Purpose:** Message encryption engine, protocol implementation, storage

**Modules:**
- `cryptic_engine.erl` - Main engine gen_server
- `cryptic_ratchet_engine.erl` - Ratchet state machine
- `cryptic_double_ratchet.erl` - Double Ratchet protocol
- `cryptic_key_ratchet.erl` - Symmetric key ratchet
- `cryptic_chat_storage.erl` - Message persistence
- `cryptic_event_manager.erl` - Event handling
- Logger modules (`cryptic_console_logger`, `cryptic_file_logger`, `cryptic_msg_logger`)

**Dependencies:**
- `kernel`
- `stdlib`
- `cryptic_lib`

**Artifacts:**
- Library application with gen_servers (used by both server and clients)

**Notes:**
- Contains behavior definitions (e.g., `cryptic_engine` behavior)
- Shared by all clients and server
- Stateful components with supervision

### 3. cryptic_server (WebSocket Server)

**Purpose:** Central server for message routing and user management

**Modules:**
- `cryptic_server_app.erl` - Application callback
- `cryptic_server_sup.erl` - Top-level supervisor
- `cryptic_server.erl` - Main server logic
- `cryptic_ws_handler.erl` - Cowboy WebSocket handler
- `cryptic_room_manager.erl` - Chat room management
- `cryptic_room_handlers.erl` - Room message handlers

**Dependencies:**
- `kernel`, `stdlib`, `sasl`
- `cryptic_lib`
- `cryptic_core`
- `cowboy` - HTTP/WebSocket server
- `gun` - HTTP client (for testing)
- `jsone` - JSON encoding

**Artifacts:**
- OTP release (deployable server)
- Standalone executable

**Deployment:**
```bash
rebar3 as prod release
_build/prod/rel/cryptic_server/bin/cryptic_server start
```

### 4. cryptic_console (Console Client)

**Purpose:** Interactive terminal-based client with line editing

**Modules:**
- `cryptic_console.erl` - Main console application
- `cryptic_console_callbacks.erl` - Engine behavior implementation
- `cryptic_shell.erl` - Enhanced shell with line editing
- `cryptic_ws_client.erl` - WebSocket client
- `cryptic_client_lib.erl` - Client utilities

**Dependencies:**
- `kernel`, `stdlib`
- `cryptic_lib`
- `cryptic_core`
- `gun` - WebSocket client
- `jsone` - JSON encoding

**Artifacts:**
- Escript (single executable file)

**Usage:**
```bash
rebar3 escriptize --app=cryptic_console
_build/default/bin/cryptic_console --username alice
```

### 5. cryptic_ncurses (NCurses Client)

**Purpose:** Full-screen terminal UI client

**Modules:**
- `cryptic_ws_ui.erl` - Main UI application
- `cryptic_ui_screen.erl` - Screen management
- `cryptic_ncurses_callbacks.erl` - Engine behavior implementation

**Dependencies:**
- `kernel`, `stdlib`
- `cryptic_lib`
- `cryptic_core`
- `gun` - WebSocket client
- `jsone` - JSON encoding
- NCurses bindings (TBD)

**Artifacts:**
- Escript or OTP release

**Notes:**
- May be implemented later
- Similar structure to console client

## Dependency Graph

```
┌─────────────────┐
│  cryptic_lib    │  (Foundation - no dependencies)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  cryptic_core   │  (depends on: cryptic_lib)
└────────┬────────┘
         │
         ├──────────────────┬──────────────────┬───────────────────┐
         ▼                  ▼                  ▼                   ▼
┌────────────────┐  ┌────────────────┐  ┌───────────────┐  ┌────────────────┐
│cryptic_server  │  │cryptic_console │  │cryptic_ncurses│  │  future apps   │
└────────────────┘  └────────────────┘  └───────────────┘  └────────────────┘
 (server release)    (escript)           (escript/rel)
```

## Configuration Files

### Root rebar.config

```erlang
%% Root rebar.config - minimal, just declares umbrella structure
{erl_opts, [debug_info]}.

{deps, []}.

{plugins, []}.

{project_plugins, [rebar3_hex, rebar3_ex_doc]}.

{relx, [
    {release, {cryptic_server, "0.1.0"},
     [cryptic_server]},
    
    {release, {cryptic_console, "0.1.0"},
     [cryptic_console]}
]}.
```

### apps/cryptic_lib/rebar.config

```erlang
{erl_opts, [debug_info, warnings_as_errors]}.

{deps, []}.

%% NIF compilation
{pre_hooks, [
    {"(linux|darwin|solaris)", compile, "make -C c_src"},
    {"(freebsd)", compile, "gmake -C c_src"}
]}.

{post_hooks, [
    {"(linux|darwin|solaris)", clean, "make -C c_src clean"},
    {"(freebsd)", clean, "gmake -C c_src clean"}
]}.

{port_specs, [
    {"priv/cryptic_nif.so", ["c_src/*.c"]}
]}.

{port_env, [
    {"CFLAGS", "$CFLAGS -I/opt/homebrew/include -std=c11 -O3"},
    {"LDFLAGS", "$LDFLAGS -L/opt/homebrew/lib -lsodium -lmonocypher"}
]}.
```

### apps/cryptic_core/rebar.config

```erlang
{erl_opts, [debug_info, warnings_as_errors]}.

{deps, [
    {cryptic_lib, {path, "../cryptic_lib"}}
]}.

{eunit_opts, [verbose]}.
```

### apps/cryptic_server/rebar.config

```erlang
{erl_opts, [debug_info, warnings_as_errors]}.

{deps, [
    {cryptic_lib, {path, "../cryptic_lib"}},
    {cryptic_core, {path, "../cryptic_core"}},
    {cowboy, "2.12.0"},
    {gun, "2.1.0"},
    {jsone, "1.8.1"}
]}.

{relx, [
    {release, {cryptic_server, "0.1.0"},
     [cryptic_server,
      sasl,
      runtime_tools]},
    
    {mode, dev},
    
    {sys_config, "./config/sys.config"},
    {vm_args, "./config/vm.args"},
    
    {dev_mode, true},
    {include_erts, false},
    
    {extended_start_script, true},
    {extended_start_script_hooks, [
        {pre_start, [{custom, "hooks/pre_start"}]},
        {post_start, [{custom, "hooks/post_start"}]}
    ]},
    
    {overlay, [
        {mkdir, "log/sasl"},
        {copy, "priv/server_certs", "priv/server_certs"}
    ]}
]}.

{profiles, [
    {prod, [
        {relx, [
            {mode, prod},
            {dev_mode, false},
            {include_erts, true},
            {include_src, false}
        ]}
    ]}
]}.
```

### apps/cryptic_console/rebar.config

```erlang
{erl_opts, [debug_info, warnings_as_errors]}.

{deps, [
    {cryptic_lib, {path, "../cryptic_lib"}},
    {cryptic_core, {path, "../cryptic_core"}},
    {gun, "2.1.0"},
    {jsone, "1.8.1"}
]}.

{escript_incl_apps, [
    cryptic_console,
    cryptic_core,
    cryptic_lib,
    gun,
    cowlib,
    jsone
]}.

{escript_main_app, cryptic_console}.
{escript_name, cryptic_console}.
{escript_emu_args, "%%! +sbtu +A1\n"}.

{escript_comment, "Cryptic Console Client"}.
```

### apps/cryptic_ncurses/rebar.config

```erlang
{erl_opts, [debug_info, warnings_as_errors]}.

{deps, [
    {cryptic_lib, {path, "../cryptic_lib"}},
    {cryptic_core, {path, "../cryptic_core"}},
    {gun, "2.1.0"},
    {jsone, "1.8.1"}
]}.

{escript_incl_apps, [
    cryptic_ncurses,
    cryptic_core,
    cryptic_lib,
    gun,
    cowlib,
    jsone
]}.

{escript_main_app, cryptic_ncurses}.
{escript_name, cryptic_ncurses}.
{escript_emu_args, "%%! +sbtu +A1\n"}.
```

## Migration Plan

### Phase 1: Preparation (Week 1)

**Goal:** Create structure without moving code

**Tasks:**
1. ✅ Create this planning document
2. Create `apps/` directory structure
3. Create skeleton `rebar.config` files for each app
4. Create `.app.src` files for each application
5. Update root `rebar.config` for umbrella structure
6. Test that `rebar3 compile` works (even with empty apps)

**Verification:**
```bash
rebar3 tree          # Should show dependency graph
rebar3 compile       # Should compile (but no modules yet)
```

### Phase 2: Move cryptic_lib (Week 1-2)

**Goal:** Extract pure library code first (least dependencies)

**Modules to Move:**
- `cryptic_lib.erl`
- `cryptic_nif.erl`
- `cryptic_messages.erl` (if exists)
- Any utility modules

**Files to Move:**
- `c_src/*` → `apps/cryptic_lib/c_src/`
- `include/cryptic.hrl` → `apps/cryptic_lib/include/`
- `include/cryptic_ansi.hrl` → `apps/cryptic_lib/include/`

**Tasks:**
1. Move modules to `apps/cryptic_lib/src/`
2. Move C source to `apps/cryptic_lib/c_src/`
3. Move headers to `apps/cryptic_lib/include/`
4. Update NIF loading paths
5. Compile and verify NIF loads correctly
6. Update any include directives in moved modules

**Verification:**
```bash
rebar3 compile --app=cryptic_lib
rebar3 eunit --app=cryptic_lib
```

**Rollback Plan:** Git branch, can revert if issues

### Phase 3: Move cryptic_core (Week 2)

**Goal:** Extract core engine logic

**Modules to Move:**
- `cryptic_engine.erl`
- `cryptic_ratchet_engine.erl`
- `cryptic_double_ratchet.erl`
- `cryptic_key_ratchet.erl`
- `cryptic_chat_storage.erl`
- `cryptic_event_manager.erl`
- `cryptic_console_logger.erl`
- `cryptic_file_logger.erl`
- `cryptic_msg_logger.erl`

**Tests to Move:**
- `test/cryptic_double_ratchet_*_test.erl`
- `test/cryptic_key_ratchet_test.erl`
- `test/cryptic_engine_*_test.erl`

**Tasks:**
1. Move modules to `apps/cryptic_core/src/`
2. Move tests to `apps/cryptic_core/test/`
3. Update include paths (may need `../../cryptic_lib/include/`)
4. Update rebar.config dependency on cryptic_lib
5. Run all tests

**Verification:**
```bash
rebar3 compile --app=cryptic_core
rebar3 eunit --app=cryptic_core
rebar3 ct --app=cryptic_core
```

### Phase 4: Move cryptic_server (Week 3)

**Goal:** Extract server application

**Modules to Move:**
- `cryptic_server.erl`
- `cryptic_server_app.erl` (may need to create)
- `cryptic_server_sup.erl` (may need to create)
- `cryptic_ws_handler.erl`
- `cryptic_room_manager.erl`
- `cryptic_room_handlers.erl`

**Tests to Move:**
- Server-specific tests

**Configuration:**
- Create `apps/cryptic_server/config/sys.config`
- Create `apps/cryptic_server/config/vm.args`
- Set up relx configuration

**Tasks:**
1. Create application callback module if needed
2. Create supervisor module if needed
3. Move server modules to `apps/cryptic_server/src/`
4. Move server tests to `apps/cryptic_server/test/`
5. Configure release with relx
6. Test release build

**Verification:**
```bash
rebar3 compile --app=cryptic_server
rebar3 release
_build/default/rel/cryptic_server/bin/cryptic_server console
```

### Phase 5: Move cryptic_console (Week 3-4)

**Goal:** Extract console client

**Modules to Move:**
- `cryptic_console.erl`
- `cryptic_console_callbacks.erl`
- `cryptic_shell.erl`
- `cryptic_ws_client.erl`
- `cryptic_client_lib.erl`

**Scripts to Update:**
- `scripts/cryptic_console` (or `bin/cryptic`)

**Tasks:**
1. Move console modules to `apps/cryptic_console/src/`
2. Configure escript build
3. Update launcher script
4. Test escript build and execution

**Verification:**
```bash
rebar3 escriptize --app=cryptic_console
_build/default/bin/cryptic_console --help
_build/default/bin/cryptic_console --username alice
```

### Phase 6: Move cryptic_ncurses (Week 4)

**Goal:** Extract NCurses UI client

**Modules to Move:**
- `cryptic_ws_ui.erl`
- `cryptic_ui_screen.erl`
- Related modules

**Tasks:**
1. Move NCurses modules to `apps/cryptic_ncurses/src/`
2. Configure escript or release build
3. Test build

**Note:** May defer this if not actively developed

### Phase 7: Cleanup and Documentation (Week 4-5)

**Goal:** Remove old structure, update documentation

**Tasks:**
1. Remove old `src/` directory (verify nothing left behind)
2. Remove old `include/` directory
3. Update `README.md` with new structure
4. Update build instructions
5. Update deployment documentation
6. Create architecture diagram
7. Update CI/CD pipelines
8. Tag release `v0.2.0-umbrella`

**Documentation Updates:**
- `README.md` - Build and run instructions
- `docs/architecture.md` - New structure overview
- `docs/development.md` - Developer guide
- `docs/deployment.md` - Deployment guide

## Build Commands Reference

### Development

```bash
# Compile everything
rebar3 compile

# Compile specific app
rebar3 compile --app=cryptic_lib
rebar3 compile --app=cryptic_core
rebar3 compile --app=cryptic_server
rebar3 compile --app=cryptic_console

# Run tests
rebar3 eunit                          # All unit tests
rebar3 eunit --app=cryptic_core       # Specific app
rebar3 ct                             # Common test
rebar3 dialyzer                       # Type checking

# Clean
rebar3 clean
rebar3 clean --all                    # Include dependencies
```

### Server Deployment

```bash
# Development release
rebar3 release
_build/default/rel/cryptic_server/bin/cryptic_server console

# Production release
rebar3 as prod release
rebar3 as prod tar

# Deploy tarball
scp _build/prod/rel/cryptic_server/cryptic_server-0.1.0.tar.gz server:/opt/
```

### Client Build

```bash
# Build console escript
rebar3 escriptize --app=cryptic_console

# Run it
_build/default/bin/cryptic_console --username alice --server ws://localhost:8080

# Install locally
cp _build/default/bin/cryptic_console ~/bin/cryptic
```

## Include Path Resolution

After restructuring, include directives need updating:

### Before (Monolithic)
```erlang
-include("cryptic.hrl").
-include("cryptic_ansi.hrl").
```

### After (Umbrella)

**In cryptic_lib modules:**
```erlang
-include("cryptic.hrl").
-include("cryptic_ansi.hrl").
```

**In cryptic_core modules:**
```erlang
-include_lib("cryptic_lib/include/cryptic.hrl").
-include_lib("cryptic_lib/include/cryptic_ansi.hrl").
```

**In cryptic_server modules:**
```erlang
-include_lib("cryptic_lib/include/cryptic.hrl").
-include_lib("cryptic_core/include/cryptic_core.hrl").  % If needed
```

**In cryptic_console modules:**
```erlang
-include_lib("cryptic_lib/include/cryptic.hrl").
-include_lib("cryptic_lib/include/cryptic_ansi.hrl").
```

## Testing Strategy

### Unit Tests
- Each app has its own `test/` directory
- Run per-app: `rebar3 eunit --app=cryptic_core`
- Run all: `rebar3 eunit`

### Integration Tests
- Keep in root `test/` directory
- Test cross-app interactions
- Run with: `rebar3 ct`

### Manual Testing Checklist

After each phase:
- [ ] All apps compile without warnings
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Server starts and accepts connections
- [ ] Console client connects and sends messages
- [ ] NCurses client works (if applicable)
- [ ] Certificate generation works
- [ ] Message encryption/decryption works
- [ ] Ratchet state advances correctly

## Risk Assessment

### High Risk
1. **NIF loading paths** - May break if paths change
   - Mitigation: Test thoroughly, update NIF loading code
   
2. **Include file paths** - Many modules include headers
   - Mitigation: Use find/replace, compile incrementally

3. **ETS table access** - Cross-app table access may break
   - Mitigation: Review all ETS usage, ensure proper ownership

### Medium Risk
1. **Test failures** - Tests may reference old paths
   - Mitigation: Update test paths incrementally

2. **Configuration files** - sys.config paths may need updates
   - Mitigation: Review all config files

### Low Risk
1. **Documentation** - Will be outdated
   - Mitigation: Update docs in final phase

## Rollback Strategy

Each phase is in a separate git branch:
- `feature/umbrella-phase1-preparation`
- `feature/umbrella-phase2-lib`
- `feature/umbrella-phase3-core`
- `feature/umbrella-phase4-server`
- `feature/umbrella-phase5-console`
- `feature/umbrella-phase6-ncurses`
- `feature/umbrella-phase7-cleanup`

If any phase fails:
1. Identify the issue
2. Fix if quick (<1 day)
3. Otherwise revert to previous branch
4. Analyze and update plan
5. Retry with updated approach

## Success Criteria

The restructuring is successful when:

1. ✅ All apps compile without errors or warnings
2. ✅ All tests pass (unit + integration)
3. ✅ Server can be deployed as standalone release
4. ✅ Console can be built as standalone escript
5. ✅ CI/CD pipeline works with new structure
6. ✅ Documentation is updated and accurate
7. ✅ Development workflow is equal or better than before
8. ✅ Build times are equal or better
9. ✅ Can run `rebar3 tree` to visualize dependencies
10. ✅ Each component can be developed independently

## Future Enhancements

After successful restructuring:

1. **Hex Packages** - Publish cryptic_lib to hex.pm
2. **Docker Images** - Separate images for server/client
3. **Multi-node Support** - Distributed server setup
4. **Plugin Architecture** - Third-party client plugins
5. **Mobile Clients** - iOS/Android using cryptic_lib
6. **Web Client** - Browser-based using WebAssembly + cryptic_lib

## Questions and Decisions

### Open Questions

1. **Q:** Should cryptic_lib include ANSI codes?
   - **A:** Yes, but consider moving to cryptic_ui_lib if we create UI-specific shared code

2. **Q:** Where should shared test utilities go?
   - **A:** Root `test/` directory, or create `apps/cryptic_test_utils/`

3. **Q:** How to handle shared configuration?
   - **A:** Keep in `config/` at root, each app can override

4. **Q:** Should we use git submodules or path dependencies?
   - **A:** Path dependencies (simpler for monorepo)

### Decisions Made

1. **Decision:** Use umbrella project (not separate repos)
   - **Rationale:** Easier development, atomic changes across apps

2. **Decision:** cryptic_core is a library, not a standalone app
   - **Rationale:** Shared by server and clients

3. **Decision:** Keep CA/ in root
   - **Rationale:** Shared resource, not app-specific

4. **Decision:** Phase-by-phase migration
   - **Rationale:** Lower risk, easier to debug

## Timeline Estimate

| Phase | Duration | Calendar | Notes |
|-------|----------|----------|-------|
| Phase 1: Preparation | 2-3 days | Week 1 | Low risk |
| Phase 2: cryptic_lib | 2-3 days | Week 1-2 | Medium risk (NIF) |
| Phase 3: cryptic_core | 3-4 days | Week 2 | Medium risk (many deps) |
| Phase 4: cryptic_server | 2-3 days | Week 3 | Medium risk (release config) |
| Phase 5: cryptic_console | 2-3 days | Week 3-4 | Low risk |
| Phase 6: cryptic_ncurses | 1-2 days | Week 4 | Low priority |
| Phase 7: Cleanup | 2-3 days | Week 4-5 | Documentation |
| **Total** | **14-21 days** | **4-5 weeks** | With buffer |

*Note: Timeline assumes part-time work; full-time could complete in 2-3 weeks*

## References

- [Rebar3 Releases](https://www.rebar3.org/docs/releases)
- [OTP Design Principles](https://www.erlang.org/doc/design_principles/users_guide.html)
- [Erlang App Structure](https://www.erlang.org/doc/design_principles/applications.html)
- [Umbrella Projects](https://www.rebar3.org/docs/configuration/dependencies#path-dependencies)

## Approval and Sign-off

- [ ] Plan reviewed by development team
- [ ] Timeline approved
- [ ] Risk assessment acknowledged
- [ ] Ready to proceed with Phase 1

---

**Next Steps:**
1. Review this plan
2. Discuss any concerns or modifications
3. Get team approval
4. Create feature branch
5. Start Phase 1
