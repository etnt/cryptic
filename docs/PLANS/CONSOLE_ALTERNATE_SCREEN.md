# Console Alternate Screen Feature

## Overview

The Cryptic console now displays engine status information on the alternate screen buffer. This keeps the main message display area clean and uncluttered by system information.

## What is Alternate Screen?

The alternate screen buffer is a feature of terminal emulators that allows applications to:
- Switch to a separate display buffer
- Show information without scrolling the main screen
- Return to the original screen state when done

Common examples: `vim`, `less`, `top`, `htop` all use alternate screen.

## Implementation

### ANSI Escape Sequences

We use ANSI escape codes defined in `include/cryptic_ansi.hrl`:

```erlang
-define(ALT_SCREEN_ON,  "\e[?1049h").  % Switch to alternate screen
-define(ALT_SCREEN_OFF, "\e[?1049l").  % Return to main screen
```

### Engine Status Display

When you run the `engine_status` command:

1. **Switch to alternate screen:** Terminal clears and shows a fresh buffer
2. **Display status:** Formatted engine information with colors and borders
3. **Wait for input:** "Press any key to return..." prompt
4. **Return to main screen:** Your conversation history is exactly as you left it

### Visual Layout

```
╔═══════════════════════════════════════════════════════════════╗
║              CRYPTIC ENGINE STATUS                            ║
╚═══════════════════════════════════════════════════════════════╝

  Username:         alice
  Active Sessions:  1
  Messages Sent:    5
  Errors:           0
  Uptime:           2 minutes, 34 seconds

Active Ratchet Sessions:
─────────────────────────────────────────────────────────────────
  bob: Step 6, Chain[1 init, 1 resp], Prev[1 msgs], Skipped[0 keys]


Press any key to return...
```

### Color Coding

- **Cyan:** Section headers and peer usernames
- **Green:** Normal status values
- **Yellow:** DH ratchet steps and warning indicators
- **Red:** Error counts when > 0
- **Bold:** Borders and section titles

## Benefits

### 1. Clean Message Display
- Engine status doesn't clutter your conversation
- Messages remain visible and scrollable
- Clear separation between chat and system info

### 2. Better User Experience
- Full-screen display for complex information
- Easy to read with borders and formatting
- No accidental scrolling past important status

### 3. Terminal-Friendly
- Works with any ANSI-compatible terminal
- Preserves terminal state
- Returns you exactly where you were

## Code Location

- **Implementation:** `src/cryptic_console.erl`
  - `show_engine_status/1` - Main function (lines ~429-507)
  - `format_session_info_alt/1` - Alternate screen session formatter (lines ~526-549)
  
- **ANSI Codes:** `include/cryptic_ansi.hrl`
  - `?ALT_SCREEN_ON` - Line 32
  - `?ALT_SCREEN_OFF` - Line 33

## Usage

Simply run the command:

```
cryptic> engine_status
```

The screen will:
1. Switch to alternate buffer
2. Show formatted status
3. Wait for any keypress
4. Return to your conversation

## Compatibility

Works with all modern terminal emulators that support ANSI escape sequences:
- macOS Terminal
- iTerm2
- Linux terminals (xterm, gnome-terminal, konsole, etc.)
- Windows Terminal
- Most SSH clients

## Future Enhancements

Potential improvements:
- Real-time status updates (refresh every second)
- Interactive navigation through sessions
- Detailed per-session statistics view
- Export status to file
- Comparison view (before/after states)

## Technical Notes

### Why Alternate Screen?

Before this feature, running `engine_status` would output 10-20 lines of text directly to the console, pushing your conversation history up and making it harder to follow ongoing chats.

With alternate screen:
- Status is shown in isolation
- Your conversation remains untouched
- Return is instantaneous and clean

### Implementation Details

The function uses direct `io:format/1` calls instead of `cryptic_shell` functions because:
- Alternate screen doesn't integrate with the shell's message buffering
- We want immediate, synchronous output
- The display is temporary and non-interactive

### Error Handling

If `get_engine_status/1` fails, the error is also shown on the alternate screen with appropriate formatting, ensuring consistent user experience.

## Related Files

- `src/cryptic_console.erl` - Console implementation
- `src/cryptic_engine.erl` - Engine status gathering
- `include/cryptic_ansi.hrl` - ANSI escape code definitions
- `docs/DH_RATCHET_STEP_EXPLAINED.md` - Explanation of DH step counter
