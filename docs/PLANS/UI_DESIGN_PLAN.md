# Cryptic Chat Terminal UI Design Plan

## Overview
Design a professional terminal-based chat interface using `cecho` (ncurses) that provides real-time messaging with a clean, intuitive layout.

## Screen Layout

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ CRYPTIC CHAT | Server: localhost:8080 | User: alice | Messages: 3 | 14:30:25 │ ← Status Bar
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ <bob>: Hey Alice, how are you doing?                              [14:25:10] │
│ <alice>: I'm doing great! Thanks for asking.                     [14:26:42] │
│ <charlie>: Anyone up for lunch today?                            [14:28:15] │
│                                                                             │ ← Message Area
│                                                                             │   (scrollable)
│                                                                             │
│                                                                             │
│                                                                             │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│ Commands: help | register <user> | send <user> <msg> | inbox | quit        │ ← Help Bar
├─────────────────────────────────────────────────────────────────────────────┤
│ > send bob Hello there!_                                                    │ ← Input Line
└─────────────────────────────────────────────────────────────────────────────┘
```

## UI Components

### 1. Status Bar (Top Line)
- **Position**: Line 0 (top)
- **Content**: 
  - App name: "CRYPTIC CHAT"
  - Server URL
  - Current username (or "Not logged in")
  - Unread message count
  - Current time
- **Colors**: White text on blue background
- **Updates**: Real-time (time every second, message count on new messages)

### 2. Message Display Area
- **Position**: Lines 1 to (height-4)
- **Features**:
  - Scrollable message history
  - Color-coded messages by sender
  - Timestamps for each message
  - Auto-scroll to bottom on new messages
  - Ability to scroll up/down through history
- **Message Format**: `<username>: message [HH:MM:SS]`
- **Colors**:
  - Own messages: Green text
  - Other messages: Cyan text
  - System messages: Yellow text
  - Timestamps: Dark gray

### 3. Help/Command Bar
- **Position**: Line (height-3)
- **Content**: Quick reference for common commands
- **Colors**: White text on dark gray background
- **Static content** (doesn't change during session)

### 4. Input Line
- **Position**: Line (height-1) (bottom)
- **Features**:
  - Command prompt: "> "
  - Real-time typing
  - Command history (up/down arrows)
  - Tab completion for usernames
  - Line editing (backspace, cursor movement)
- **Colors**: White text on black background

## Key Features

### Real-time Updates
1. **Message Polling**: Background polling every 2 seconds when enabled
2. **Status Updates**: Time updates every second
3. **Instant Display**: New messages appear immediately without user input
4. **Non-blocking Input**: User can type while messages are being received

### User Interaction
1. **Keyboard Navigation**:
   - `Enter`: Send command/message
   - `Up/Down`: Command history
   - `Page Up/Page Down`: Scroll message history
   - `Ctrl+C`: Quit application
   - `Tab`: Username completion (future enhancement)

2. **Commands**:
   - `register <username>`: Register new user
   - `send <user> <message>`: Send message
   - `inbox`: Check messages manually
   - `list_users`: Show available users
   - `polling on/off`: Enable/disable auto-polling
   - `clear`: Clear message display
   - `help`: Show help
   - `quit`: Exit application

### Visual Design
1. **Color Scheme**:
   - Status bar: Blue background, white text
   - Message area: Black background
   - Own messages: Green text
   - Other messages: Cyan text
   - System messages: Yellow text
   - Help bar: Dark gray background, white text
   - Input line: Black background, white text

2. **Borders**: Simple ASCII box drawing characters
3. **Responsive**: Adapts to terminal resize

## Implementation Phases

### Phase 1: Basic Layout
- Initialize cecho
- Create static layout with status bar, message area, help bar, input line
- Basic window management and drawing

### Phase 2: Message Display
- Implement message display area
- Add scrolling functionality
- Color-coded message rendering
- Timestamp formatting

### Phase 3: Input Handling
- Non-blocking input system
- Command parsing and execution
- Integration with existing cryptic_client_lib functions

### Phase 4: Real-time Features
- Background message polling
- Live status updates
- Automatic message display

### Phase 5: Enhanced Features
- Command history
- Message history scrolling
- Username tab completion
- Terminal resize handling

## Technical Architecture

### Main Process Structure
```erlang
cryptic_cecho_ui:start() ->
    %% Initialize cecho
    %% Start input handler process
    %% Start status updater process
    %% Start message poller process
    %% Enter main UI loop
```

### Process Communication
- **Main UI Process**: Handles screen updates and coordination
- **Input Handler**: Captures keyboard input, sends to main process
- **Status Updater**: Updates time and status information
- **Message Poller**: Checks for new messages when polling enabled

### State Management
```erlang
-record(ui_state, {
    chat_state,           % existing chat state
    screen_height,        % terminal dimensions
    screen_width,
    message_history,      % displayed messages
    scroll_position,      % current scroll offset
    command_history,      % previous commands
    current_input         % current input line
}).
```

This design provides a professional, user-friendly terminal interface that maintains the real-time messaging capabilities while offering a much better user experience than the current line-based interface.
