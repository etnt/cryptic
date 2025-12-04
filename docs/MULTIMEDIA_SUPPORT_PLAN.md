# Cryptic Multimedia Support Plan
## File, Audio, and Video Transfer Implementation

**Document Version**: 1.0  
**Created**: December 2025  
**Status**: Planning Phase

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Current Architecture Analysis](#current-architecture-analysis)
3. [Design Principles](#design-principles)
4. [Technical Specification](#technical-specification)
5. [Implementation Phases](#implementation-phases)
6. [Security Considerations](#security-considerations)
7. [Performance & Scalability](#performance--scalability)
8. [API Reference](#api-reference)
9. [Testing Strategy](#testing-strategy)
10. [Migration Path](#migration-path)

---

## Executive Summary

This plan outlines the implementation of end-to-end encrypted file, audio, and video transfer capabilities in Cryptic, maintaining the existing security guarantees (X3DH + Double Ratchet) while adding support for large binary transfers.

### Key Goals
- **Maintain E2E Encryption**: All multimedia content encrypted with Double Ratchet
- **Chunked Transfer**: Support large files without memory exhaustion
- **Progressive Delivery**: Stream audio/video with minimal latency
- **Backward Compatibility**: Existing text messaging unaffected
- **Storage Integration**: Encrypted at-rest storage in SQLite database
- **Resume Capability**: Handle interrupted transfers gracefully

### Design Philosophy
- Reuse existing crypto stack (no new protocols)
- Leverage event bus architecture for progress notifications
- Keep WebSocket message protocol JSON-based with binary payloads
- Store metadata separately from chunks for efficient queries

---

## Current Architecture Analysis

### Existing Message Flow

```
User Input → Engine (Encrypt) → WebSocket Client → Server → WebSocket Handler → Recipient
```

### Current Limitations

1. **Message Size**: Text messages encrypted as single units
2. **Storage Schema**: `message_type TEXT DEFAULT 'text'` only supports text
3. **WebSocket Frames**: JSON text frames, binary frames marked as "NYI" (Not Yet Implemented)
4. **Memory**: No chunking mechanism for large payloads

### Existing Assets to Leverage

✅ **Double Ratchet Encryption** - Already handles arbitrary binary data  
✅ **Event Bus** - Can publish progress events  
✅ **Storage Module** - `cryptic_chat_storage` with `message_type` field  
✅ **WebSocket Infrastructure** - Supports both text and binary frames  
✅ **Callback Architecture** - Can add new callbacks for transfer progress

---

## Design Principles

### 1. **Encryption-First**
Every chunk encrypted individually with Double Ratchet for forward secrecy. File metadata encrypted separately.

### 2. **Chunked Transfer**
```
File → Chunks (64KB each) → Encrypt Each → Transfer → Decrypt → Reassemble
```

### 3. **Metadata-Driven**
File transfer starts with metadata message:
```json
{
  "type": "file_init",
  "file_id": "uuid",
  "filename": "encrypted_filename",
  "mime_type": "application/octet-stream",
  "size": 1048576,
  "chunk_count": 16,
  "checksum": "sha256_hash"
}
```

### 4. **Event-Driven Progress**
```erlang
#{
    type => file_transfer_progress,
    file_id => <<"uuid">>,
    chunk => 5,
    total_chunks => 16,
    bytes_transferred => 327680
}
```

---

## Technical Specification

### Message Type Extensions

#### A. Text Message (Existing)
```erlang
#{
    type => deliver_message,
    from => <<"alice">>,
    message => <<"Hello!">>,
    timestamp => {1638, 123456, 789012}
}
```

#### B. File Transfer Initiation
```erlang
#{
    type => file_init,
    message_id => <<"uuid-1234">>,
    from => <<"alice">>,
    to => <<"bob">>,
    file_id => <<"file-uuid-5678">>,
    encrypted_metadata => <<...>>  % Contains: filename, mime_type, size, checksum
}
```

**Encrypted Metadata Structure**:
```erlang
#{
    filename => <<"vacation.jpg">>,
    mime_type => <<"image/jpeg">>,
    size_bytes => 2048576,
    chunk_size => 65536,
    total_chunks => 32,
    checksum_algorithm => <<"sha256">>,
    checksum => <<...32 bytes...>>
}
```

#### C. File Chunk Transfer
```erlang
#{
    type => file_chunk,
    message_id => <<"uuid-chunk-1">>,
    file_id => <<"file-uuid-5678">>,
    chunk_index => 0,
    total_chunks => 32,
    encrypted_chunk => <<...>>  % Encrypted with ratchet
}
```

#### D. File Transfer Complete
```erlang
#{
    type => file_complete,
    file_id => <<"file-uuid-5678">>,
    chunk_count => 32,
    final_checksum => <<...>>
}
```

#### E. File Transfer Error
```erlang
#{
    type => file_error,
    file_id => <<"file-uuid-5678">>,
    error => <<"checksum_mismatch | timeout | disk_full">>
}
```

### Audio/Video Streaming Extensions

For real-time audio/video, use same chunking but with priority flags:

```erlang
#{
    type => stream_chunk,
    stream_id => <<"stream-uuid">>,
    media_type => <<"audio | video">>,
    codec => <<"opus | h264">>,
    sequence => 42,
    timestamp_ms => 1680,
    encrypted_chunk => <<...>>,
    priority => high  % Skip retry logic for real-time
}
```

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)

#### 1.1 Database Schema Updates

**File**: `src/cryptic_chat_storage.erl`

Add new table for file metadata:
```sql
CREATE TABLE file_transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL UNIQUE,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    server_host TEXT NOT NULL,
    server_port INTEGER NOT NULL,
    encrypted_metadata BLOB NOT NULL,
    salt BLOB NOT NULL,
    nonce BLOB NOT NULL,
    total_chunks INTEGER NOT NULL,
    chunks_received INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending', -- pending, downloading, complete, failed
    checksum BLOB,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    completed_at INTEGER,
    error_message TEXT
);

CREATE INDEX idx_file_transfers_status ON file_transfers(status);
CREATE INDEX idx_file_transfers_users ON file_transfers(from_user, to_user);
```

Add chunk storage table:
```sql
CREATE TABLE file_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    encrypted_chunk BLOB NOT NULL,
    salt BLOB NOT NULL,
    nonce BLOB NOT NULL,
    received_at INTEGER DEFAULT (strftime('%s', 'now')),
    UNIQUE(file_id, chunk_index),
    FOREIGN KEY(file_id) REFERENCES file_transfers(file_id) ON DELETE CASCADE
);

CREATE INDEX idx_file_chunks_file_id ON file_chunks(file_id, chunk_index);
```

Update message_type enum:
```sql
-- Modify encrypted_messages table
ALTER TABLE encrypted_messages 
  ADD COLUMN file_id TEXT DEFAULT NULL;
  
-- New message types: 'text', 'file', 'audio', 'video', 'stream'
```

#### 1.2 Core File Transfer Module

**File**: `src/cryptic_file_transfer.erl`

```erlang
-module(cryptic_file_transfer).

-export([
    %% Sender API
    send_file/4,           % (EnginePid, ToUser, FilePath, Options) -> {ok, FileId}
    cancel_transfer/2,     % (EnginePid, FileId) -> ok
    
    %% Receiver API
    accept_file/3,         % (EnginePid, FileId, SavePath) -> ok
    reject_file/2,         % (EnginePid, FileId) -> ok
    
    %% Progress Monitoring
    get_transfer_status/2, % (EnginePid, FileId) -> {ok, Status}
    list_active_transfers/1 % (EnginePid) -> {ok, [FileId]}
]).

%% Chunk size: 64KB (optimal for most networks)
-define(DEFAULT_CHUNK_SIZE, 65536).
-define(MAX_FILE_SIZE, 1073741824). % 1GB limit
```

Key functions:

```erlang
send_file(EnginePid, ToUser, FilePath, Options) ->
    %% 1. Read file metadata
    {ok, FileInfo} = file:read_file_info(FilePath),
    Size = FileInfo#file_info.size,
    
    %% 2. Generate file_id
    FileId = generate_file_id(),
    
    %% 3. Calculate chunks
    ChunkSize = maps:get(chunk_size, Options, ?DEFAULT_CHUNK_SIZE),
    TotalChunks = ceil(Size / ChunkSize),
    
    %% 4. Compute checksum
    {ok, Checksum} = compute_file_checksum(FilePath),
    
    %% 5. Create encrypted metadata
    Metadata = #{
        filename => filename:basename(FilePath),
        mime_type => guess_mime_type(FilePath),
        size_bytes => Size,
        chunk_size => ChunkSize,
        total_chunks => TotalChunks,
        checksum_algorithm => <<"sha256">>,
        checksum => Checksum
    },
    
    %% 6. Send file_init message
    gen_server:call(EnginePid, {
        send_file_init,
        ToUser,
        FileId,
        Metadata
    }),
    
    %% 7. Spawn chunk sender process
    spawn_chunk_sender(EnginePid, ToUser, FileId, FilePath, ChunkSize, TotalChunks),
    
    {ok, FileId}.
```

#### 1.3 WebSocket Protocol Extensions

**File**: `src/cryptic_ws_handler.erl`

Handle new message types in `websocket_handle/2`:

```erlang
handle_command(#{<<"type">> := <<"file_init">>} = Message, State) ->
    FromUser = maps:get(username, State),
    ToUser = maps:get(<<"to">>, Message),
    FileId = maps:get(<<"file_id">>, Message),
    EncryptedMetadata = maps:get(<<"encrypted_metadata">>, Message),
    
    %% Store pending file transfer
    cryptic_server:store_pending_file(ToUser, FileId, EncryptedMetadata),
    
    %% Forward to recipient if online
    case lookup_user_connection(binary_to_list(ToUser)) of
        {ok, Pid} ->
            Pid ! {file_init, FromUser, FileId, EncryptedMetadata},
            {ok, State};
        {error, not_found} ->
            %% Store for later delivery
            {ok, State}
    end;

handle_command(#{<<"type">> := <<"file_chunk">>} = Message, State) ->
    FileId = maps:get(<<"file_id">>, Message),
    ChunkIndex = maps:get(<<"chunk_index">>, Message),
    EncryptedChunk = base64:decode(maps:get(<<"encrypted_chunk">>, Message)),
    
    %% Forward chunk to recipient
    ToUser = get_file_recipient(FileId),
    case lookup_user_connection(ToUser) of
        {ok, Pid} ->
            Pid ! {file_chunk, FileId, ChunkIndex, EncryptedChunk},
            
            %% Send acknowledgment
            AckMsg = #{
                <<"type">> => <<"chunk_ack">>,
                <<"file_id">> => FileId,
                <<"chunk_index">> => ChunkIndex
            },
            {reply, {text, jsx:encode(AckMsg)}, State};
        _ ->
            {ok, State}
    end.
```

### Phase 2: Engine Integration (Weeks 3-4)

#### 2.1 Engine Callbacks

**File**: `src/cryptic_engine.erl`

Add new callback behavior:

```erlang
-callback file_transfer_progress(
    FileId :: binary(),
    Progress :: #{
        chunk => non_neg_integer(),
        total_chunks => non_neg_integer(),
        bytes_transferred => non_neg_integer(),
        status => pending | downloading | complete | failed
    },
    Context :: map()
) -> {ok, UpdatedContext} | {error, Reason, Context}.
```

Add handlers for file messages:

```erlang
handle_call({send_file_init, ToUser, FileId, Metadata}, _From, State) ->
    %% Encrypt metadata with Double Ratchet
    MetadataBinary = term_to_binary(Metadata),
    {ok, EncryptedMetadata, NewState} = 
        encrypt_for_peer(ToUser, MetadataBinary, State),
    
    %% Publish to event bus
    cryptic_event_bus:publish(#{
        type => websocket_outbound,
        message => #{
            <<"type">> => <<"file_init">>,
            <<"to">> => ToUser,
            <<"file_id">> => FileId,
            <<"encrypted_metadata">> => base64:encode(EncryptedMetadata)
        }
    }),
    
    {reply, ok, NewState};

handle_info({file_chunk, FileId, ChunkIndex, EncryptedChunk}, State) ->
    %% Decrypt chunk
    case decrypt_chunk(EncryptedChunk, State) of
        {ok, PlaintextChunk, NewState} ->
            %% Store chunk
            store_file_chunk(FileId, ChunkIndex, PlaintextChunk),
            
            %% Publish progress event
            cryptic_event_bus:publish(#{
                type => file_transfer_progress,
                file_id => FileId,
                chunk => ChunkIndex,
                status => downloading
            }),
            
            {noreply, NewState};
        {error, Reason, State} ->
            %% Handle decryption error
            {noreply, State}
    end.
```

#### 2.2 Chunk Sender Process

**File**: `src/cryptic_chunk_sender.erl`

```erlang
-module(cryptic_chunk_sender).
-behaviour(gen_server).

%% State
-record(state, {
    engine_pid :: pid(),
    to_user :: binary(),
    file_id :: binary(),
    file_handle :: file:fd(),
    chunk_size :: pos_integer(),
    current_chunk :: non_neg_integer(),
    total_chunks :: non_neg_integer(),
    pending_acks :: #{non_neg_integer() => reference()},
    retry_limit :: pos_integer()
}).

init([EnginePid, ToUser, FileId, FilePath, ChunkSize, TotalChunks]) ->
    {ok, FileHandle} = file:open(FilePath, [read, binary]),
    
    State = #state{
        engine_pid = EnginePid,
        to_user = ToUser,
        file_id = FileId,
        file_handle = FileHandle,
        chunk_size = ChunkSize,
        current_chunk = 0,
        total_chunks = TotalChunks,
        pending_acks = #{},
        retry_limit = 3
    },
    
    %% Start sending chunks
    self() ! send_next_chunk,
    
    {ok, State}.

handle_info(send_next_chunk, #state{current_chunk = Current, total_chunks = Total} = State) 
  when Current < Total ->
    %% Read chunk from file
    {ok, ChunkData} = file:pread(
        State#state.file_handle,
        Current * State#state.chunk_size,
        State#state.chunk_size
    ),
    
    %% Send to engine for encryption
    gen_server:cast(State#state.engine_pid, {
        send_file_chunk,
        State#state.to_user,
        State#state.file_id,
        Current,
        Total,
        ChunkData
    }),
    
    %% Set timeout for acknowledgment
    Timer = erlang:send_after(5000, self(), {chunk_timeout, Current}),
    
    NewState = State#state{
        current_chunk = Current + 1,
        pending_acks = maps:put(Current, Timer, State#state.pending_acks)
    },
    
    {noreply, NewState};

handle_info({chunk_ack, ChunkIndex}, State) ->
    %% Cancel timeout
    case maps:find(ChunkIndex, State#state.pending_acks) of
        {ok, Timer} ->
            erlang:cancel_timer(Timer),
            NewAcks = maps:remove(ChunkIndex, State#state.pending_acks),
            
            %% If all chunks sent and acknowledged
            case State#state.current_chunk == State#state.total_chunks andalso
                 maps:size(NewAcks) == 0 of
                true ->
                    file:close(State#state.file_handle),
                    send_file_complete(State),
                    {stop, normal, State};
                false ->
                    self() ! send_next_chunk,
                    {noreply, State#state{pending_acks = NewAcks}}
            end;
        error ->
            {noreply, State}
    end.
```

### Phase 3: UI Integration (Weeks 5-6)

#### 3.1 Console UI Updates

**File**: `src/cryptic_console.erl`

Add commands:
```erlang
"/send-file <username> <filepath>"
"/accept-file <file_id> <save_path>"
"/reject-file <file_id>"
"/list-files"
```

Event handlers:
```erlang
handle_info({event, #{type := file_transfer_progress, 
                      file_id := FileId,
                      chunk := Chunk,
                      total_chunks := Total}}, State) ->
    Percentage = (Chunk / Total) * 100,
    cryptic_shell:print_info(io_lib:format(
        "File ~s: ~.1f% (~p/~p chunks)",
        [FileId, Percentage, Chunk, Total]
    )),
    {noreply, State};

handle_info({event, #{type := file_init,
                      from := From,
                      file_id := FileId,
                      filename := Filename,
                      size := Size}}, State) ->
    SizeMB = Size / (1024 * 1024),
    cryptic_shell:print_info(io_lib:format(
        "~s wants to send you '~s' (~.2f MB)",
        [From, Filename, SizeMB]
    )),
    cryptic_shell:print_info(
        "Accept with: /accept-file " ++ binary_to_list(FileId) ++ " <save_path>"
    ),
    {noreply, State}.
```

#### 3.2 Event Bus Extensions

**File**: `src/cryptic_event_bus.erl`

New event types:
```erlang
%% File transfer events
file_init           % New file transfer offered
file_accepted       % User accepted file
file_rejected       % User rejected file
file_transfer_progress  % Chunk received
file_complete       % All chunks received and verified
file_error          % Transfer failed

%% Stream events (audio/video)
stream_started      % Media stream initiated
stream_chunk        % Media chunk received
stream_ended        % Stream terminated
```

### Phase 4: Audio/Video Streaming (Weeks 7-8)

#### 4.1 Real-Time Codec Integration

**File**: `src/cryptic_media_stream.erl`

```erlang
-module(cryptic_media_stream).

-export([
    start_audio_stream/3,   % (EnginePid, ToUser, Options)
    start_video_stream/3,
    send_audio_chunk/3,     % (StreamId, AudioData, Timestamp)
    send_video_chunk/3,
    stop_stream/2
]).

%% Configuration
-define(AUDIO_CHUNK_MS, 20).    % 20ms audio chunks (Opus frame)
-define(VIDEO_CHUNK_MS, 33).    % ~30 FPS video
-define(JITTER_BUFFER_MS, 100). % Compensate for network jitter

start_audio_stream(EnginePid, ToUser, Options) ->
    StreamId = generate_stream_id(),
    Codec = maps:get(codec, Options, opus),
    
    %% Send stream init
    gen_server:call(EnginePid, {
        send_stream_init,
        ToUser,
        StreamId,
        #{
            media_type => audio,
            codec => Codec,
            sample_rate => maps:get(sample_rate, Options, 48000),
            channels => maps:get(channels, Options, 1)
        }
    }),
    
    {ok, StreamId}.
```

#### 4.2 Jitter Buffer

**File**: `src/cryptic_jitter_buffer.erl`

```erlang
-module(cryptic_jitter_buffer).

%% Reorder out-of-sequence chunks and smooth playback

-record(buffer_state, {
    max_size :: pos_integer(),
    chunks :: #{Sequence => {Timestamp, Data}},
    next_sequence :: non_neg_integer(),
    playout_delay :: pos_integer()
}).

add_chunk(Sequence, Timestamp, Data, State) ->
    %% Add to buffer
    NewChunks = maps:put(Sequence, {Timestamp, Data}, State#buffer_state.chunks),
    
    %% Check if ready to play
    case can_playout(State#buffer_state.next_sequence, NewChunks) of
        true ->
            {ok, Data, advance_buffer(State)};
        false ->
            {buffering, State#buffer_state{chunks = NewChunks}}
    end.
```

### Phase 5: Advanced Features (Weeks 9-10)

#### 5.1 Resume Capability

Track partial transfers:
```erlang
resume_file_transfer(EnginePid, FileId) ->
    %% Query which chunks are missing
    {ok, MissingChunks} = cryptic_file_transfer:get_missing_chunks(FileId),
    
    %% Request only missing chunks
    lists:foreach(fun(ChunkIndex) ->
        request_chunk_retransmit(EnginePid, FileId, ChunkIndex)
    end, MissingChunks).
```

#### 5.2 Thumbnail Generation

For images/videos, send low-res preview first:
```erlang
send_file_with_preview(EnginePid, ToUser, FilePath, Options) ->
    %% Generate thumbnail
    {ok, Thumbnail} = generate_thumbnail(FilePath),
    
    %% Send thumbnail as separate small message
    cryptic_engine:send_message(EnginePid, ToUser, 
        term_to_binary(#{preview => Thumbnail})),
    
    %% Then send full file
    send_file(EnginePid, ToUser, FilePath, Options).
```

#### 5.3 Bandwidth Management

**File**: `src/cryptic_bandwidth_controller.erl`

```erlang
%% Adaptive chunk rate based on network conditions
adjust_send_rate(CurrentRate, PacketLoss, RTT) ->
    if
        PacketLoss > 0.1 ->  % >10% loss
            max(CurrentRate * 0.5, MinRate);
        RTT > 500 ->         % High latency
            CurrentRate * 0.8;
        true ->
            min(CurrentRate * 1.2, MaxRate)
    end.
```

---

## Security Considerations

### 1. **Chunk Encryption**

Each chunk encrypted with unique Double Ratchet message key:
```erlang
encrypt_chunk(ChunkData, PeerUsername, State) ->
    %% Use standard ratchet encryption
    {ok, EncryptedChunk, NewState} = 
        cryptic_double_ratchet:encrypt_message(ChunkData, RatchetState),
    
    %% Result includes ratchet header (DH public key, counters)
    {ok, EncryptedChunk, NewState}.
```

**Security Properties**:
- ✅ Forward secrecy (each chunk has unique key)
- ✅ Post-compromise security (DH ratchet steps)
- ✅ Authentication (ChaCha20-Poly1305 AEAD)

### 2. **Metadata Encryption**

Filename, MIME type, size also encrypted:
```erlang
Metadata = #{
    filename => <<"sensitive_report.pdf">>,  % Encrypted
    mime_type => <<"application/pdf">>,      % Encrypted
    size => 1048576                          % Encrypted
}
```

**Prevents**: Metadata analysis attacks

### 3. **Checksum Verification**

```erlang
verify_file_integrity(FileId) ->
    %% 1. Retrieve all chunks
    {ok, Chunks} = reassemble_chunks(FileId),
    
    %% 2. Compute checksum of reassembled file
    ActualChecksum = crypto:hash(sha256, Chunks),
    
    %% 3. Compare with expected checksum from metadata
    {ok, ExpectedChecksum} = get_file_checksum(FileId),
    
    ActualChecksum =:= ExpectedChecksum.
```

**Prevents**: Chunk corruption, malicious modification

### 4. **Denial of Service Mitigations**

```erlang
%% Limit concurrent transfers per user
-define(MAX_CONCURRENT_TRANSFERS, 5).

%% Limit file size
-define(MAX_FILE_SIZE, 1073741824). % 1GB

%% Rate limiting
check_rate_limit(Username) ->
    %% Max 10 file transfers per hour
    cryptic_rate_limiter:check(Username, file_transfer, 10, 3600).
```

### 5. **Storage Quotas**

```erlang
%% Prevent disk exhaustion
check_storage_quota(Username) ->
    UsedBytes = calculate_user_storage(Username),
    Quota = get_user_quota(Username),  % Default: 5GB
    
    UsedBytes < Quota.
```

---

## Performance & Scalability

### Chunk Size Optimization

| File Type | Optimal Chunk Size | Rationale |
|-----------|-------------------|-----------|
| Text files | 32 KB | Small overhead, fast encryption |
| Images | 64 KB | Balance memory/network efficiency |
| Audio (streaming) | 4 KB (20ms Opus) | Low latency |
| Video (streaming) | 16 KB | 30 FPS smoothness |
| Large files | 256 KB | Minimize roundtrips |

### Memory Usage

Per-transfer memory footprint:
```
Sender:
- File handle: ~8 KB
- Chunk buffer: 64 KB
- Pending acks map: ~1 KB per chunk
- Total per transfer: ~100 KB

Receiver:
- Chunk reassembly buffer: 64 KB * N (N = max out-of-order chunks)
- Metadata: ~2 KB
- Total per transfer: ~300 KB
```

### Database Performance

Index strategy:
```sql
-- Fast lookups by status
CREATE INDEX idx_file_status ON file_transfers(status, created_at);

-- Fast chunk retrieval
CREATE INDEX idx_chunks_file ON file_chunks(file_id, chunk_index);

-- Purge old completed transfers
DELETE FROM file_transfers 
WHERE status = 'complete' 
  AND completed_at < (strftime('%s', 'now') - 2592000); -- 30 days
```

### Network Considerations

Estimated bandwidth usage:

| Media Type | Bitrate | Chunk Rate | Bandwidth (with encryption overhead) |
|------------|---------|------------|--------------------------------------|
| Text | N/A | N/A | < 1 KB/s |
| Opus audio (mono) | 16 kbps | 50 chunks/s | ~20 kbps |
| H.264 video (720p) | 2 Mbps | 30 chunks/s | ~2.5 Mbps |
| File transfer | Variable | 10-100 chunks/s | 500 KB/s - 5 MB/s |

---

## API Reference

### User-Facing API

#### Send File
```erlang
cryptic_engine:send_file(EnginePid, ToUser, FilePath, Options) ->
    {ok, FileId} | {error, Reason}.

%% Options:
%%   chunk_size => pos_integer()  (default: 65536)
%%   priority => low | normal | high
%%   compress => boolean()  (default: false)
```

#### Accept File
```erlang
cryptic_engine:accept_file(EnginePid, FileId, SavePath) ->
    ok | {error, Reason}.
```

#### Monitor Progress
```erlang
%% Subscribe to events
cryptic_event_bus:subscribe(self(), fun(Event) ->
    case Event of
        #{type := file_transfer_progress} -> true;
        _ -> false
    end
end).

%% Receive events
receive
    {event, #{type := file_transfer_progress,
              file_id := FileId,
              chunk := Chunk,
              total_chunks := Total}} ->
        Percentage = (Chunk / Total) * 100,
        io:format("Progress: ~.1f%~n", [Percentage])
end.
```

### Internal API

#### Chunk Encryption
```erlang
cryptic_file_transfer:encrypt_chunk(ChunkData, RatchetState) ->
    {ok, EncryptedChunk, NewRatchetState} | {error, Reason}.
```

#### Storage API
```erlang
cryptic_chat_storage:save_file_chunk(FileId, ChunkIndex, EncryptedChunk, Passphrase) ->
    ok | {error, Reason}.

cryptic_chat_storage:get_file_chunks(FileId, Passphrase) ->
    {ok, [EncryptedChunk]} | {error, Reason}.
```

---

## Testing Strategy

### Unit Tests

```erlang
%% test/cryptic_file_transfer_tests.erl

chunk_encryption_test() ->
    %% Test that each chunk gets unique encryption
    Chunks = [<<"chunk1">>, <<"chunk2">>, <<"chunk3">>],
    
    {ok, RatchetState} = setup_ratchet(),
    
    EncryptedChunks = lists:foldl(fun(Chunk, {Acc, State}) ->
        {ok, Encrypted, NewState} = 
            cryptic_file_transfer:encrypt_chunk(Chunk, State),
        {[Encrypted | Acc], NewState}
    end, {[], RatchetState}, Chunks),
    
    %% Verify all ciphertexts are different
    ?assertEqual(3, length(lists:usort(EncryptedChunks))).

checksum_verification_test() ->
    %% Test integrity verification
    FileData = crypto:strong_rand_bytes(1024 * 1024),
    ExpectedChecksum = crypto:hash(sha256, FileData),
    
    %% Simulate transfer
    Chunks = split_into_chunks(FileData, 65536),
    
    %% Corrupt one chunk
    CorruptedChunks = corrupt_chunk(Chunks, 5),
    
    %% Reassemble and verify
    Reassembled = reassemble_chunks(CorruptedChunks),
    ActualChecksum = crypto:hash(sha256, Reassembled),
    
    ?assertNotEqual(ExpectedChecksum, ActualChecksum).
```

### Integration Tests

```erlang
%% test/cryptic_file_e2e_tests.erl

file_transfer_e2e_test() ->
    %% Setup Alice and Bob
    {ok, AliceEngine} = start_test_engine("alice"),
    {ok, BobEngine} = start_test_engine("bob"),
    
    %% Alice sends file to Bob
    TestFile = create_test_file(1024 * 1024), % 1MB
    {ok, FileId} = cryptic_engine:send_file(
        AliceEngine, <<"bob">>, TestFile, #{}
    ),
    
    %% Bob accepts
    SavePath = "/tmp/bob_received_file",
    ok = cryptic_engine:accept_file(BobEngine, FileId, SavePath),
    
    %% Wait for completion
    receive
        {event, #{type := file_complete, file_id := FileId}} ->
            ok
    after 30000 ->
        error(timeout)
    end,
    
    %% Verify integrity
    {ok, OriginalData} = file:read_file(TestFile),
    {ok, ReceivedData} = file:read_file(SavePath),
    
    ?assertEqual(OriginalData, ReceivedData).
```

### Performance Tests

```erlang
benchmark_chunk_rate_test() ->
    %% Measure chunks/second
    {ok, Engine} = start_test_engine("benchmark"),
    
    StartTime = erlang:monotonic_time(millisecond),
    
    %% Send 1000 chunks
    lists:foreach(fun(_) ->
        Chunk = crypto:strong_rand_bytes(65536),
        cryptic_file_transfer:encrypt_chunk(Chunk, Engine)
    end, lists:seq(1, 1000)),
    
    EndTime = erlang:monotonic_time(millisecond),
    Duration = EndTime - StartTime,
    
    ChunksPerSecond = 1000 / (Duration / 1000),
    
    %% Should handle at least 100 chunks/second
    ?assert(ChunksPerSecond > 100).
```

---

## Migration Path

### Backward Compatibility

#### Phase 1: Additive Changes
- New message types (`file_init`, `file_chunk`) don't affect existing `x3dh`/`ratchet` messages
- Database schema adds new tables, doesn't modify `encrypted_messages`
- Old clients ignore unknown message types

#### Phase 2: Optional Feature
```erlang
%% Check if peer supports file transfer
supports_file_transfer(PeerUsername) ->
    case get_peer_capabilities(PeerUsername) of
        #{features := Features} ->
            lists:member(file_transfer, Features);
        _ ->
            false
    end.

%% Graceful degradation
send_file_or_link(EnginePid, ToUser, FilePath) ->
    case supports_file_transfer(ToUser) of
        true ->
            cryptic_engine:send_file(EnginePid, ToUser, FilePath, #{});
        false ->
            %% Fallback: send text message with file description
            cryptic_engine:send_message(EnginePid, ToUser,
                <<"File available: ", FilePath/binary>>)
    end.
```

### Rollout Strategy

1. **Week 1-2**: Deploy server changes (support new message types)
2. **Week 3-4**: Release client updates with UI disabled
3. **Week 5-6**: Enable UI for beta testers
4. **Week 7-8**: General availability

### Data Migration

No migration needed - new feature is additive.

Optional: Pre-populate storage quotas:
```sql
INSERT INTO storage_quotas (username, quota_bytes, created_at)
SELECT DISTINCT from_user, 5368709120, strftime('%s', 'now')
FROM encrypted_messages
WHERE from_user NOT IN (SELECT username FROM storage_quotas);
```

---

## Future Enhancements

### Phase 6: Advanced Media Features

1. **Voice Messages**
   - Record audio in UI
   - Automatic compression (Opus codec)
   - Waveform visualization

2. **Video Calls**
   - WebRTC integration for peer-to-peer
   - Fallback to relay server
   - Screen sharing capability

3. **Group File Sharing**
   - Send file to multiple recipients
   - Deduplicate encrypted chunks (same ratchet key)
   - Progress tracking per recipient

4. **Cloud Storage Integration**
   - Optionally backup encrypted files to S3/B2
   - Share large files via encrypted links
   - Automatic expiration

### Phase 7: Performance Optimizations

1. **Parallel Chunk Transfer**
   - Send multiple chunks concurrently
   - Adaptive parallelism based on bandwidth

2. **Compression**
   - Zstandard compression before encryption
   - Detect compressible content (skip for JPEG/MP4)

3. **Delta Sync**
   - For file updates, send only changed chunks
   - rsync-like binary diff algorithm

---

## Appendix A: Example Usage Scenarios

### Scenario 1: Send Photo to Friend

```erlang
%% Alice sends vacation photo to Bob
1> {ok, FileId} = cryptic_engine:send_file(
    EnginePid,
    <<"bob">>,
    "/home/alice/vacation.jpg",
    #{compress => false}
).
{ok, <<"file-abc123">>}

%% Console shows progress
%% [12:34:56] Sending vacation.jpg to bob (2.4 MB)
%% [12:34:57] Progress: 25% (16/64 chunks)
%% [12:34:58] Progress: 50% (32/64 chunks)
%% [12:34:59] Progress: 75% (48/64 chunks)
%% [12:35:00] ✓ File sent successfully
```

### Scenario 2: Receive File Notification

```erlang
%% Bob receives notification
%% [12:34:56] alice wants to send you 'vacation.jpg' (2.40 MB)
%% Accept with: /accept-file file-abc123 ~/Downloads/

2> cryptic_console:handle_command("/accept-file file-abc123 ~/Downloads/").

%% [12:34:57] Receiving vacation.jpg from alice
%% [12:34:58] Progress: 25% (16/64 chunks)
%% [12:34:59] Progress: 50% (32/64 chunks)
%% [12:35:00] Progress: 75% (48/64 chunks)
%% [12:35:01] ✓ File received: ~/Downloads/vacation.jpg
```

### Scenario 3: Audio Streaming

```erlang
%% Start voice call
1> {ok, StreamId} = cryptic_media_stream:start_audio_stream(
    EnginePid,
    <<"bob">>,
    #{codec => opus, sample_rate => 48000}
).

%% Audio chunks sent automatically from microphone
%% [12:40:00] 🎤 Voice call started with bob
%% [12:40:20] 📊 Bitrate: 16 kbps, Latency: 45ms
%% [12:45:00] 🎤 Voice call ended (5:00 duration)
```

---

## Appendix B: Error Handling

### Error Categories

| Error | Cause | Recovery |
|-------|-------|----------|
| `checksum_mismatch` | Data corruption | Retry transfer |
| `timeout` | Network issue | Resume from last chunk |
| `disk_full` | No storage space | Reject transfer |
| `quota_exceeded` | User over limit | Notify sender |
| `file_not_found` | Invalid path | Prompt user |
| `encryption_failed` | Ratchet error | Re-establish session |

### Example Handler

```erlang
handle_file_error(FileId, Error, State) ->
    case Error of
        checksum_mismatch ->
            %% Retry once
            case get_retry_count(FileId) of
                N when N < 1 ->
                    retry_transfer(FileId),
                    increment_retry_count(FileId);
                _ ->
                    notify_user({file_failed, FileId, Error}),
                    cleanup_transfer(FileId)
            end;
            
        timeout ->
            %% Resume from last successful chunk
            {ok, LastChunk} = get_last_received_chunk(FileId),
            resume_from_chunk(FileId, LastChunk + 1);
            
        disk_full ->
            notify_user({storage_full, FileId}),
            reject_transfer(FileId);
            
        _ ->
            notify_user({file_failed, FileId, Error}),
            cleanup_transfer(FileId)
    end,
    {noreply, State}.
```

---

## Appendix C: Configuration Reference

### Server Configuration

```erlang
%% config/sys.config

{cryptic, [
    {file_transfer, #{
        max_file_size => 1073741824,        % 1 GB
        max_concurrent_transfers => 5,
        chunk_size => 65536,                % 64 KB
        chunk_timeout_ms => 5000,
        default_storage_quota => 5368709120, % 5 GB
        enable_compression => true,
        supported_codecs => [opus, h264, vp9]
    }},
    
    {media_streaming, #{
        audio_buffer_ms => 100,
        video_buffer_ms => 200,
        max_concurrent_streams => 3,
        enable_adaptive_bitrate => true
    }}
]}.
```

### Client Configuration

```erlang
%% In console/UI startup
Options = #{
    auto_accept_files => false,      % Prompt before accepting
    default_save_path => "~/Downloads/cryptic/",
    max_download_bandwidth => 5242880,  % 5 MB/s
    show_transfer_progress => true,
    audio_input_device => "default",
    video_input_device => "default"
}.
```

---

## Conclusion

This plan provides a comprehensive, phased approach to adding file, audio, and video support to Cryptic while maintaining its strong security guarantees. The chunked transfer architecture scales from small text files to large video streams, all protected by the Double Ratchet protocol.

### Key Takeaways

✅ **Security-first**: Every chunk encrypted with forward secrecy  
✅ **Scalable**: Chunking prevents memory exhaustion  
✅ **Resilient**: Resume capability handles network interruptions  
✅ **Event-driven**: Leverages existing event bus architecture  
✅ **Backward compatible**: Additive changes don't break existing clients  

### Next Steps

1. Review and approve this plan
2. Set up development environment
3. Begin Phase 1 implementation (database schema)
4. Create feature branch: `feature/multimedia-support`
5. Iterate with testing and feedback

---

**Questions or feedback?** Open an issue in the Cryptic repository.

**Document Maintainer**: Cryptic Development Team  
**Last Updated**: December 2025
