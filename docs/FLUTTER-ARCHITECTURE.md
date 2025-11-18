# Flutter Mobile App Architecture for Cryptic

This document outlines the architecture for a Flutter mobile application that implements the Cryptic end-to-end encrypted messaging protocol.

## Overview

The Flutter app will be a faithful port of the Erlang client architecture, maintaining the same cryptographic protocols (X3DH, Double Ratchet) and WebSocket communication while adapting to Flutter's reactive UI patterns.

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                         UI Layer (Flutter)                      │
│  - ChatScreen, ContactsScreen, SettingsScreen                   │
│  - State Management (Riverpod/Provider)                         │
└─────────────────────────────────────────────────────────────────┘
                              ↕
┌─────────────────────────────────────────────────────────────────┐
│                      Business Logic Layer                       │
│  - CrypticEngine (orchestrates crypto + network)                │
│  - MessageService (send/receive messages)                       │
│  - SessionManager (manage peer sessions)                        │
└─────────────────────────────────────────────────────────────────┘
                              ↕
┌────────────────────────────┬────────────────────────────────────┐
│     Crypto Layer           │        Network Layer               │
│  - X3DH Protocol           │  - WebSocket Client                │
│  - Double Ratchet          │  - mTLS Certificate Handling       │
│  - Key Management          │  - Message Encoding/Decoding       │
└────────────────────────────┴────────────────────────────────────┘
                              ↕
┌─────────────────────────────────────────────────────────────────┐
│                       Storage Layer                             │
│  - Secure Key Storage (flutter_secure_storage)                  │
│  - Message Database (sqflite_sqlcipher)                         │
│  - Session State Persistence                                    │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```dart
lib/
├── main.dart                          // App entry point
├── core/
│   ├── config/
│   │   └── app_config.dart           // Server URLs, ports, etc.
│   ├── di/
│   │   └── injection.dart            // Dependency injection setup
│   └── utils/
│       ├── logger.dart               // Logging utility
│       └── extensions.dart           // Helper extensions
│
├── domain/
│   ├── models/
│   │   ├── identity_keys.dart       // Identity key pairs (sign + DH)
│   │   ├── prekey_bundle.dart       // X3DH prekey bundle
│   │   ├── session_state.dart       // Double Ratchet session state
│   │   ├── message.dart             // Plaintext message model
│   │   └── encrypted_message.dart   // X3DH/Ratchet encrypted message
│   │
│   ├── repositories/
│   │   ├── crypto_repository.dart   // Abstract crypto operations
│   │   ├── network_repository.dart  // Abstract network operations
│   │   └── storage_repository.dart  // Abstract storage operations
│   │
│   └── usecases/
│       ├── send_message.dart        // Use case: send encrypted message
│       ├── receive_message.dart     // Use case: decrypt received message
│       ├── initialize_session.dart  // Use case: X3DH handshake
│       └── upload_keys.dart         // Use case: upload prekey bundles
│
├── data/
│   ├── crypto/
│   │   ├── x3dh/
│   │   │   ├── x3dh_engine.dart           // Port of cryptic_lib.erl X3DH functions
│   │   │   ├── key_agreement.dart         // DH operations
│   │   │   └── kdf.dart                   // HKDF key derivation
│   │   │
│   │   ├── ratchet/
│   │   │   ├── double_ratchet.dart        // Port of cryptic_double_ratchet.erl
│   │   │   ├── kdf_chain.dart             // KDF chain step
│   │   │   ├── message_keys.dart          // Message key derivation
│   │   │   └── header_encryption.dart     // Header encryption
│   │   │
│   │   ├── primitives/
│   │   │   ├── ed25519.dart               // Signing (via pointycastle)
│   │   │   ├── x25519.dart                // DH key exchange (via pointycastle)
│   │   │   ├── chacha20_poly1305.dart     // AEAD encryption
│   │   │   └── hkdf.dart                  // HMAC-based KDF
│   │   │
│   │   └── keys/
│   │       ├── key_generator.dart         // Generate identity/prekeys
│   │       ├── key_serializer.dart        // Encode/decode keys
│   │       └── key_validator.dart         // Validate key formats
│   │
│   ├── network/
│   │   ├── websocket/
│   │   │   ├── websocket_client.dart      // Port of cryptic_ws_client.erl
│   │   │   ├── connection_manager.dart    // Connection state, reconnection
│   │   │   ├── message_queue.dart         // Queue messages when offline
│   │   │   └── mtls_config.dart           // mTLS certificate setup
│   │   │
│   │   └── protocol/
│   │       ├── message_encoder.dart       // Encode messages to JSON
│   │       ├── message_decoder.dart       // Decode JSON to models
│   │       └── protocol_types.dart        // Message type constants
│   │
│   ├── storage/
│   │   ├── secure_storage/
│   │   │   ├── key_storage.dart           // Store identity keys securely
│   │   │   ├── certificate_storage.dart   // Store mTLS certificates
│   │   │   └── passphrase_storage.dart    // Store user passphrase (hashed)
│   │   │
│   │   ├── database/
│   │   │   ├── database.dart              // SQLite database setup
│   │   │   ├── daos/
│   │   │   │   ├── message_dao.dart       // Message CRUD operations
│   │   │   │   ├── session_dao.dart       // Session state CRUD
│   │   │   │   └── contact_dao.dart       // Contact management
│   │   │   │
│   │   │   └── models/
│   │   │       ├── message_entity.dart    // Database message model
│   │   │       └── session_entity.dart    // Database session model
│   │   │
│   │   └── repositories_impl/
│   │       ├── crypto_repository_impl.dart
│   │       ├── network_repository_impl.dart
│   │       └── storage_repository_impl.dart
│   │
│   └── engine/
│       ├── cryptic_engine.dart            // Port of cryptic_engine.erl
│       ├── engine_state.dart              // Engine state management
│       ├── session_manager.dart           // Manage multiple peer sessions
│       └── message_processor.dart         // Process incoming/outgoing messages
│
├── presentation/
│   ├── providers/
│   │   ├── engine_provider.dart           // Riverpod provider for engine
│   │   ├── messages_provider.dart         // Message list state
│   │   ├── contacts_provider.dart         // Contact list state
│   │   └── connection_provider.dart       // WebSocket connection state
│   │
│   ├── screens/
│   │   ├── splash/
│   │   │   └── splash_screen.dart         // App startup, key loading
│   │   │
│   │   ├── auth/
│   │   │   ├── setup_screen.dart          // Initial setup (generate keys)
│   │   │   └── unlock_screen.dart         // Passphrase entry
│   │   │
│   │   ├── chat/
│   │   │   ├── chat_list_screen.dart      // List of conversations
│   │   │   ├── chat_screen.dart           // Individual chat view
│   │   │   └── widgets/
│   │   │       ├── message_bubble.dart    // Message display
│   │   │       ├── input_field.dart       // Message input
│   │   │       └── typing_indicator.dart  // Typing animation
│   │   │
│   │   ├── contacts/
│   │   │   ├── contacts_screen.dart       // User list from server
│   │   │   └── contact_detail_screen.dart // Contact info
│   │   │
│   │   └── settings/
│   │       ├── settings_screen.dart       // App settings
│   │       ├── key_management_screen.dart // View/backup keys
│   │       └── server_config_screen.dart  // Server connection settings
│   │
│   └── widgets/
│       ├── connection_status.dart         // WebSocket status indicator
│       ├── error_dialog.dart              // Error display
│       └── loading_overlay.dart           // Loading state
│
└── test/
    ├── unit/
    │   ├── crypto/
    │   │   ├── x3dh_test.dart             // X3DH test vectors
    │   │   └── double_ratchet_test.dart   // Double Ratchet test vectors
    │   │
    │   └── network/
    │       └── protocol_test.dart         // Message encoding/decoding tests
    │
    ├── integration/
    │   ├── engine_test.dart               // End-to-end engine tests
    │   └── message_flow_test.dart         // Send/receive message flow
    │
    └── widget/
        └── chat_screen_test.dart          // UI tests
```

## Core Components

### 1. CrypticEngine (Port of `cryptic_engine.erl`)

The central orchestrator for all cryptographic operations and message handling.

```dart
class CrypticEngine {
  final String username;
  final CryptoRepository _crypto;
  final NetworkRepository _network;
  final StorageRepository _storage;
  
  IdentityKeys? _identityKeys;
  final Map<String, SessionState> _sessions = {};
  final Map<String, PrekeyBundle> _peerKeyBundles = {};
  
  StreamController<Message> _messageStream = StreamController.broadcast();
  StreamController<String> _systemMessageStream = StreamController.broadcast();
  
  // Initialize engine (load keys, connect to server)
  Future<void> initialize(String passphrase) async {
    // Load identity keys from secure storage
    _identityKeys = await _storage.loadIdentityKeys(username, passphrase);
    
    if (_identityKeys == null) {
      // First time: generate keys
      _identityKeys = await _crypto.generateIdentityKeys();
      await _storage.saveIdentityKeys(username, _identityKeys!, passphrase);
    }
    
    // Connect to WebSocket server
    await _network.connect(username);
    
    // Upload identity keys and prekey bundles to server
    await uploadKeys();
    
    // Listen for incoming messages
    _network.messageStream.listen(_handleServerMessage);
  }
  
  // Send encrypted message to peer
  Future<void> sendMessage(String toUser, String plaintext) async {
    // Get or create session with peer
    SessionState? session = _sessions[toUser];
    
    if (session == null) {
      // No session exists: perform X3DH
      await _initiateX3DHSession(toUser, plaintext);
    } else {
      // Session exists: use Double Ratchet
      await _sendRatchetMessage(toUser, plaintext, session);
    }
  }
  
  // Initialize X3DH session with peer
  Future<void> _initiateX3DHSession(String toUser, String plaintext) async {
    // Request peer's prekey bundle from server
    final bundle = await _network.requestKeyBundle(toUser);
    _peerKeyBundles[toUser] = bundle;
    
    // Perform X3DH key agreement
    final x3dhResult = await _crypto.performX3DH(
      identityKeys: _identityKeys!,
      peerBundle: bundle,
    );
    
    // Initialize Double Ratchet with shared secret
    final session = await _crypto.initializeRatchet(
      sharedSecret: x3dhResult.sharedKey,
      peerDHPublicKey: bundle.signedPrekeyPublic,
    );
    
    _sessions[toUser] = session;
    await _storage.saveSession(username, toUser, session);
    
    // Encrypt first message
    final encrypted = await _crypto.ratchetEncrypt(session, plaintext);
    
    // Send X3DH initial message
    await _network.sendX3DHMessage(
      toUser: toUser,
      identityKey: x3dhResult.ephemeralPublic,
      ephemeralKey: x3dhResult.ephemeralPublic,
      usedOTPKId: bundle.oneTimePrekey?.keyId,
      ciphertext: encrypted.ciphertext,
    );
  }
  
  // Send message using existing ratchet session
  Future<void> _sendRatchetMessage(
    String toUser,
    String plaintext,
    SessionState session,
  ) async {
    // Encrypt with Double Ratchet
    final encrypted = await _crypto.ratchetEncrypt(session, plaintext);
    
    // Update session state
    _sessions[toUser] = encrypted.newSession;
    await _storage.saveSession(username, toUser, encrypted.newSession);
    
    // Send ratchet message
    await _network.sendRatchetMessage(
      toUser: toUser,
      dhPublic: encrypted.dhPublic,
      previousChainLength: encrypted.previousChainLength,
      messageNumber: encrypted.messageNumber,
      ciphertext: encrypted.ciphertext,
    );
  }
  
  // Handle incoming message from server
  Future<void> _handleServerMessage(ServerMessage msg) async {
    switch (msg.type) {
      case MessageType.x3dh:
        await _handleX3DHMessage(msg as X3DHMessage);
        break;
      case MessageType.ratchet:
        await _handleRatchetMessage(msg as RatchetMessage);
        break;
      case MessageType.keyBundle:
        await _handleKeyBundle(msg as KeyBundleMessage);
        break;
      case MessageType.userStatus:
        _systemMessageStream.add('User ${msg.username} is ${msg.status}');
        break;
      default:
        _systemMessageStream.add('Unknown message type: ${msg.type}');
    }
  }
  
  // Handle incoming X3DH message
  Future<void> _handleX3DHMessage(X3DHMessage msg) async {
    // Perform X3DH as responder
    final x3dhResult = await _crypto.receiveX3DH(
      identityKeys: _identityKeys!,
      peerIdentityKey: msg.identityKey,
      peerEphemeralKey: msg.ephemeralKey,
      usedOTPKId: msg.usedOTPKId,
    );
    
    // Initialize Double Ratchet
    final session = await _crypto.initializeRatchetAsResponder(
      sharedSecret: x3dhResult.sharedKey,
      peerDHPublicKey: msg.identityKey,
    );
    
    _sessions[msg.fromUser] = session;
    await _storage.saveSession(username, msg.fromUser, session);
    
    // Decrypt message
    final decrypted = await _crypto.ratchetDecrypt(
      session,
      msg.ciphertext,
      dhPublic: msg.ephemeralKey,
      previousChainLength: 0,
      messageNumber: 0,
    );
    
    _sessions[msg.fromUser] = decrypted.newSession;
    await _storage.saveSession(username, msg.fromUser, decrypted.newSession);
    
    // Deliver to UI
    _messageStream.add(Message(
      from: msg.fromUser,
      text: decrypted.plaintext,
      timestamp: DateTime.now(),
    ));
    
    // Save to database
    await _storage.saveMessage(username, msg.fromUser, decrypted.plaintext);
  }
  
  // Handle incoming ratchet message
  Future<void> _handleRatchetMessage(RatchetMessage msg) async {
    final session = _sessions[msg.fromUser];
    if (session == null) {
      _systemMessageStream.add('No session for ${msg.fromUser}');
      return;
    }
    
    // Decrypt with Double Ratchet
    final decrypted = await _crypto.ratchetDecrypt(
      session,
      msg.ciphertext,
      dhPublic: msg.dhPublic,
      previousChainLength: msg.previousChainLength,
      messageNumber: msg.messageNumber,
    );
    
    _sessions[msg.fromUser] = decrypted.newSession;
    await _storage.saveSession(username, msg.fromUser, decrypted.newSession);
    
    // Deliver to UI
    _messageStream.add(Message(
      from: msg.fromUser,
      text: decrypted.plaintext,
      timestamp: DateTime.now(),
    ));
    
    // Save to database
    await _storage.saveMessage(username, msg.fromUser, decrypted.plaintext);
  }
  
  // Upload identity keys and prekeys to server
  Future<void> uploadKeys() async {
    // Generate one-time prekeys
    final oneTimePrekeys = await _crypto.generateOneTimePrekeys(count: 100);
    
    // Upload to server
    await _network.uploadIdentityKeys(_identityKeys!);
    await _network.uploadPrekeyBundle(oneTimePrekeys);
    
    _systemMessageStream.add('Keys uploaded successfully');
  }
  
  // Streams for UI
  Stream<Message> get messageStream => _messageStream.stream;
  Stream<String> get systemMessageStream => _systemMessageStream.stream;
}
```

### 2. WebSocket Client (Port of `cryptic_ws_client.erl`)

Handles mTLS WebSocket connection to server.

```dart
class WebSocketClient implements NetworkRepository {
  final String serverHost;
  final int serverPort;
  final String username;
  
  WebSocketChannel? _channel;
  final StreamController<ServerMessage> _messageController = 
      StreamController.broadcast();
  
  @override
  Stream<ServerMessage> get messageStream => _messageController.stream;
  
  @override
  Future<void> connect(String username) async {
    // Load mTLS certificates
    final cert = await _loadCertificate(username);
    final key = await _loadPrivateKey(username);
    final ca = await _loadCACertificate();
    
    // Create mTLS context
    final securityContext = SecurityContext()
      ..useCertificateChain(cert)
      ..usePrivateKey(key)
      ..setTrustedCertificates(ca);
    
    // Connect WebSocket with mTLS
    final uri = Uri.parse('wss://$serverHost:$serverPort');
    final socket = await SecureSocket.connect(
      serverHost,
      serverPort,
      context: securityContext,
    );
    
    _channel = IOWebSocketChannel(WebSocket.fromUpgradedSocket(
      socket,
      serverSide: false,
    ));
    
    // Listen for messages
    _channel!.stream.listen(
      (data) => _handleMessage(data),
      onError: (error) => _handleError(error),
      onDone: () => _handleDisconnect(),
    );
  }
  
  void _handleMessage(dynamic data) {
    final json = jsonDecode(data as String);
    final message = ServerMessage.fromJson(json);
    _messageController.add(message);
  }
  
  @override
  Future<void> sendX3DHMessage({
    required String toUser,
    required Uint8List identityKey,
    required Uint8List ephemeralKey,
    int? usedOTPKId,
    required Uint8List ciphertext,
  }) async {
    final message = {
      'type': 'x3dh',
      'message_id': Uuid().v4(),
      'from_user': username,
      'to_user': toUser,
      'identity_key': base64Encode(identityKey),
      'ephemeral_key': base64Encode(ephemeralKey),
      'used_one_time_prekey_id': usedOTPKId,
      'ciphertext': base64Encode(ciphertext),
    };
    
    _channel!.sink.add(jsonEncode(message));
  }
  
  @override
  Future<void> sendRatchetMessage({
    required String toUser,
    required Uint8List dhPublic,
    required int previousChainLength,
    required int messageNumber,
    required Uint8List ciphertext,
  }) async {
    final message = {
      'type': 'ratchet',
      'message_id': Uuid().v4(),
      'from_user': username,
      'to_user': toUser,
      'dh_public': base64Encode(dhPublic),
      'previous_chain_length': previousChainLength,
      'message_number': messageNumber,
      'ciphertext': base64Encode(ciphertext),
    };
    
    _channel!.sink.add(jsonEncode(message));
  }
  
  @override
  Future<PrekeyBundle> requestKeyBundle(String username) async {
    final message = {
      'type': 'get_key_bundle',
      'username': username,
    };
    
    _channel!.sink.add(jsonEncode(message));
    
    // Wait for key_bundle response
    final response = await messageStream
        .firstWhere((msg) => msg.type == MessageType.keyBundle);
    
    return (response as KeyBundleMessage).bundle;
  }
}
```

### 3. X3DH Implementation (Port of `cryptic_lib.erl`)

```dart
class X3DHEngine {
  final Ed25519 _ed25519 = Ed25519();
  final X25519 _x25519 = X25519();
  final HKDF _hkdf = HKDF();
  
  // Generate identity key pairs
  Future<IdentityKeys> generateIdentityKeys() async {
    // Signing key pair (Ed25519)
    final signKeyPair = _ed25519.generateKeyPair();
    
    // DH key pair (X25519)
    final dhKeyPair = _x25519.generateKeyPair();
    
    // Signed prekey
    final signedPrekeyPair = _x25519.generateKeyPair();
    final signedPrekeySignature = _ed25519.sign(
      signKeyPair.privateKey,
      signedPrekeyPair.publicKey,
    );
    
    return IdentityKeys(
      identitySignPublic: signKeyPair.publicKey,
      identitySignPrivate: signKeyPair.privateKey,
      identityDHPublic: dhKeyPair.publicKey,
      identityDHPrivate: dhKeyPair.privateKey,
      signedPrekeyPublic: signedPrekeyPair.publicKey,
      signedPrekeyPrivate: signedPrekeyPair.privateKey,
      signedPrekeySignature: signedPrekeySignature,
      signedPrekeyId: 1,
    );
  }
  
  // Perform X3DH as initiator
  Future<X3DHResult> performX3DH({
    required IdentityKeys identityKeys,
    required PrekeyBundle peerBundle,
  }) async {
    // Verify signed prekey signature
    final isValid = _ed25519.verify(
      peerBundle.identitySignKey,
      peerBundle.signedPrekeyPublic,
      peerBundle.signedPrekeySignature,
    );
    
    if (!isValid) {
      throw Exception('Invalid signed prekey signature');
    }
    
    // Generate ephemeral key pair
    final ephemeralKeyPair = _x25519.generateKeyPair();
    
    // Perform 4 DH operations
    final dh1 = _x25519.computeSharedSecret(
      identityKeys.identityDHPrivate,
      peerBundle.signedPrekeyPublic,
    );
    
    final dh2 = _x25519.computeSharedSecret(
      ephemeralKeyPair.privateKey,
      peerBundle.identityDHKey,
    );
    
    final dh3 = _x25519.computeSharedSecret(
      ephemeralKeyPair.privateKey,
      peerBundle.signedPrekeyPublic,
    );
    
    final dh4 = peerBundle.oneTimePrekey != null
        ? _x25519.computeSharedSecret(
            ephemeralKeyPair.privateKey,
            peerBundle.oneTimePrekey!.publicKey,
          )
        : Uint8List(32); // Zero bytes if no OPK
    
    // Concatenate DH outputs
    final dhOutput = Uint8List.fromList([
      ...dh1,
      ...dh2,
      ...dh3,
      ...dh4,
    ]);
    
    // Derive shared secret with HKDF
    final sharedKey = _hkdf.deriveKey(
      dhOutput,
      salt: Uint8List(32),
      info: utf8.encode('Cryptic X3DH'),
      length: 32,
    );
    
    return X3DHResult(
      sharedKey: sharedKey,
      ephemeralPublic: ephemeralKeyPair.publicKey,
    );
  }
  
  // Receive X3DH as responder
  Future<X3DHResult> receiveX3DH({
    required IdentityKeys identityKeys,
    required Uint8List peerIdentityKey,
    required Uint8List peerEphemeralKey,
    int? usedOTPKId,
  }) async {
    // Perform 4 DH operations (in reverse)
    final dh1 = _x25519.computeSharedSecret(
      identityKeys.signedPrekeyPrivate,
      peerIdentityKey,
    );
    
    final dh2 = _x25519.computeSharedSecret(
      identityKeys.identityDHPrivate,
      peerEphemeralKey,
    );
    
    final dh3 = _x25519.computeSharedSecret(
      identityKeys.signedPrekeyPrivate,
      peerEphemeralKey,
    );
    
    // Get one-time prekey if used
    Uint8List? dh4;
    if (usedOTPKId != null) {
      final otpk = await _getOneTimePrekey(usedOTPKId);
      if (otpk != null) {
        dh4 = _x25519.computeSharedSecret(otpk, peerEphemeralKey);
      }
    }
    dh4 ??= Uint8List(32);
    
    // Concatenate DH outputs
    final dhOutput = Uint8List.fromList([
      ...dh1,
      ...dh2,
      ...dh3,
      ...dh4,
    ]);
    
    // Derive shared secret with HKDF
    final sharedKey = _hkdf.deriveKey(
      dhOutput,
      salt: Uint8List(32),
      info: utf8.encode('Cryptic X3DH'),
      length: 32,
    );
    
    return X3DHResult(
      sharedKey: sharedKey,
      ephemeralPublic: Uint8List(0), // Not used by responder
    );
  }
}
```

### 4. Double Ratchet Implementation (Port of `cryptic_double_ratchet.erl`)

```dart
class DoubleRatchet {
  final X25519 _x25519 = X25519();
  final HKDF _hkdf = HKDF();
  final ChaCha20Poly1305 _aead = ChaCha20Poly1305();
  
  // Initialize ratchet as initiator
  Future<SessionState> initialize({
    required Uint8List sharedSecret,
    required Uint8List peerDHPublicKey,
  }) async {
    // Derive root key and chain key from shared secret
    final rootKey = _hkdf.deriveKey(
      sharedSecret,
      salt: Uint8List(32),
      info: utf8.encode('Cryptic Root Key'),
      length: 32,
    );
    
    // Generate initial DH key pair
    final dhKeyPair = _x25519.generateKeyPair();
    
    // Perform DH ratchet step
    final dhOutput = _x25519.computeSharedSecret(
      dhKeyPair.privateKey,
      peerDHPublicKey,
    );
    
    // Derive new root key and sending chain key
    final kdfOutput = _hkdf.deriveKey(
      Uint8List.fromList([...rootKey, ...dhOutput]),
      salt: Uint8List(32),
      info: utf8.encode('Cryptic Chain Key'),
      length: 64,
    );
    
    final newRootKey = kdfOutput.sublist(0, 32);
    final sendingChainKey = kdfOutput.sublist(32, 64);
    
    return SessionState(
      rootKey: newRootKey,
      sendingChainKey: sendingChainKey,
      receivingChainKey: null,
      dhKeyPair: dhKeyPair,
      peerDHPublic: peerDHPublicKey,
      sendingChainLength: 0,
      receivingChainLength: 0,
      previousSendingChainLength: 0,
      skippedMessageKeys: {},
    );
  }
  
  // Encrypt message
  Future<EncryptedMessage> encrypt(
    SessionState session,
    String plaintext,
  ) async {
    // Derive message key from chain key
    final messageKey = _hkdf.deriveKey(
      session.sendingChainKey!,
      salt: Uint8List(32),
      info: utf8.encode('Cryptic Message Key'),
      length: 32,
    );
    
    // Advance chain key
    final newChainKey = _hkdf.deriveKey(
      session.sendingChainKey!,
      salt: Uint8List(32),
      info: utf8.encode('Cryptic Chain Step'),
      length: 32,
    );
    
    // Encrypt plaintext
    final nonce = _generateNonce();
    final ciphertext = _aead.encrypt(
      key: messageKey,
      nonce: nonce,
      plaintext: utf8.encode(plaintext),
      additionalData: Uint8List(0),
    );
    
    final newSession = session.copyWith(
      sendingChainKey: newChainKey,
      sendingChainLength: session.sendingChainLength + 1,
    );
    
    return EncryptedMessage(
      ciphertext: Uint8List.fromList([...nonce, ...ciphertext]),
      dhPublic: session.dhKeyPair.publicKey,
      previousChainLength: session.previousSendingChainLength,
      messageNumber: session.sendingChainLength,
      newSession: newSession,
    );
  }
  
  // Decrypt message
  Future<DecryptedMessage> decrypt(
    SessionState session,
    Uint8List ciphertext, {
    required Uint8List dhPublic,
    required int previousChainLength,
    required int messageNumber,
  }) async {
    // Check if we need to perform DH ratchet
    SessionState workingSession = session;
    if (!_bytesEqual(dhPublic, session.peerDHPublic!)) {
      workingSession = await _performDHRatchet(session, dhPublic);
    }
    
    // Check for skipped messages
    final skippedKey = '${base64Encode(dhPublic)}:$messageNumber';
    if (workingSession.skippedMessageKeys.containsKey(skippedKey)) {
      final messageKey = workingSession.skippedMessageKeys[skippedKey]!;
      return await _decryptWithKey(ciphertext, messageKey, workingSession);
    }
    
    // Skip messages if needed
    while (workingSession.receivingChainLength < messageNumber) {
      final skippedMessageKey = _deriveMessageKey(
        workingSession.receivingChainKey!,
      );
      
      final key = '${base64Encode(dhPublic)}:${workingSession.receivingChainLength}';
      workingSession = workingSession.copyWith(
        skippedMessageKeys: {
          ...workingSession.skippedMessageKeys,
          key: skippedMessageKey,
        },
      );
      
      workingSession = _advanceChainKey(workingSession, isReceiving: true);
    }
    
    // Derive message key
    final messageKey = _deriveMessageKey(workingSession.receivingChainKey!);
    
    // Advance chain key
    final newSession = _advanceChainKey(workingSession, isReceiving: true);
    
    return await _decryptWithKey(ciphertext, messageKey, newSession);
  }
  
  Future<SessionState> _performDHRatchet(
    SessionState session,
    Uint8List peerDHPublic,
  ) async {
    // Generate new DH key pair
    final newDHKeyPair = _x25519.generateKeyPair();
    
    // Perform DH
    final dhOutput = _x25519.computeSharedSecret(
      newDHKeyPair.privateKey,
      peerDHPublic,
    );
    
    // Derive new root key and receiving chain key
    final kdfOutput = _hkdf.deriveKey(
      Uint8List.fromList([...session.rootKey, ...dhOutput]),
      salt: Uint8List(32),
      info: utf8.encode('Cryptic Chain Key'),
      length: 64,
    );
    
    final newRootKey = kdfOutput.sublist(0, 32);
    final receivingChainKey = kdfOutput.sublist(32, 64);
    
    // Perform sending DH ratchet
    final sendingDHOutput = _x25519.computeSharedSecret(
      newDHKeyPair.privateKey,
      peerDHPublic,
    );
    
    final sendingKdfOutput = _hkdf.deriveKey(
      Uint8List.fromList([...newRootKey, ...sendingDHOutput]),
      salt: Uint8List(32),
      info: utf8.encode('Cryptic Chain Key'),
      length: 64,
    );
    
    final finalRootKey = sendingKdfOutput.sublist(0, 32);
    final sendingChainKey = sendingKdfOutput.sublist(32, 64);
    
    return session.copyWith(
      rootKey: finalRootKey,
      sendingChainKey: sendingChainKey,
      receivingChainKey: receivingChainKey,
      dhKeyPair: newDHKeyPair,
      peerDHPublic: peerDHPublic,
      previousSendingChainLength: session.sendingChainLength,
      sendingChainLength: 0,
      receivingChainLength: 0,
    );
  }
  
  Uint8List _deriveMessageKey(Uint8List chainKey) {
    return _hkdf.deriveKey(
      chainKey,
      salt: Uint8List(32),
      info: utf8.encode('Cryptic Message Key'),
      length: 32,
    );
  }
  
  SessionState _advanceChainKey(SessionState session, {required bool isReceiving}) {
    final chainKey = isReceiving 
        ? session.receivingChainKey! 
        : session.sendingChainKey!;
    
    final newChainKey = _hkdf.deriveKey(
      chainKey,
      salt: Uint8List(32),
      info: utf8.encode('Cryptic Chain Step'),
      length: 32,
    );
    
    if (isReceiving) {
      return session.copyWith(
        receivingChainKey: newChainKey,
        receivingChainLength: session.receivingChainLength + 1,
      );
    } else {
      return session.copyWith(
        sendingChainKey: newChainKey,
        sendingChainLength: session.sendingChainLength + 1,
      );
    }
  }
  
  Future<DecryptedMessage> _decryptWithKey(
    Uint8List ciphertext,
    Uint8List messageKey,
    SessionState session,
  ) async {
    // Extract nonce (first 12 bytes)
    final nonce = ciphertext.sublist(0, 12);
    final encrypted = ciphertext.sublist(12);
    
    // Decrypt
    final plaintext = _aead.decrypt(
      key: messageKey,
      nonce: nonce,
      ciphertext: encrypted,
      additionalData: Uint8List(0),
    );
    
    return DecryptedMessage(
      plaintext: utf8.decode(plaintext),
      newSession: session,
    );
  }
  
  Uint8List _generateNonce() {
    final random = Random.secure();
    return Uint8List.fromList(
      List.generate(12, (_) => random.nextInt(256)),
    );
  }
  
  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
```

## UI Layer with Riverpod

### State Management

```dart
// Provider for CrypticEngine
final crypticEngineProvider = StateNotifierProvider<CrypticEngineNotifier, EngineState>((ref) {
  return CrypticEngineNotifier();
});

class CrypticEngineNotifier extends StateNotifier<EngineState> {
  CrypticEngine? _engine;
  
  CrypticEngineNotifier() : super(EngineState.initial());
  
  Future<void> initialize(String username, String passphrase) async {
    state = state.copyWith(status: EngineStatus.initializing);
    
    try {
      _engine = CrypticEngine(
        username: username,
        crypto: CryptoRepositoryImpl(),
        network: WebSocketClientImpl(),
        storage: StorageRepositoryImpl(),
      );
      
      await _engine!.initialize(passphrase);
      
      // Listen to message stream
      _engine!.messageStream.listen((message) {
        // Update messages state
      });
      
      state = state.copyWith(
        status: EngineStatus.ready,
        username: username,
      );
    } catch (e) {
      state = state.copyWith(
        status: EngineStatus.error,
        errorMessage: e.toString(),
      );
    }
  }
  
  Future<void> sendMessage(String toUser, String text) async {
    await _engine?.sendMessage(toUser, text);
  }
}

// Provider for messages
final messagesProvider = StreamProvider.family<List<Message>, String>((ref, peerUsername) {
  final storage = ref.watch(storageRepositoryProvider);
  return storage.getMessagesStream(peerUsername);
});

// Provider for contacts
final contactsProvider = FutureProvider<List<String>>((ref) async {
  final network = ref.watch(networkRepositoryProvider);
  return await network.listUsers();
});
```

### Chat Screen

```dart
class ChatScreen extends ConsumerWidget {
  final String peerUsername;
  
  const ChatScreen({required this.peerUsername});
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final messagesAsync = ref.watch(messagesProvider(peerUsername));
    final engineState = ref.watch(crypticEngineProvider);
    
    return Scaffold(
      appBar: AppBar(
        title: Text(peerUsername),
        subtitle: Text(engineState.connectionStatus),
        actions: [
          IconButton(
            icon: Icon(Icons.info),
            onPressed: () => _showContactInfo(context),
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: messagesAsync.when(
              data: (messages) => ListView.builder(
                reverse: true,
                itemCount: messages.length,
                itemBuilder: (context, index) {
                  final message = messages[index];
                  return MessageBubble(
                    message: message,
                    isMe: message.from == engineState.username,
                  );
                },
              ),
              loading: () => Center(child: CircularProgressIndicator()),
              error: (error, stack) => Center(child: Text('Error: $error')),
            ),
          ),
          MessageInputField(
            onSend: (text) {
              ref.read(crypticEngineProvider.notifier)
                  .sendMessage(peerUsername, text);
            },
          ),
        ],
      ),
    );
  }
}
```

## Key Flutter Packages

```yaml
dependencies:
  flutter:
    sdk: flutter
  
  # Crypto
  pointycastle: ^3.9.0              # Ed25519, X25519, ChaCha20-Poly1305
  cryptography: ^2.7.0              # Additional crypto utilities
  
  # Network
  web_socket_channel: ^2.4.0        # WebSocket client
  http: ^1.1.0                      # HTTP for REST endpoints
  
  # Storage
  flutter_secure_storage: ^9.0.0   # Secure key storage
  sqflite_sqlcipher: ^3.0.0        # Encrypted SQLite
  hive_flutter: ^1.1.0             # Alternative key-value store
  
  # State Management
  flutter_riverpod: ^2.4.0         # Reactive state management
  
  # Utilities
  uuid: ^4.2.0                      # Generate message IDs
  path_provider: ^2.1.0            # File paths
  logger: ^2.0.0                   # Logging
  intl: ^0.18.0                    # Date formatting
  
dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.4.0                  # Mocking for tests
  integration_test:
    sdk: flutter
```

## Testing Strategy

### Unit Tests

```dart
// test/unit/crypto/x3dh_test.dart
void main() {
  group('X3DH Protocol', () {
    late X3DHEngine engine;
    
    setUp(() {
      engine = X3DHEngine();
    });
    
    test('should generate valid identity keys', () async {
      final keys = await engine.generateIdentityKeys();
      
      expect(keys.identitySignPublic.length, equals(32));
      expect(keys.identityDHPublic.length, equals(32));
      expect(keys.signedPrekeySignature.length, equals(64));
    });
    
    test('should perform X3DH key agreement', () async {
      // Alice (initiator)
      final aliceKeys = await engine.generateIdentityKeys();
      
      // Bob (responder)
      final bobKeys = await engine.generateIdentityKeys();
      final bobBundle = PrekeyBundle.from(bobKeys);
      
      // Alice performs X3DH
      final aliceResult = await engine.performX3DH(
        identityKeys: aliceKeys,
        peerBundle: bobBundle,
      );
      
      // Bob receives X3DH
      final bobResult = await engine.receiveX3DH(
        identityKeys: bobKeys,
        peerIdentityKey: aliceKeys.identityDHPublic,
        peerEphemeralKey: aliceResult.ephemeralPublic,
        usedOTPKId: null,
      );
      
      // Shared secrets should match
      expect(aliceResult.sharedKey, equals(bobResult.sharedKey));
    });
  });
}
```

### Integration Tests

```dart
// test/integration/message_flow_test.dart
void main() {
  testWidgets('should send and receive encrypted messages', (tester) async {
    // Initialize Alice's engine
    final alice = CrypticEngine(
      username: 'alice',
      crypto: MockCryptoRepository(),
      network: MockNetworkRepository(),
      storage: MockStorageRepository(),
    );
    await alice.initialize('password');
    
    // Initialize Bob's engine
    final bob = CrypticEngine(
      username: 'bob',
      crypto: MockCryptoRepository(),
      network: MockNetworkRepository(),
      storage: MockStorageRepository(),
    );
    await bob.initialize('password');
    
    // Alice sends message to Bob
    await alice.sendMessage('bob', 'Hello Bob!');
    
    // Wait for Bob to receive
    final message = await bob.messageStream.first;
    
    expect(message.from, equals('alice'));
    expect(message.text, equals('Hello Bob!'));
  });
}
```

## Security Considerations

1. **Key Storage**: Use `flutter_secure_storage` with hardware-backed encryption
2. **Database Encryption**: Use `sqflite_sqlcipher` with key derived from user passphrase
3. **Forward Secrecy**: Implement proper Double Ratchet with DH ratchet steps
4. **Certificate Pinning**: Pin CA certificate for mTLS connections
5. **Memory Security**: Clear sensitive data from memory after use
6. **Code Obfuscation**: Enable ProGuard/R8 for Android release builds
7. **Root Detection**: Detect jailbroken/rooted devices and warn users

## Next Steps

1. **Phase 1**: Implement crypto primitives (X3DH, Double Ratchet)
2. **Phase 2**: Implement WebSocket client with mTLS
3. **Phase 3**: Implement storage layer (keys, sessions, messages)
4. **Phase 4**: Implement CrypticEngine orchestration
5. **Phase 5**: Build UI screens
6. **Phase 6**: Testing and security audit
7. **Phase 7**: App store deployment

## UI Layout Design

### Design Philosophy

The Cryptic mobile app should prioritize:
1. **Simplicity**: Clean, uncluttered interface focusing on secure messaging
2. **Privacy First**: Minimal metadata display, no read receipts by default
3. **Security Visibility**: Clear indicators of encryption status and connection security
4. **Offline Support**: Queue messages when offline, show sync status
5. **Dark Theme Default**: Reduce eye strain and battery usage

### Main Navigation Structure

```
┌─────────────────────────────────────────────────────┐
│  Bottom Navigation Bar (3 tabs)                     │
│  ┌────────┬────────┬────────┐                       │
│  │ Chats  │ People │Settings│                       │
│  └────────┴────────┴────────┘                       │
└─────────────────────────────────────────────────────┘
```

### Screen 1: Chats List (Home)

```
┌─────────────────────────────────────────────────────┐
│ ┌─────┐ Cryptic          🔒 Encrypted    [⚙️]        │ AppBar
│ │ 🔐  │                  🟢 Connected                │
│ └─────┘                                             │
├─────────────────────────────────────────────────────┤
│ 🔍 Search conversations...                         │ Search
├─────────────────────────────────────────────────────┤
│ ┌─────┐ Alice                              14:23    │
│ │  A  │ Hey, did you see that?              [2]     │ Chat Item
│ └─────┘ ●●● Typing...                               │ (3 unread)
├─────────────────────────────────────────────────────┤
│ ┌─────┐ Bob                                09:15    │
│ │  B  │ Meeting at 3pm                      ✓✓      │ Chat Item
│ └─────┘                                             │ (read)
├─────────────────────────────────────────────────────┤
│ ┌─────┐ Charlie                        Yesterday    │
│ │  C  │ Thanks for the help!                ✓       │ Chat Item
│ └─────┘                                             │ (delivered)
├─────────────────────────────────────────────────────┤
│ ┌─────┐ Diana                          2 days ago   │
│ │  D  │ 🔄 Establishing secure session...           │ Chat Item
│ └─────┘                                             │ (X3DH in progress)
├─────────────────────────────────────────────────────┤
│                                                     │
│              Empty State:                           │
│        "No conversations yet"                       │
│        "Tap + to start chatting"                    │
│                                                     │
└─────────────────────────────────────────────────────┘
│ 🏠 Chats    👥 People    ⚙️ Settings              │ Bottom Nav
└─────────────────────────────────────────────────────┘

                    [+]  Floating Action Button
```

**Features:**
- Avatar with first letter of username (no photos for privacy)
- Connection status indicator (🟢 connected, 🔴 offline, 🟡 reconnecting)
- Encryption status (🔒 encrypted, 🔓 establishing session)
- Message preview (truncated, no sensitive data in notifications)
- Timestamp (smart formatting: time, yesterday, date)
- Delivery status: ✓ sent, ✓✓ delivered (no read receipts for privacy)
- Unread badge count
- Typing indicator when peer is typing
- Swipe actions: Archive, Delete, Pin

### Screen 2: Chat Conversation

```
┌─────────────────────────────────────────────────────┐
│ ← Alice                    🔒 E2EE         [⋮]       │ AppBar
│                         Last seen: Never            │ (Privacy)
├─────────────────────────────────────────────────────┤
│                        [ℹ️ System Notice]           │
│         Session established with Alice              │ System
│         Encryption: Double Ratchet + X3DH           │ Message
│         Fingerprint: F479...DFFF                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────────────────────────────┐           │
│  │ Hey! How are you doing?              │  14:20    │ Their
│  │                                      │     ✓     │ Message
│  └──────────────────────────────────────┘           │
│                                                     │
│                   ┌────────────────────────────┐    │
│            14:23  │ I'm good, thanks!          │    │ Your
│               ✓✓  │ How about you?             │    │ Message
│                   └────────────────────────────┘    │
│                                                     │
│  ┌──────────────────────────────────────┐           │
│  │ Pretty good. Want to grab coffee?    │  14:25    │ Their
│  │                                      │     ✓     │ Message
│  └──────────────────────────────────────┘           │
│                                                     │
│                   ┌────────────────────────────┐    │
│            14:27  │ Sure! When?                │    │ Your
│               🔄  │                            │    │ Message
│                   └────────────────────────────┘    │ (Sending)
│                                                     │
│  ●●● Alice is typing...                             │ Typing
│                                                     │ Indicator
├─────────────────────────────────────────────────────┤
│ [📎] ┌────────────────────────────────┐  [🎤] [📷]   │ Input
│      │ Type a message...              │             │ Toolbar
│      └────────────────────────────────┘      [➤]    │
└─────────────────────────────────────────────────────┘
```

**Features:**
- Message bubbles (theirs left, yours right)
- Timestamp on each message
- Delivery status on your messages
- System messages for key events (session established, key rotated)
- Typing indicator
- Long-press for actions: Copy, Delete, Reply
- Swipe up/down to scroll through history
- Pull down to load older messages
- "Jump to bottom" button when scrolled up
- Input toolbar with:
  - Attachment button (files, not media for privacy)
  - Voice memo button (encrypted audio)
  - Camera button (for sending encrypted photos)
  - Send button

### Screen 3: People (Contacts)

```
┌─────────────────────────────────────────────────────┐
│ People                                      [+]     │ AppBar
│                                                     │
├─────────────────────────────────────────────────────┤
│ 🔍 Search by username...                            │ Search
├─────────────────────────────────────────────────────┤
│ Active Contacts (5)                                 │ Section
├─────────────────────────────────────────────────────┤
│ ┌─────┐ Alice                    🟢 Online          │
│ │  A  │ Last seen: Active now                      │ Contact
│ └─────┘ Fingerprint: F479...DFFF              [💬]  │ Item
├─────────────────────────────────────────────────────┤
│ ┌─────┐ Bob                      🟡 Away            │
│ │  B  │ Last seen: 5 mins ago                      │ Contact
│ └─────┘ Fingerprint: A123...BC45              [💬]  │ Item
├─────────────────────────────────────────────────────┤
│ All Users on Server (12)                            │ Section
├─────────────────────────────────────────────────────┤
│ ┌─────┐ Charlie                  🔴 Offline         │
│ │  C  │ Never contacted                             │ Contact
│ └─────┘ Fingerprint: Not established          [💬]  │ Item
├─────────────────────────────────────────────────────┤
│ ┌─────┐ Diana                                       │
│ │  D  │ Never contacted                             │ Contact
│ └─────┘ Fingerprint: Not established          [💬]  │ Item
├─────────────────────────────────────────────────────┤
│                                                     │
└─────────────────────────────────────────────────────┘
│ 🏠 Chats    👥 People    ⚙️ Settings                 │ Bottom Nav
└─────────────────────────────────────────────────────┘
```

**Features:**
- List all registered users on server
- Show online/offline status (if enabled on server)
- Group into "Active Contacts" (have exchanged messages) and "All Users"
- Show key fingerprint once session established
- Tap to view details
- Tap 💬 to start conversation
- Search/filter by username
- Pull to refresh user list from server

### Screen 4: Contact Detail

```
┌─────────────────────────────────────────────────────┐
│ ← Contact Info                                      │ AppBar
│                                                     │
├─────────────────────────────────────────────────────┤
│           ┌─────────────┐                           │
│           │             │                           │
│           │      A      │  Large Avatar             │
│           │             │                           │
│           └─────────────┘                           │
│                                                     │
│              Alice                                  │ Username
│         alice@cryptic                               │
│                                                     │
│      [🔐 Verify Keys]  [💬 Message]                  │ Actions
│                                                     │
├─────────────────────────────────────────────────────┤
│ Security Information                                │
├─────────────────────────────────────────────────────┤
│ 🔒 Session Status                                   │
│    Active - Double Ratchet Encryption               │
│                                                     │
│ 🔑 Identity Key Fingerprint                         │
│    F479 A1EB AAAD FFF4 3B2C                         │
│    91DE 8A73 BB19 CD45 E8F2                         │
│    [Copy] [QR Code] [Verify in Person]              │
│                                                     │
│ 📊 Session Statistics                               │
│    Messages exchanged: 127                          │
│    Session created: 2 days ago                      │
│    Last message: 5 mins ago                         │
│                                                     │
├─────────────────────────────────────────────────────┤
│ Conversation Settings                               │
├─────────────────────────────────────────────────────┤
│ 🔔 Notifications              [Toggle: ON]          │
│ 📌 Pin conversation            [Toggle: OFF]        │
│ 🗄️ Archive                                          │
│                                                     │
├─────────────────────────────────────────────────────┤
│ Danger Zone                                         │
├─────────────────────────────────────────────────────┤
│ 🔄 Reset Session (New Keys)                         │
│ 🗑️ Delete Conversation                              │
│ 🚫 Block User                                       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**Features:**
- Display key fingerprint prominently
- QR code for in-person verification
- Session statistics
- Conversation management
- Security actions (reset session, verify keys)

### Screen 5: Settings

```
┌─────────────────────────────────────────────────────┐
│ Settings                                            │ AppBar
│                                                     │
├─────────────────────────────────────────────────────┤
│ Account                                             │ Section
├─────────────────────────────────────────────────────┤
│ ┌─────┐ admin                                       │
│ │  @  │ Logged in                                   │ Profile
│ └─────┘ admin@cryptic.local                         │
│         [Change Passphrase]                         │
├─────────────────────────────────────────────────────┤
│ Connection                                          │ Section
├─────────────────────────────────────────────────────┤
│ 🌐 Server: localhost:8443                           │
│    Status: 🟢 Connected                             │
│    [Change Server] [Test Connection]                │
│                                                     │
│ 🔐 Certificate Status                               │
│    Valid until: Dec 31, 2025                        │
│    Fingerprint: A1B2...C3D4                         │
│    [View Details] [Renew]                           │
│                                                     │
├─────────────────────────────────────────────────────┤
│ Security                                            │ Section
├─────────────────────────────────────────────────────┤
│ 🔑 My Identity Key                                  │
│    Fingerprint: F479 A1EB AAAD FFF4...              │
│    [View Full Key] [Export Backup]                  │
│                                                     │
│ 🗄️ Message History                                  │
│    Database: Encrypted                              │
│    Size: 12.4 MB                                    │
│    [Export] [Clear All]                             │
│                                                     │
│ 🔒 Screen Lock                   [Toggle: ON]       │
│    Require passphrase on app start                  │
│                                                     │
│ 📱 Biometric Unlock             [Toggle: OFF]       │
│    Use fingerprint/face to unlock                   │
│                                                     │
├─────────────────────────────────────────────────────┤
│ Privacy                                             │ Section
├─────────────────────────────────────────────────────┤
│ 👁️ Read Receipts                 [Toggle: OFF]      │
│    Let others know when you read messages           │
│                                                     │
│ ✍️ Typing Indicators            [Toggle: ON]        │
│    Show when you're typing                          │
│                                                     │
│ 🕐 Last Seen                     [Toggle: OFF]      │
│    Share your last active time                      │
│                                                     │
│ 📸 Save Media to Gallery         [Toggle: OFF]      │
│    Automatically save received photos               │
│                                                     │
├─────────────────────────────────────────────────────┤
│ Appearance                                          │ Section
├─────────────────────────────────────────────────────┤
│ 🎨 Theme                        [Dark]              │
│    Options: Light, Dark, System                     │
│                                                     │
│ 💬 Message Text Size            [Medium]            │
│    Options: Small, Medium, Large                    │
│                                                     │
├─────────────────────────────────────────────────────┤
│ Data & Storage                                      │ Section
├─────────────────────────────────────────────────────┤
│ 💾 Storage Usage: 45.2 MB                           │
│    Messages: 12.4 MB                                │
│    Keys/Sessions: 2.1 MB                            │
│    Cache: 30.7 MB                                   │
│    [Clear Cache]                                    │
│                                                     │
├─────────────────────────────────────────────────────┤
│ About                                               │ Section
├─────────────────────────────────────────────────────┤
│ ℹ️ Version: 1.0.0 (Build 42)                        │
│ 📚 Documentation                                    │
│ 🐛 Report Bug                                       │
│ 📜 Open Source Licenses                             │
│ 🔐 Security Audit Report                            │
│                                                     │
├─────────────────────────────────────────────────────┤
│ Danger Zone                                         │ Section
├─────────────────────────────────────────────────────┤
│ 🗑️ Delete All Data                                  │
│    Remove all messages, keys, and settings          │
│                                                     │
│ 🚪 Log Out                                          │
│    Disconnect and clear session                     │
│                                                     │
└─────────────────────────────────────────────────────┘
│ 🏠 Chats    👥 People    ⚙️ Settings              │ Bottom Nav
└─────────────────────────────────────────────────────┘
```

**Features:**
- Comprehensive settings organization
- Clear security indicators
- Easy access to key management
- Privacy controls
- Connection management
- Theme customization

### Color Scheme (Dark Theme)

```dart
// lib/core/theme/app_colors.dart
class AppColors {
  // Primary Colors
  static const primary = Color(0xFF4A90E2);      // Blue for trust
  static const secondary = Color(0xFF50C878);    // Green for security
  static const accent = Color(0xFFE94B3C);       // Red for warnings
  
  // Background
  static const background = Color(0xFF121212);   // Near black
  static const surface = Color(0xFF1E1E1E);      // Slightly lighter
  static const card = Color(0xFF2C2C2C);         // Cards/bubbles
  
  // Text
  static const textPrimary = Color(0xFFE0E0E0); // Light gray
  static const textSecondary = Color(0xFF9E9E9E); // Muted gray
  static const textHint = Color(0xFF616161);     // Darker gray
  
  // Status
  static const online = Color(0xFF4CAF50);       // Green
  static const offline = Color(0xFFBDBDBD);      // Gray
  static const away = Color(0xFFFFA726);         // Orange
  
  // Message Bubbles
  static const ownMessageBubble = Color(0xFF2C5F8D);    // Dark blue
  static const otherMessageBubble = Color(0xFF3A3A3A);  // Dark gray
  
  // Security
  static const encrypted = Color(0xFF4CAF50);    // Green lock
  static const unencrypted = Color(0xFFFF9800);  // Orange warning
}
```

### Typography

```dart
// lib/core/theme/app_text_styles.dart
class AppTextStyles {
  static const headline1 = TextStyle(
    fontSize: 24,
    fontWeight: FontWeight.bold,
    color: AppColors.textPrimary,
  );
  
  static const headline2 = TextStyle(
    fontSize: 20,
    fontWeight: FontWeight.w600,
    color: AppColors.textPrimary,
  );
  
  static const bodyLarge = TextStyle(
    fontSize: 16,
    color: AppColors.textPrimary,
  );
  
  static const bodyMedium = TextStyle(
    fontSize: 14,
    color: AppColors.textSecondary,
  );
  
  static const caption = TextStyle(
    fontSize: 12,
    color: AppColors.textHint,
  );
  
  static const messageText = TextStyle(
    fontSize: 15,
    height: 1.4,
    color: AppColors.textPrimary,
  );
}
```

## Alternative Distribution Methods (Non-Store Deployment)

For privacy-focused users who want to avoid Google Play Store or
Apple App Store, here are low-key deployment options:

### 1. Direct APK Distribution (Android)

**Advantages:**
- No Google account required
- No app store approval process
- Complete control over updates
- Works on de-Googled phones (GrapheneOS, CalyxOS, LineageOS)
- Immediate deployment

**Implementation:**

#### Step 1: Build Release APK

```bash
# Build release APK with split ABIs for smaller size
flutter build apk --release --split-per-abi

# Output files (in build/app/outputs/flutter-apk/):
# - app-armeabi-v7a-release.apk  (32-bit ARM, ~20MB)
# - app-arm64-v8a-release.apk    (64-bit ARM, ~25MB) - Most phones
# - app-x86_64-release.apk       (64-bit Intel, for emulators)
```

#### Step 2: Sign APK (Required for Installation)

```bash
# Generate signing key (one time)
keytool -genkey -v -keystore cryptic-release-key.jks \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -alias cryptic-key

# Configure in android/key.properties:
storePassword=<your-password>
keyPassword=<your-password>
keyAlias=cryptic-key
storeFile=/path/to/cryptic-release-key.jks

# Build will automatically sign
flutter build apk --release
```

#### Step 3: Distribute APK

**Option A: Self-Hosted Website**

```nginx
# nginx config for APK hosting
server {
    listen 443 ssl;
    server_name downloads.cryptic.app;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    root /var/www/cryptic/apk;
    
    location /latest {
        alias /var/www/cryptic/apk/app-arm64-v8a-release.apk;
        add_header Content-Disposition 'attachment; filename="cryptic-latest.apk"';
        add_header Content-Type "application/vnd.android.package-archive";
    }
    
    location /verify {
        alias /var/www/cryptic/apk/checksums.txt;
        add_header Content-Type "text/plain";
    }
}
```

Provide checksums for verification:
```bash
# Generate checksums
sha256sum *.apk > checksums.txt
gpg --clearsign checksums.txt

# Users verify:
wget https://downloads.cryptic.app/latest
wget https://downloads.cryptic.app/checksums.txt.asc
gpg --verify checksums.txt.asc
sha256sum -c checksums.txt
```

**Option B: IPFS (Decentralized)**

```bash
# Add APK to IPFS
ipfs add app-arm64-v8a-release.apk
# Returns: QmXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Share IPFS CID (Content Identifier)
# Users download with:
ipfs get QmXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# or via gateway:
https://ipfs.io/ipfs/QmXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Option C: Tor Hidden Service**

```
# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/cryptic_downloads/
HiddenServicePort 80 127.0.0.1:8080

# Restart tor to get .onion address
# Share: http://abc123xyz.onion/cryptic-latest.apk
```

**Option D: Direct File Sharing**

- Email attachment (for trusted contacts)
- Encrypted cloud storage (ProtonDrive, MEGA)
- Syncthing (peer-to-peer sync)
- Physical transfer (USB, NFC)

#### Step 4: User Installation Instructions

**For Users:**

1. **Enable installation from unknown sources:**
   ```
   Settings → Security → Install unknown apps
   → [Your Browser/File Manager] → Allow
   ```

2. **Download APK** from trusted source

3. **Verify checksum:**
   ```bash
   # Using Termux on Android
   pkg install coreutils
   sha256sum cryptic-latest.apk
   # Compare with published checksum
   ```

4. **Install:**
   - Tap downloaded APK file
   - Android will show permissions required
   - Tap "Install"
   - Grant necessary permissions (storage, network)

5. **First run:**
   - App will prompt for passphrase
   - Generate or import identity keys
   - Configure server connection

### 2. F-Droid Repository (Android - Open Source Distribution)

**Advantages:**
- Trusted by privacy-conscious users
- Automatic updates
- Reproducible builds (verifiable)
- No Google required
- Free and open source only

**Requirements:**
- App must be 100% open source
- No proprietary libraries
- No tracking/analytics
- Source code publicly available

**Setup:**

#### Create F-Droid Repository

```bash
# 1. Install fdroidserver
pip install fdroidserver

# 2. Initialize repository
mkdir -p fdroid-repo/{metadata,repo}
cd fdroid-repo
fdroid init

# 3. Configure repository
cat > config.yml <<EOF
repo_name: "Cryptic Messenger"
repo_description: "End-to-end encrypted messaging"
repo_url: "https://fdroid.cryptic.app/repo"
archive_url: "https://fdroid.cryptic.app/archive"
repo_icon: "icon.png"
repo_keyalias: "cryptic-fdroid"
EOF

# 4. Create app metadata
cat > metadata/com.cryptic.messenger.yml <<EOF
Categories:
  - Internet
  - Security
License: MIT
AuthorName: Cryptic Team
AuthorEmail: dev@cryptic.app
SourceCode: https://github.com/etnt/cryptic
IssueTracker: https://github.com/etnt/cryptic/issues

AutoName: Cryptic Messenger
Summary: End-to-end encrypted messaging
Description: |
  Cryptic is a privacy-focused messenger using Signal Protocol.
  Features:
  * X3DH key agreement
  * Double Ratchet encryption
  * mTLS server connection
  * No phone number required
  * No central identity server
  * Offline message queueing

RepoType: git
Repo: https://github.com/etnt/cryptic

Builds:
  - versionName: '1.0.0'
    versionCode: 1
    commit: v1.0.0
    subdir: flutter-app
    output: build/app/outputs/flutter-apk/app-release.apk
    build:
      - flutter build apk --release
    ndk: r21e
EOF

# 5. Build and publish
fdroid update
fdroid publish

# 6. Upload to web server
rsync -avz repo/ user@fdroid.cryptic.app:/var/www/fdroid/
```

#### Users Add Repository

```
F-Droid → Settings → Repositories → Add Repository
URL: https://fdroid.cryptic.app/repo
Fingerprint: <your-repo-fingerprint>
```

### 3. iOS Distribution (Without App Store)

**Option A: TestFlight (Limited to 10,000 testers)**

```bash
# 1. Build for TestFlight
flutter build ipa --release

# 2. Upload via Xcode or Transporter
# 3. Share TestFlight link with testers
# Link expires after 90 days per build
```

**Option B: Ad Hoc Distribution (100 devices max)**

```bash
# 1. Register device UDIDs in Apple Developer Portal
# 2. Create Ad Hoc provisioning profile
# 3. Build with profile
flutter build ipa --export-options-plist=AdHoc.plist

# 4. Distribute IPA via:
#    - Apple Configurator 2
#    - iTunes File Sharing
#    - Direct URL (install via Safari)
```

**Option C: Enterprise Distribution (Requires Apple Enterprise Account)**

```bash
# For in-house distribution only
# Not allowed for public distribution
# Risk of certificate revocation if abused
```

**Option D: Jailbroken Devices (Not Recommended)**

- Install via Cydia/Sileo
- No signing required
- Security implications for users

### 4. Progressive Web App (PWA) - Cross-Platform Alternative

**Advantages:**
- No app store required
- Works on iOS and Android
- Automatic updates
- Single codebase
- No installation required (initially)

**Limitations:**
- Limited cryptographic API access (no secure enclave)
- No background sync (must be open)
- No push notifications on iOS
- Can't access certain device features

**Implementation:**

```dart
// Build Flutter PWA
flutter build web --release

// Deploy to web server
rsync -avz build/web/ user@app.cryptic.io:/var/www/html/

// Users access via browser:
https://app.cryptic.io

// Add to home screen prompt appears
```

**manifest.json for PWA:**
```json
{
  "name": "Cryptic Messenger",
  "short_name": "Cryptic",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#121212",
  "theme_color": "#4A90E2",
  "description": "End-to-end encrypted messaging",
  "icons": [
    {
      "src": "icons/icon-192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "any maskable"
    },
    {
      "src": "icons/icon-512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "any maskable"
    }
  ]
}
```

### 5. Update Mechanism (Without App Stores)

Since you're not using app stores, implement your own update system:

#### In-App Update Checker

```dart
class UpdateChecker {
  static const updateCheckUrl = 'https://api.cryptic.app/version';
  
  Future<UpdateInfo?> checkForUpdates() async {
    try {
      final response = await http.get(Uri.parse(updateCheckUrl));
      final data = jsonDecode(response.body);
      
      final latestVersion = data['version'];
      final currentVersion = await getPackageVersion();
      
      if (_isNewerVersion(latestVersion, currentVersion)) {
        return UpdateInfo(
          version: latestVersion,
          downloadUrl: data['download_url'],
          releaseNotes: data['release_notes'],
          signature: data['signature'],  // GPG signature
          checksum: data['sha256'],
        );
      }
      
      return null;
    } catch (e) {
      print('Update check failed: $e');
      return null;
    }
  }
  
  Future<void> downloadAndInstall(UpdateInfo info) async {
    // 1. Download APK
    final file = await _downloadFile(info.downloadUrl);
    
    // 2. Verify signature
    final isValid = await _verifySignature(file, info.signature);
    if (!isValid) {
      throw Exception('Invalid signature - update rejected');
    }
    
    // 3. Verify checksum
    final checksum = await _calculateChecksum(file);
    if (checksum != info.checksum) {
      throw Exception('Checksum mismatch - update rejected');
    }
    
    // 4. Install (Android only)
    if (Platform.isAndroid) {
      await InstallPlugin.installApk(file.path);
    } else {
      // iOS: Open Safari to TestFlight or show instructions
      await launchUrl(info.downloadUrl);
    }
  }
  
  bool _isNewerVersion(String latest, String current) {
    final latestParts = latest.split('.').map(int.parse).toList();
    final currentParts = current.split('.').map(int.parse).toList();
    
    for (int i = 0; i < 3; i++) {
      if (latestParts[i] > currentParts[i]) return true;
      if (latestParts[i] < currentParts[i]) return false;
    }
    return false;
  }
}
```

#### Version API Endpoint

```json
// https://api.cryptic.app/version
{
  "version": "1.0.1",
  "build": 43,
  "release_date": "2025-11-18",
  "download_url": "https://downloads.cryptic.app/v1.0.1/app-arm64-v8a-release.apk",
  "sha256": "abc123...",
  "signature": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----",
  "release_notes": "- Fixed connection issue\n- Improved message sync",
  "minimum_version": "1.0.0",
  "force_update": false
}
```

### 6. Distribution Comparison

| Method | Android | iOS | Store Approval | Auto-Updates | User Trust | Privacy |
|--------|---------|-----|----------------|--------------|------------|---------|
| Direct APK | ✅ | ❌ | No | Manual | Low | High |
| F-Droid | ✅ | ❌ | Yes (OSS) | Yes | High | High |
| Self-hosted | ✅ | Limited | No | Custom | Medium | High |
| IPFS | ✅ | ❌ | No | Manual | Medium | Very High |
| TestFlight | ❌ | ✅ | Yes | Yes | High | Medium |
| PWA | ✅ | ✅ | No | Automatic | Medium | Medium |
| Play Store | ✅ | ❌ | Yes | Yes | Very High | Low |
| App Store | ❌ | ✅ | Yes | Yes | Very High | Low |

### 7. Recommended Distribution Strategy

**For Maximum Privacy and Control:**

1. **Primary:** Self-hosted APK with GPG signatures
   - Full control
   - No third-party tracking
   - Verifiable downloads

2. **Alternative:** F-Droid repository
   - Trusted by privacy community
   - Reproducible builds
   - Automatic updates

3. **Fallback:** IPFS for censorship resistance
   - Decentralized
   - No takedowns possible
   - Global availability

4. **Web Access:** PWA for quick access
   - No installation required
   - Works everywhere
   - Limited features but functional

**Distribution Workflow:**

```bash
# Release script
#!/bin/bash

VERSION="1.0.1"

# 1. Build APK
flutter build apk --release --split-per-abi

# 2. Sign and verify
jarsigner -verify app-arm64-v8a-release.apk

# 3. Generate checksums
sha256sum *.apk > checksums.txt

# 4. Sign checksums with GPG
gpg --clearsign checksums.txt

# 5. Upload to self-hosted server
scp *.apk checksums.txt.asc user@downloads.cryptic.app:/var/www/apk/v${VERSION}/

# 6. Update version API
curl -X POST https://api.cryptic.app/update-version \
  -H "Authorization: Bearer $API_TOKEN" \
  -d "{\"version\": \"${VERSION}\", \"url\": \"https://downloads.cryptic.app/v${VERSION}/\"}"

# 7. Add to IPFS
ipfs add -r v${VERSION}/ | tee ipfs-cids.txt

# 8. Update F-Droid metadata
cd fdroid-repo
git tag v${VERSION}
fdroid update
fdroid publish

# 9. Announce release
echo "Release ${VERSION} complete!"
echo "APK: https://downloads.cryptic.app/v${VERSION}/"
echo "IPFS: $(cat ipfs-cids.txt | grep 'added' | tail -1 | awk '{print $2}')"
```

## References

- [Signal Protocol Specifications](https://signal.org/docs/)
- [Flutter Cryptography Guide](https://pub.dev/packages/cryptography)
- [PointyCastle Documentation](https://pub.dev/packages/pointycastle)
- [Riverpod State Management](https://riverpod.dev/)
- [F-Droid Build Documentation](https://f-droid.org/docs/Building_Applications/)
- [Android APK Signing](https://developer.android.com/studio/publish/app-signing)
- [Flutter PWA Guide](https://docs.flutter.dev/platform-integration/web/building)
- [IPFS Documentation](https://docs.ipfs.tech/)
