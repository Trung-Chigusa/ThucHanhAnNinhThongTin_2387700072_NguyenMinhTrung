# SecureChat - Design Specification

## Goal

Build the SecureChat portion of Lab 03 as a local, runnable Python application that demonstrates mutual TLS, room-based chat, and client-to-client message encryption. The server relays encrypted envelopes and does not receive message plaintext or client private keys.

## Context and placement

- The assignment source is `Buổi 3/lab-03.pdf`.
- The repository currently contains Buổi 1 work only. SecureChat will live in `Buổi 3/secure-chat/` and will not change the existing Buổi 1 files.
- The PDF demonstrates AES-CBC and sends the AES key to the server over TLS. This implementation will retain the requested concepts while using authenticated encryption and a client-side key agreement so the relay does not see plaintext.

## Architecture

### Certificate-backed transport

- `make-certs.bat` and `openssl.cnf` create a local CA, a server certificate with `localhost` and `127.0.0.1` subject alternative names, and distinct Alice and Bob client certificates.
- The server requires a CA-issued client certificate. Clients validate the server certificate chain and hostname. TLS is limited to TLS 1.2 or later.
- The demo server binds to `127.0.0.1:8443` by default. The README may explain how to bind to a private lab interface; it must not imply that this demo is ready for public Internet deployment.
- Generated certificates, private keys, and local logs are ignored by Git. Only certificate-generation inputs and instructions are committed.

### End-to-end message encryption

- Each client creates an ephemeral X25519 key pair for its connection. Its certificate identity and ephemeral public key are announced to peers through the TLS connection.
- Each client signs its public-key announcement with its own client certificate private key. Peers validate the certificate against the local CA, check the certificate identity and validity, then verify the signature. This prevents the relay from silently replacing a peer's key.
- Clients derive a pairwise key with X25519 and HKDF-SHA256, binding derivation to protocol version, room, participant identities, and both public keys.
- Every chat message is encrypted separately for each recipient with AES-GCM. Sender, recipient, and room are authenticated as associated data. The server routes ciphertext and never logs message bodies.
- The server may observe identities, rooms, timing, and message sizes. It can drop or delay traffic. These metadata and availability risks are outside the lab's encryption goal.

### Server, rooms, and wire protocol

- `server.py` accepts TLS connections on a configurable host and port and handles each client in a daemon thread.
- `ConnectionManager` tracks authenticated client sessions and performs synchronized sends. `RoomManager` manages room membership and broadcast routing.
- Client and server exchange newline-delimited JSON frames with a 64 KiB maximum frame size. Reads must support partial TCP reads and multiple frames in a receive buffer.
- The server accepts only the supported protocol messages, rejects duplicate active identities and invalid room or username values, and removes a client from every room on disconnect.
- `client.py` is a terminal client that joins a room, displays peer identities, sends encrypted messages, and exits cleanly on `exit` or Ctrl+C.

## Files

- `Buổi 3/secure-chat/README.md` - setup, certificate generation, run commands, architecture, and limits.
- `Buổi 3/secure-chat/requirements.txt` - runtime dependency on `cryptography`.
- `Buổi 3/secure-chat/openssl.cnf` and `make-certs.bat` - local CA and demo certificate creation.
- `Buổi 3/secure-chat/securechat/protocol.py` - bounded JSON framing and message validation.
- `Buổi 3/secure-chat/securechat/crypto.py` - X25519, HKDF, certificate/signature checks, and AES-GCM envelopes.
- `Buổi 3/secure-chat/securechat/connection_manager.py` and `room_manager.py` - synchronized session and room state.
- `Buổi 3/secure-chat/server.py` and `client.py` - runnable server and terminal client.
- `Buổi 3/secure-chat/tests/` - automated unit and local TLS integration checks.

## Failure handling

- Invalid or untrusted certificates fail the TLS connection; hostname verification stays enabled.
- Invalid peer certificates, key signatures, message authentication tags, frames, or protocol fields are rejected without logging plaintext.
- A disconnected or slow peer must not hold the global manager lock while sending. Failed sends remove the peer from its rooms.
- Certificate-generation scripts fail rather than silently replacing an existing CA private key.

## Verification and acceptance

1. Automated checks cover encryption/decryption between two clients, rejection of tampered ciphertext and wrong keys, key-announcement signature validation, frame boundaries and malformed frames, and room membership/broadcast behavior.
2. A local TLS integration check confirms the server rejects a client without a trusted certificate and accepts two distinct trusted clients.
3. A two-client chat smoke run confirms both users can join different rooms, exchange messages in the same room, and not read messages from another room.
4. Server-side captured message envelopes contain ciphertext only; no application log records plaintext.
5. `README.md` accurately states that local CA and client private keys are for the lab and must not be committed or reused in production.

## Out of scope

- Public Internet deployment, accounts/password authentication, persistent chat history, file transfer, moderation, and availability guarantees.
- A browser UI; the lab requires a functional chat client and server, and a terminal client keeps the demonstration small and inspectable.
- NetRecon. It is a separate Lab 03 application and receives its own design and plan.

## Secret-handling constraint

The source PDF contains what appears to be a real SMTP app password. It is unrelated to SecureChat and must not be copied into source, environment files, logs, test fixtures, or Git history. If it is genuine, the owner should revoke it.
