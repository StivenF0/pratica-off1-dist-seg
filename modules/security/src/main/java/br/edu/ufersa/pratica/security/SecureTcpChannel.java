package br.edu.ufersa.pratica.security;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Objects;
import java.util.UUID;

/** Length-prefixed TCP channel established by RSA and protected by one AES/HMAC session. */
public final class SecureTcpChannel implements AutoCloseable {
    private final Socket socket;
    private final SecureSession session;
    private final DataInputStream input;
    private final DataOutputStream output;
    private final Object sendLock = new Object();
    private final Object receiveLock = new Object();

    private SecureTcpChannel(Socket socket, SecureSession session,
                             DataInputStream input, DataOutputStream output) {
        this.socket = socket;
        this.session = session;
        this.input = input;
        this.output = output;
    }

    /** Initiates RSA-OAEP/PSS setup and returns only after the peer proves possession of the session keys. */
    public static SecureTcpChannel connect(Socket socket, LocalIdentity localIdentity,
                                           TrustStore trustStore, String recipient,
                                           ReplayGuard replayGuard)
            throws IOException, GeneralSecurityException {
        validateSocket(socket);
        Objects.requireNonNull(localIdentity, "localIdentity");
        Objects.requireNonNull(trustStore, "trustStore");
        Objects.requireNonNull(replayGuard, "replayGuard");
        int previousTimeout = socket.getSoTimeout();
        DataInputStream input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        DataOutputStream output = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
        SecureHandshake.Pending pending = null;
        try {
            trustStore.requireLocalIdentity(localIdentity);
            replayGuard.ensureReady();
            if (previousTimeout == 0) {
                socket.setSoTimeout((int) CryptoProfile.DEFAULT_HANDSHAKE_TIMEOUT.toMillis());
            }
            pending = SecureHandshake.create(localIdentity, trustStore, recipient);
            writeFrame(output, pending.encodedOffer());
            byte[] ready = readFrame(input);
            if (!SecureHandshake.confirm(pending, ready)) {
                throw new SecurityProtocolException("O peer não confirmou a sessão nova.");
            }
            SecurityAudit.hmac("HMAC_OK", localIdentity.project(), localIdentity.name(), recipient,
                    pending.session().sessionId(), "RECEIVE", "READY");
            return new SecureTcpChannel(socket, pending.session(), input, output);
        } catch (IOException | GeneralSecurityException | RuntimeException exception) {
            closeOnFailure(socket, exception);
            if (pending != null) {
                pending.session().close();
            }
            if (exception instanceof HmacValidationException) {
                SecurityAudit.hmac("HMAC_FAIL", localIdentity.project(), localIdentity.name(), recipient,
                        pending == null ? null : pending.session().sessionId(), "RECEIVE", "READY");
            }
            throw exception;
        } finally {
            restoreTimeout(socket, previousTimeout);
        }
    }

    /** Accepts one signed key offer, validates its HMAC, and returns after sending READY. */
    public static SecureTcpChannel accept(Socket socket, LocalIdentity localIdentity,
                                          TrustStore trustStore, ReplayGuard replayGuard)
            throws IOException, GeneralSecurityException {
        validateSocket(socket);
        Objects.requireNonNull(localIdentity, "localIdentity");
        Objects.requireNonNull(trustStore, "trustStore");
        Objects.requireNonNull(replayGuard, "replayGuard");
        int previousTimeout = socket.getSoTimeout();
        DataInputStream input = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        DataOutputStream output = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
        SecureHandshake.Accepted accepted = null;
        byte[] offer = null;
        try {
            trustStore.requireLocalIdentity(localIdentity);
            replayGuard.ensureReady();
            if (previousTimeout == 0) {
                socket.setSoTimeout((int) CryptoProfile.DEFAULT_HANDSHAKE_TIMEOUT.toMillis());
            }
            offer = readFrame(input);
            accepted = SecureHandshake.accept(offer, localIdentity, trustStore, replayGuard);
            SecurityAudit.hmac("HMAC_OK", localIdentity.project(), localIdentity.name(),
                    accepted.session().remoteIdentity(), accepted.session().sessionId(), "RECEIVE", "KEY_EXCHANGE");
            writeFrame(output, accepted.encodedReady());
            return new SecureTcpChannel(socket, accepted.session(), input, output);
        } catch (IOException | GeneralSecurityException | RuntimeException exception) {
            closeOnFailure(socket, exception);
            if (accepted != null) {
                accepted.session().close();
            }
            if (exception instanceof HmacValidationException) {
                SecurityAudit.hmac("HMAC_FAIL", localIdentity.project(), localIdentity.name(),
                        "desconhecido", offerSessionId(offer), "RECEIVE", "KEY_EXCHANGE");
            }
            throw exception;
        } finally {
            restoreTimeout(socket, previousTimeout);
        }
    }

    /** Encrypts and sends one application payload on this authenticated session. */
    public void send(byte[] payload) throws IOException, GeneralSecurityException {
        byte[] frame = session.seal(payload);
        synchronized (sendLock) {
            try {
                writeFrame(output, frame);
            } catch (IOException exception) {
                session.close();
                closeOnFailure(socket, exception);
                throw exception;
            }
        }
    }

    /** Receives one payload after HMAC, GCM, session, direction, and replay validation. */
    public OpenedMessage receive() throws IOException, GeneralSecurityException {
        synchronized (receiveLock) {
            try {
                OpenedMessage message = session.open(readFrame(input));
                SecurityAudit.hmac("HMAC_OK", session.project(), session.localIdentity(),
                        session.remoteIdentity(), session.sessionId(), "RECEIVE", "DATA");
                return message;
            } catch (IOException | GeneralSecurityException exception) {
                session.close();
                closeOnFailure(socket, exception);
                if (exception instanceof HmacValidationException) {
                    SecurityAudit.hmac("HMAC_FAIL", session.project(), session.localIdentity(),
                            session.remoteIdentity(), session.sessionId(), "RECEIVE", "DATA");
                }
                throw exception;
            }
        }
    }

    public String peerIdentity() {
        return session.remoteIdentity();
    }

    @Override
    public void close() throws IOException {
        session.close();
        socket.close();
    }

    private static void validateSocket(Socket socket) throws IOException {
        Objects.requireNonNull(socket, "socket");
        if (socket.isClosed() || !socket.isConnected()) {
            throw new IOException("O socket TCP precisa estar conectado e aberto.");
        }
        socket.setTcpNoDelay(true);
    }

    private static void writeFrame(DataOutputStream output, byte[] frame) throws IOException {
        if (frame.length < 1 || frame.length > CryptoProfile.MAX_TCP_ENVELOPE_BYTES) {
            throw new IOException("Tamanho de frame TCP inválido.");
        }
        output.writeInt(frame.length);
        output.write(frame);
        output.flush();
    }

    private static byte[] readFrame(DataInputStream input) throws IOException {
        int frameLength = input.readInt();
        if (frameLength < 1 || frameLength > CryptoProfile.MAX_TCP_ENVELOPE_BYTES) {
            throw new IOException("Tamanho de frame TCP inválido.");
        }
        byte[] frame = input.readNBytes(frameLength);
        if (frame.length != frameLength) {
            throw new EOFException("Conexão encerrada no meio de um frame TCP.");
        }
        return frame;
    }

    private static void closeOnFailure(Socket socket, Exception failure) {
        try {
            socket.close();
        } catch (IOException closeFailure) {
            failure.addSuppressed(closeFailure);
        }
    }

    private static void restoreTimeout(Socket socket, int timeout) {
        if (!socket.isClosed()) {
            try {
                socket.setSoTimeout(timeout);
            } catch (IOException ignored) {
                // Socket failure already determines the channel result.
            }
        }
    }

    private static UUID offerSessionId(byte[] offer) {
        try {
            return SecureHandshake.sessionIdFromOffer(offer);
        } catch (IOException ignored) {
            return null;
        }
    }
}
