package br.edu.ufersa.pratica.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** AES-256-GCM and HMAC-SHA-256 message protection for one authenticated peer session. */
public final class SecureSession implements AutoCloseable {
    static final int MAGIC = 0x53455332; // SES2
    static final int VERSION = 2;
    static final int APPLICATION = 0;
    static final int READY = 1;
    static final int INITIATOR_TO_RESPONDER = 0;
    static final int RESPONDER_TO_INITIATOR = 1;

    private final String project;
    private final String localIdentity;
    private final String remoteIdentity;
    private final UUID sessionId;
    private final byte[] aesKey;
    private final byte[] hmacKey;
    private final boolean initiator;
    private final ReceiveWindow receiveWindow = new ReceiveWindow();
    private long nextSendSequence;
    private boolean closed;

    SecureSession(String project, String localIdentity, String remoteIdentity, UUID sessionId,
                  byte[] aesKey, byte[] hmacKey, boolean initiator) {
        this.project = Objects.requireNonNull(project, "project");
        this.localIdentity = Objects.requireNonNull(localIdentity, "localIdentity");
        this.remoteIdentity = Objects.requireNonNull(remoteIdentity, "remoteIdentity");
        this.sessionId = Objects.requireNonNull(sessionId, "sessionId");
        if (aesKey == null || aesKey.length != CryptoProfile.AES_KEY_BYTES
                || hmacKey == null || hmacKey.length != CryptoProfile.HMAC_KEY_BYTES
                || MessageDigest.isEqual(aesKey, hmacKey)) {
            throw new IllegalArgumentException("A sessão precisa de chaves AES-256 e HMAC-SHA-256 independentes.");
        }
        this.aesKey = aesKey.clone();
        this.hmacKey = hmacKey.clone();
        this.initiator = initiator;
    }

    public String project() {
        return project;
    }

    public String localIdentity() {
        return localIdentity;
    }

    public String remoteIdentity() {
        return remoteIdentity;
    }

    public UUID sessionId() {
        return sessionId;
    }

    /** Creates an encrypted application frame. A session never reuses a direction/sequence IV. */
    public synchronized byte[] seal(byte[] payload) throws GeneralSecurityException {
        Objects.requireNonNull(payload, "payload");
        return seal(APPLICATION, payload);
    }

    /** Opens an application frame after its HMAC, GCM tag, direction, and replay window pass. */
    public synchronized OpenedMessage open(byte[] encoded) throws GeneralSecurityException {
        ParsedFrame frame;
        try {
            frame = parse(encoded);
        } catch (IOException exception) {
            throw new SecurityProtocolException("Frame de sessão inválido.", exception);
        }
        if (frame.type() != APPLICATION) {
            throw new SecurityProtocolException("O frame não contém uma mensagem de aplicação.");
        }
        return open(frame, encoded, APPLICATION, false);
    }

    synchronized byte[] sealReady() throws GeneralSecurityException {
        return seal(READY, readyPayload());
    }

    synchronized boolean confirmReady(byte[] encoded) throws GeneralSecurityException {
        ParsedFrame frame;
        try {
            frame = parse(encoded);
        } catch (IOException exception) {
            throw new SecurityProtocolException("Confirmação de sessão inválida.", exception);
        }
        if (frame.type() != READY || frame.sequence() != 0) {
            throw new SecurityProtocolException("Confirmação de sessão inválida.");
        }
        OpenedMessage ready = open(frame, encoded, READY, true);
        if (ready.duplicate()) {
            return false;
        }
        if (!Arrays.equals(ready.payload(), readyPayload())) {
            throw new SecurityProtocolException("Confirmação de sessão inválida.");
        }
        return !ready.duplicate();
    }

    synchronized boolean isInitiator() {
        return initiator;
    }

    synchronized boolean matchesReady(byte[] encoded) {
        try {
            ParsedFrame frame = parse(encoded);
            return frame.type() == READY && frame.sessionId().equals(sessionId);
        } catch (IOException | IllegalArgumentException exception) {
            return false;
        }
    }

    static boolean isSessionFrame(byte[] encoded) {
        return encoded != null && encoded.length >= 4 && ByteBuffer.wrap(encoded).getInt() == MAGIC;
    }

    static UUID sessionIdFromFrame(byte[] encoded) throws IOException {
        ParsedFrame frame = parse(encoded);
        return frame.sessionId();
    }

    static int frameType(byte[] encoded) throws IOException {
        return parse(encoded).type();
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            Arrays.fill(aesKey, (byte) 0);
            Arrays.fill(hmacKey, (byte) 0);
            closed = true;
        }
    }

    private byte[] seal(int type, byte[] payload) throws GeneralSecurityException {
        ensureOpen();
        if (payload.length > CryptoProfile.MAX_TCP_SESSION_PAYLOAD_BYTES) {
            throw new SecurityProtocolException("Payload excede o limite permitido para TCP.");
        }
        if (nextSendSequence == Long.MAX_VALUE) {
            throw new SecurityProtocolException("A sequência da sessão esgotou; negocie uma sessão nova.");
        }

        byte[] plaintext = payload.clone();
        long sequence = nextSendSequence++;
        try {
            int direction = initiator ? INITIATOR_TO_RESPONDER : RESPONDER_TO_INITIATOR;
            int ciphertextLength = Math.addExact(plaintext.length, CryptoProfile.GCM_TAG_BYTES);
            byte[] header = encodeHeader(type, direction, sequence, ciphertextLength);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new GCMParameterSpec(CryptoProfile.GCM_TAG_BITS, iv(direction, sequence)), CryptoProfile.RANDOM);
            cipher.updateAAD(header);
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] authenticated = concat(header, ciphertext);
            byte[] mac = hmac(authenticated);
            byte[] frame = concat(authenticated, mac);
            if (frame.length > CryptoProfile.MAX_TCP_ENVELOPE_BYTES) {
                throw new SecurityProtocolException("Frame excede o limite TCP.");
            }
            return frame;
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private OpenedMessage open(ParsedFrame frame, byte[] encoded, int expectedType, boolean allowDuplicate)
            throws GeneralSecurityException {
        ensureOpen();
        int expectedDirection = initiator ? RESPONDER_TO_INITIATOR : INITIATOR_TO_RESPONDER;
        if (frame.type() != expectedType || !frame.sessionId().equals(sessionId)
                || frame.direction() != expectedDirection || frame.sequence() < 0) {
            throw new SecurityProtocolException("Mensagem inválida ou não autenticada.");
        }

        byte[] actualMac = hmac(Arrays.copyOf(encoded, frame.macOffset()));
        byte[] suppliedMac = Arrays.copyOfRange(encoded, frame.macOffset(), encoded.length);
        if (!MessageDigest.isEqual(actualMac, suppliedMac)) {
            throw new HmacValidationException();
        }

        byte[] ciphertext = Arrays.copyOfRange(encoded, frame.ciphertextOffset(), frame.macOffset());
        byte[] plaintext;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new GCMParameterSpec(CryptoProfile.GCM_TAG_BITS, iv(frame.direction(), frame.sequence())));
            cipher.updateAAD(Arrays.copyOf(encoded, frame.headerLength()));
            plaintext = cipher.doFinal(ciphertext);
        } catch (AEADBadTagException exception) {
            throw new SecurityProtocolException("Mensagem inválida ou não autenticada.", exception);
        }

        boolean fresh = receiveWindow.claim(frame.sequence());
        if (!fresh && !allowDuplicate) {
            Arrays.fill(plaintext, (byte) 0);
            return new OpenedMessage(project, remoteIdentity, localIdentity, sessionId,
                    frame.sequence(), new byte[0], true);
        }
        OpenedMessage message = new OpenedMessage(project, remoteIdentity, localIdentity, sessionId,
                frame.sequence(), fresh ? plaintext : new byte[0], !fresh);
        Arrays.fill(plaintext, (byte) 0);
        return message;
    }

    private byte[] hmac(byte[] bytes) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
        return mac.doFinal(bytes);
    }

    private byte[] readyPayload() {
        String initiatorName = initiator ? localIdentity : remoteIdentity;
        String responderName = initiator ? remoteIdentity : localIdentity;
        return ("READY\n" + project + "\n" + initiatorName + "\n" + responderName + "\n" + sessionId)
                .getBytes(StandardCharsets.US_ASCII);
    }

    private byte[] encodeHeader(int type, int direction, long sequence, int ciphertextLength)
            throws GeneralSecurityException {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(CryptoProfile.SESSION_HEADER_BYTES);
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeInt(MAGIC);
            out.writeByte(VERSION);
            out.writeByte(type);
            out.writeLong(sessionId.getMostSignificantBits());
            out.writeLong(sessionId.getLeastSignificantBits());
            out.writeByte(direction);
            out.writeLong(sequence);
            out.writeInt(ciphertextLength);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new GeneralSecurityException("Não foi possível montar o cabeçalho da sessão.", exception);
        }
    }

    private static ParsedFrame parse(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length < CryptoProfile.SESSION_HEADER_BYTES
                + CryptoProfile.GCM_TAG_BYTES + CryptoProfile.HMAC_BYTES
                || encoded.length > CryptoProfile.MAX_TCP_ENVELOPE_BYTES) {
            throw new IOException("Tamanho inválido do frame de sessão.");
        }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(encoded));
        if (in.readInt() != MAGIC || in.readUnsignedByte() != VERSION) {
            throw new IOException("Magic ou versão de sessão desconhecidos.");
        }
        int type = in.readUnsignedByte();
        long most = in.readLong();
        long least = in.readLong();
        int direction = in.readUnsignedByte();
        long sequence = in.readLong();
        int ciphertextLength = in.readInt();
        int headerLength = encoded.length - in.available();
        long expected = (long) headerLength + ciphertextLength + CryptoProfile.HMAC_BYTES;
        if (type != APPLICATION && type != READY || direction != INITIATOR_TO_RESPONDER
                && direction != RESPONDER_TO_INITIATOR || sequence < 0
                || ciphertextLength < CryptoProfile.GCM_TAG_BYTES || expected != encoded.length) {
            throw new IOException("Campos ou comprimentos inválidos no frame de sessão.");
        }
        return new ParsedFrame(type, new UUID(most, least), direction, sequence, headerLength,
                headerLength + ciphertextLength);
    }

    private static byte[] iv(int direction, long sequence) {
        return ByteBuffer.allocate(CryptoProfile.GCM_IV_BYTES).putInt(direction).putLong(sequence).array();
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private void ensureOpen() throws SecurityProtocolException {
        if (closed) {
            throw new SecurityProtocolException("A sessão segura foi encerrada.");
        }
    }

    private record ParsedFrame(int type, UUID sessionId, int direction, long sequence,
                               int headerLength, int macOffset) {
        int ciphertextOffset() {
            return headerLength;
        }
    }

    private static final class ReceiveWindow {
        private long highest = -1;
        private long seen;

        boolean claim(long sequence) {
            if (highest < 0) {
                highest = sequence;
                seen = 1;
                return true;
            }
            if (sequence > highest) {
                long shift = sequence - highest;
                seen = shift >= Long.SIZE ? 1 : (seen << (int) shift) | 1;
                highest = sequence;
                return true;
            }
            long behind = highest - sequence;
            if (behind >= Long.SIZE) {
                return false;
            }
            long bit = 1L << (int) behind;
            if ((seen & bit) != 0) {
                return false;
            }
            seen |= bit;
            return true;
        }
    }
}
