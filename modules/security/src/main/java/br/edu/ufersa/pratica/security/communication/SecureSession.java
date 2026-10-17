package br.edu.ufersa.pratica.security.communication;

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
import br.edu.ufersa.pratica.security.CryptoProfile;
import br.edu.ufersa.pratica.security.HmacValidationException;
import br.edu.ufersa.pratica.security.SecurityProtocolException;
import br.edu.ufersa.pratica.security.identity.LocalIdentity;
import br.edu.ufersa.pratica.security.identity.TrustedIdentity;

/** AES-256-GCM, HMAC-SHA-256, and RSA-PSS protection for one peer session. */
public final class SecureSession implements AutoCloseable {
    static final int MAGIC = 0x53455333; // SES3
    static final int VERSION = 3;
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
    private final LocalIdentity signer;
    private final TrustedIdentity verifier;
    private final boolean initiator;
    private long nextSendSequence;
    private boolean closed;

    SecureSession(LocalIdentity localIdentity, TrustedIdentity remoteIdentity, UUID sessionId,
                  byte[] aesKey, byte[] hmacKey, boolean initiator) {
        LocalIdentity local = Objects.requireNonNull(localIdentity, "localIdentity");
        TrustedIdentity remote = Objects.requireNonNull(remoteIdentity, "remoteIdentity");
        this.project = local.project();
        this.localIdentity = local.name();
        this.remoteIdentity = remote.name();
        this.sessionId = Objects.requireNonNull(sessionId, "sessionId");
        if (aesKey == null || aesKey.length != CryptoProfile.AES_KEY_BYTES
                || hmacKey == null || hmacKey.length != CryptoProfile.HMAC_KEY_BYTES
                || MessageDigest.isEqual(aesKey, hmacKey)) {
            throw new IllegalArgumentException("A sessão precisa de chaves AES-256 e HMAC-SHA-256 independentes.");
        }
        this.aesKey = aesKey.clone();
        this.hmacKey = hmacKey.clone();
        this.signer = local;
        this.verifier = remote;
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

    /** Opens a frame after validating HMAC, signature, GCM tag, and direction. */
    public synchronized byte[] open(byte[] encoded) throws GeneralSecurityException {
        ParsedFrame frame;
        try {
            frame = parse(encoded);
        } catch (IOException exception) {
            throw new SecurityProtocolException("Frame de sessão inválido.", exception);
        }
        if (frame.type() != APPLICATION) {
            throw new SecurityProtocolException("O frame não contém uma mensagem de aplicação.");
        }
        return open(frame, encoded, APPLICATION);
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
        byte[] ready = open(frame, encoded, READY);
        if (!Arrays.equals(ready, readyPayload())) {
            throw new SecurityProtocolException("Confirmação de sessão inválida.");
        }
        return true;
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
        if (payload.length > CryptoProfile.MAX_SESSION_PAYLOAD_BYTES) {
            throw new SecurityProtocolException("Payload excede o limite permitido para um frame.");
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
            byte[] unsigned = concat(authenticated, mac);
            byte[] frame = concat(unsigned, signer.sign(unsigned));
            if (frame.length > CryptoProfile.MAX_FRAME_BYTES) {
                throw new SecurityProtocolException("Frame excede o limite permitido.");
            }
            return frame;
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private byte[] open(ParsedFrame frame, byte[] encoded, int expectedType) throws GeneralSecurityException {
        ensureOpen();
        int expectedDirection = initiator ? RESPONDER_TO_INITIATOR : INITIATOR_TO_RESPONDER;
        if (frame.type() != expectedType || !frame.sessionId().equals(sessionId)
                || frame.direction() != expectedDirection || frame.sequence() < 0) {
            throw new SecurityProtocolException("Mensagem inválida ou não autenticada.");
        }

        byte[] actualMac = hmac(Arrays.copyOf(encoded, frame.macOffset()));
        byte[] suppliedMac = Arrays.copyOfRange(encoded, frame.macOffset(), frame.signatureOffset());
        if (!MessageDigest.isEqual(actualMac, suppliedMac)) {
            throw new HmacValidationException();
        }

        byte[] unsigned = Arrays.copyOf(encoded, frame.signatureOffset());
        byte[] signature = Arrays.copyOfRange(encoded, frame.signatureOffset(), encoded.length);
        boolean validSignature;
        try {
            validSignature = verifier.verify(unsigned, signature);
        } catch (GeneralSecurityException exception) {
            throw new SecurityProtocolException("Assinatura digital inválida.", exception);
        }
        if (!validSignature) {
            throw new SecurityProtocolException("Assinatura digital inválida.");
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

        byte[] payload = plaintext.clone();
        Arrays.fill(plaintext, (byte) 0);
        return payload;
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
                + CryptoProfile.GCM_TAG_BYTES + CryptoProfile.HMAC_BYTES + CryptoProfile.SIGNATURE_BYTES
                || encoded.length > CryptoProfile.MAX_FRAME_BYTES) {
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
        long expected = (long) headerLength + ciphertextLength + CryptoProfile.HMAC_BYTES
                + CryptoProfile.SIGNATURE_BYTES;
        if (type != APPLICATION && type != READY || direction != INITIATOR_TO_RESPONDER
                && direction != RESPONDER_TO_INITIATOR || sequence < 0
                || ciphertextLength < CryptoProfile.GCM_TAG_BYTES || expected != encoded.length) {
            throw new IOException("Campos ou comprimentos inválidos no frame de sessão.");
        }
        int signatureOffset = encoded.length - CryptoProfile.SIGNATURE_BYTES;
        return new ParsedFrame(type, new UUID(most, least), direction, sequence, headerLength,
                headerLength + ciphertextLength, signatureOffset);
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
                               int headerLength, int macOffset, int signatureOffset) {
        int ciphertextOffset() {
            return headerLength;
        }
    }

}
