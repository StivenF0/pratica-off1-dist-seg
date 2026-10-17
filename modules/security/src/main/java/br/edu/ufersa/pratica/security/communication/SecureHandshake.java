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
import java.util.Map;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import br.edu.ufersa.pratica.security.CryptoProfile;
import br.edu.ufersa.pratica.security.HmacValidationException;
import br.edu.ufersa.pratica.security.SecurityProtocolException;
import br.edu.ufersa.pratica.security.identity.IdentityNames;
import br.edu.ufersa.pratica.security.identity.LocalIdentity;
import br.edu.ufersa.pratica.security.identity.TrustedIdentity;

/** RSA-OAEP session setup for the application-owned socket handshake. */
public final class SecureHandshake {
    private static final int MAGIC = 0x4B455933; // KEY3
    private static final int VERSION = 3;
    private static final int MAX_IDENTIFIER_BYTES = 64;

    private SecureHandshake() {
    }

    public static Pending create(LocalIdentity initiator, TrustedIdentity recipient)
            throws GeneralSecurityException {
        if (initiator == null || recipient == null) {
            throw new NullPointerException("initiator e recipient são obrigatórios.");
        }
        if (initiator.name().equals(recipient.name())) {
            throw new SecurityProtocolException("Uma identidade não pode negociar uma sessão consigo mesma.");
        }

        byte[] aesKey = null;
        byte[] hmacKey = new byte[CryptoProfile.HMAC_KEY_BYTES];
        byte[] material = null;
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(CryptoProfile.AES_KEY_BITS, CryptoProfile.RANDOM);
            SecretKey generated = generator.generateKey();
            aesKey = generated.getEncoded();
            if (aesKey == null || aesKey.length != CryptoProfile.AES_KEY_BYTES) {
                throw new GeneralSecurityException("O provedor não gerou uma chave AES-256.");
            }
            CryptoProfile.RANDOM.nextBytes(hmacKey);
            material = concat(aesKey, hmacKey);
            byte[] wrappedKeys = recipient.wrapSessionKeys(material);
            UUID sessionId = UUID.randomUUID();
            byte[] header = encodeHeader(initiator.project(), initiator.name(), recipient.name(),
                    sessionId, wrappedKeys.length);
            byte[] authenticated = concat(header, wrappedKeys);
            byte[] unsigned = concat(authenticated, hmac(hmacKey, authenticated));
            byte[] offer = concat(unsigned, initiator.sign(unsigned));
            if (offer.length > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
                throw new SecurityProtocolException("A oferta de sessão excede o limite UDP de 1200 bytes.");
            }
            SecureSession session = new SecureSession(initiator, recipient, sessionId, aesKey, hmacKey, true);
            return new Pending(session, offer);
        } finally {
            if (aesKey != null) {
                Arrays.fill(aesKey, (byte) 0);
            }
            Arrays.fill(hmacKey, (byte) 0);
            if (material != null) {
                Arrays.fill(material, (byte) 0);
            }
        }
    }

    public static Accepted accept(byte[] encoded, LocalIdentity recipient,
                                  Map<String, TrustedIdentity> trustedPeers)
            throws GeneralSecurityException {
        if (recipient == null || trustedPeers == null) {
            throw new NullPointerException("recipient e trustedPeers são obrigatórios.");
        }
        Offer offer;
        try {
            offer = parse(encoded);
        } catch (IOException | IllegalArgumentException exception) {
            throw new SecurityProtocolException("Oferta de sessão inválida.", exception);
        }

        Header header = offer.header();
        if (!header.project().equals(recipient.project()) || !header.recipient().equals(recipient.name())) {
            throw new SecurityProtocolException("Oferta de sessão destinada a outra identidade ou projeto.");
        }
        TrustedIdentity initiator = trustedPeers.get(header.sender());
        if (initiator == null || !initiator.name().equals(header.sender())) {
            throw new SecurityProtocolException("Identidade não confiável para este projeto.");
        }

        byte[] unsigned = Arrays.copyOf(encoded, offer.signatureOffset());
        byte[] signature = Arrays.copyOfRange(encoded, offer.signatureOffset(), encoded.length);
        if (!initiator.verify(unsigned, signature)) {
            throw new SecurityProtocolException("Oferta de sessão inválida ou não autenticada.");
        }

        byte[] wrapped = Arrays.copyOfRange(encoded, offer.wrappedKeysOffset(),
                offer.wrappedKeysOffset() + header.wrappedKeysLength());
        byte[] material = recipient.unwrapSessionKeys(wrapped);
        try {
            if (material.length != CryptoProfile.AES_KEY_BYTES + CryptoProfile.HMAC_KEY_BYTES) {
                throw new SecurityProtocolException("Material criptográfico da sessão inválido.");
            }
            byte[] aesKey = Arrays.copyOfRange(material, 0, CryptoProfile.AES_KEY_BYTES);
            byte[] hmacKey = Arrays.copyOfRange(material, CryptoProfile.AES_KEY_BYTES, material.length);
            try {
                byte[] authenticated = Arrays.copyOf(encoded, offer.macOffset());
                byte[] suppliedMac = Arrays.copyOfRange(encoded, offer.macOffset(), offer.signatureOffset());
                if (!MessageDigest.isEqual(hmac(hmacKey, authenticated), suppliedMac)) {
                    throw new HmacValidationException();
                }
                SecureSession session = new SecureSession(recipient, initiator, header.sessionId(),
                        aesKey, hmacKey, false);
                try {
                    return new Accepted(session, session.sealReady());
                } catch (GeneralSecurityException exception) {
                    session.close();
                    throw exception;
                }
            } finally {
                Arrays.fill(aesKey, (byte) 0);
                Arrays.fill(hmacKey, (byte) 0);
            }
        } finally {
            Arrays.fill(material, (byte) 0);
        }
    }

    public static boolean confirm(Pending pending, byte[] ready) throws GeneralSecurityException {
        if (pending == null) {
            throw new NullPointerException("pending");
        }
        return pending.session().confirmReady(ready);
    }

    public static boolean isOffer(byte[] encoded) {
        return encoded != null && encoded.length >= Integer.BYTES
                && ByteBuffer.wrap(encoded).getInt() == MAGIC;
    }

    private static byte[] encodeHeader(String project, String sender, String recipient, UUID sessionId,
                                       int wrappedLength) throws GeneralSecurityException {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(128);
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeInt(MAGIC);
            out.writeByte(VERSION);
            out.writeLong(sessionId.getMostSignificantBits());
            out.writeLong(sessionId.getLeastSignificantBits());
            writeIdentifier(out, project);
            writeIdentifier(out, sender);
            writeIdentifier(out, recipient);
            out.writeShort(wrappedLength);
            out.writeShort(CryptoProfile.HMAC_BYTES);
            out.writeShort(CryptoProfile.RSA_BYTES);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new GeneralSecurityException("Não foi possível montar o cabeçalho da oferta.", exception);
        }
    }

    private static Offer parse(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length < 128 || encoded.length > CryptoProfile.MAX_FRAME_BYTES) {
            throw new IOException("Tamanho inválido da oferta de sessão.");
        }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(encoded));
        if (in.readInt() != MAGIC || in.readUnsignedByte() != VERSION) {
            throw new IOException("Magic ou versão de oferta desconhecidos.");
        }
        UUID sessionId = new UUID(in.readLong(), in.readLong());
        String project = readIdentifier(in);
        String sender = readIdentifier(in);
        String recipient = readIdentifier(in);
        int wrappedLength = in.readUnsignedShort();
        int macLength = in.readUnsignedShort();
        int signatureLength = in.readUnsignedShort();
        int headerLength = encoded.length - in.available();
        if (wrappedLength != CryptoProfile.RSA_BYTES || macLength != CryptoProfile.HMAC_BYTES
                || signatureLength != CryptoProfile.RSA_BYTES
                || (long) headerLength + wrappedLength + macLength + signatureLength != encoded.length) {
            throw new IOException("Comprimentos criptográficos inválidos na oferta.");
        }
        Header header = new Header(project, sender, recipient, sessionId, wrappedLength);
        int wrappedOffset = headerLength;
        int macOffset = wrappedOffset + wrappedLength;
        return new Offer(header, wrappedOffset, macOffset, macOffset + macLength);
    }

    private static void writeIdentifier(DataOutputStream out, String value) throws IOException {
        IdentityNames.requireValid(value, "Identificador");
        byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
        if (encoded.length > MAX_IDENTIFIER_BYTES) {
            throw new IOException("Identificador excede o tamanho máximo.");
        }
        out.writeByte(encoded.length);
        out.write(encoded);
    }

    private static String readIdentifier(DataInputStream in) throws IOException {
        int length = in.readUnsignedByte();
        if (length < 1 || length > MAX_IDENTIFIER_BYTES) {
            throw new IOException("Tamanho de identificador inválido.");
        }
        byte[] bytes = in.readNBytes(length);
        if (bytes.length != length) {
            throw new IOException("Oferta truncada.");
        }
        for (byte value : bytes) {
            if ((value & 0x80) != 0) {
                throw new IOException("Identificador contém bytes não ASCII.");
            }
        }
        String identifier = new String(bytes, StandardCharsets.US_ASCII);
        try {
            return IdentityNames.requireValid(identifier, "Identificador");
        } catch (IllegalArgumentException exception) {
            throw new IOException("Identificador inválido.", exception);
        }
    }

    private static byte[] hmac(byte[] key, byte[] value) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(value);
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public record Pending(SecureSession session, byte[] encodedOffer) {
        public Pending {
            encodedOffer = encodedOffer.clone();
        }

        @Override
        public byte[] encodedOffer() {
            return encodedOffer.clone();
        }
    }

    public record Accepted(SecureSession session, byte[] encodedReady) {
        public Accepted {
            encodedReady = encodedReady.clone();
        }

        @Override
        public byte[] encodedReady() {
            return encodedReady.clone();
        }
    }

    private record Header(String project, String sender, String recipient, UUID sessionId,
                          int wrappedKeysLength) {
    }

    private record Offer(Header header, int wrappedKeysOffset, int macOffset, int signatureOffset) {
    }
}
