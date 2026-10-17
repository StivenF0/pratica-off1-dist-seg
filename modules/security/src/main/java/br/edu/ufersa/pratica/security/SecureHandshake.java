package br.edu.ufersa.pratica.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** RSA-OAEP/PSS session establishment; application data never uses this envelope. */
final class SecureHandshake {
    private static final int MAGIC = 0x4B455932; // KEY2
    private static final int VERSION = 2;
    private static final int MAX_IDENTIFIER_BYTES = 64;

    private SecureHandshake() {
    }

    static Pending create(LocalIdentity initiator, TrustStore trustStore, String recipient)
            throws GeneralSecurityException {
        if (initiator == null || trustStore == null) {
            throw new NullPointerException("initiator e trustStore são obrigatórios.");
        }
        IdentityNames.requireValid(recipient, "O destinatário");
        trustStore.requireLocalIdentity(initiator);
        if (recipient.equals(initiator.name())) {
            throw new SecurityProtocolException("Uma identidade não pode negociar uma sessão consigo mesma.");
        }
        TrustedIdentity destination = trustStore.requireIdentity(recipient);

        long issuedAt = Instant.now().toEpochMilli();
        if (issuedAt <= 0) {
            throw new SecurityProtocolException("O relógio local retornou um instante inválido.");
        }
        long expiresAt;
        try {
            expiresAt = Math.addExact(issuedAt, CryptoProfile.MAX_MESSAGE_LIFETIME.toMillis());
        } catch (ArithmeticException exception) {
            throw new SecurityProtocolException("Validade da oferta fora do limite.", exception);
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
            byte[] wrappedKeys = wrap(material, destination.transportPublicKey());
            UUID sessionId = UUID.randomUUID();
            byte[] header = encodeHeader(initiator.project(), initiator.name(), recipient, sessionId,
                    issuedAt, expiresAt, wrappedKeys.length);
            byte[] authenticated = concat(header, wrappedKeys);
            byte[] offerMac = hmac(hmacKey, authenticated);
            byte[] unsigned = concat(authenticated, offerMac);
            Signature signature = signer(initiator);
            signature.update(unsigned);
            byte[] signed = concat(unsigned, signature.sign());
            if (signed.length > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
                throw new SecurityProtocolException("A oferta de sessão excede o limite UDP de 1200 bytes.");
            }
            SecureSession session = new SecureSession(initiator.project(), initiator.name(), recipient,
                    sessionId, aesKey, hmacKey, true);
            return new Pending(session, signed);
        } catch (ArithmeticException exception) {
            throw new SecurityProtocolException("Não foi possível criar a oferta de sessão.", exception);
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

    static Accepted accept(byte[] encoded, LocalIdentity recipient, TrustStore trustStore,
                           ReplayGuard replayGuard) throws GeneralSecurityException {
        if (recipient == null || trustStore == null || replayGuard == null) {
            throw new NullPointerException("recipient, trustStore e replayGuard são obrigatórios.");
        }
        replayGuard.ensureReady();
        trustStore.requireLocalIdentity(recipient);
        ParsedOffer offer;
        try {
            offer = parse(encoded);
        } catch (IOException | IllegalArgumentException exception) {
            throw new SecurityProtocolException("Oferta de sessão inválida.", exception);
        }

        Header header = offer.header();
        if (!header.project().equals(recipient.project()) || !header.project().equals(trustStore.project())
                || !header.recipient().equals(recipient.name())) {
            throw new SecurityProtocolException("Oferta de sessão destinada a outra identidade ou projeto.");
        }
        TrustedIdentity initiator = trustStore.requireIdentity(header.sender());
        byte[] bytes = encoded.clone();
        try {
            Signature verifier = verifier(initiator);
            verifier.update(bytes, 0, offer.signatureOffset());
            if (!verifier.verify(Arrays.copyOfRange(bytes, offer.signatureOffset(), bytes.length))) {
                throw new SecurityProtocolException("Oferta de sessão inválida ou não autenticada.");
            }
            replayGuard.validateTimestamps(header.issuedAtMillis(), header.expiresAtMillis());

            byte[] wrapped = Arrays.copyOfRange(bytes, offer.wrappedKeysOffset(),
                    offer.wrappedKeysOffset() + header.wrappedKeysLength());
            byte[] material = unwrap(wrapped, recipient);
            try {
                if (material.length != CryptoProfile.AES_KEY_BYTES + CryptoProfile.HMAC_KEY_BYTES) {
                    throw new SecurityProtocolException("Material criptográfico da sessão inválido.");
                }
                byte[] aesKey = Arrays.copyOfRange(material, 0, CryptoProfile.AES_KEY_BYTES);
                byte[] hmacKey = Arrays.copyOfRange(material, CryptoProfile.AES_KEY_BYTES, material.length);
                try {
                    byte[] authenticated = Arrays.copyOf(bytes, offer.macOffset());
                    byte[] suppliedMac = Arrays.copyOfRange(bytes, offer.macOffset(), offer.signatureOffset());
                    if (!MessageDigest.isEqual(hmac(hmacKey, authenticated), suppliedMac)) {
                        throw new HmacValidationException();
                    }
                    SecureSession session = new SecureSession(header.project(), recipient.name(), header.sender(),
                            header.sessionId(), aesKey, hmacKey, false);
                    boolean fresh;
                    try {
                        fresh = replayGuard.claim(header.sender(), header.sessionId(),
                                header.issuedAtMillis(), header.expiresAtMillis());
                    } catch (GeneralSecurityException exception) {
                        session.close();
                        throw exception;
                    }
                    if (!fresh) {
                        session.close();
                        throw new SecurityProtocolException("Oferta de sessão repetida.");
                    }
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
        } catch (SecurityProtocolException exception) {
            throw exception;
        } catch (GeneralSecurityException exception) {
            throw new SecurityProtocolException("Oferta de sessão inválida ou não autenticada.", exception);
        }
    }

    static boolean confirm(Pending pending, byte[] ready) throws GeneralSecurityException {
        if (pending == null) {
            throw new NullPointerException("pending");
        }
        if (!pending.session().matchesReady(ready)) {
            throw new SecurityProtocolException("Confirmação de sessão inválida.");
        }
        return pending.session().confirmReady(ready);
    }

    static boolean isOffer(byte[] encoded) {
        return encoded != null && encoded.length >= Integer.BYTES
                && java.nio.ByteBuffer.wrap(encoded).getInt() == MAGIC;
    }

    static UUID sessionIdFromOffer(byte[] encoded) throws IOException {
        return parse(encoded).header().sessionId();
    }

    private static byte[] encodeHeader(String project, String sender, String recipient, UUID sessionId,
                                       long issuedAt, long expiresAt, int wrappedLength)
            throws GeneralSecurityException {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(256);
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeInt(MAGIC);
            out.writeByte(VERSION);
            out.writeLong(issuedAt);
            out.writeLong(expiresAt);
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

    private static ParsedOffer parse(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length < 128 || encoded.length > CryptoProfile.MAX_TCP_ENVELOPE_BYTES) {
            throw new IOException("Tamanho inválido da oferta de sessão.");
        }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(encoded));
        if (in.readInt() != MAGIC || in.readUnsignedByte() != VERSION) {
            throw new IOException("Magic ou versão de oferta desconhecidos.");
        }
        long issuedAt = in.readLong();
        long expiresAt = in.readLong();
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
        Header header = new Header(project, sender, recipient, sessionId, issuedAt, expiresAt, wrappedLength);
        int wrappedOffset = headerLength;
        int macOffset = wrappedOffset + wrappedLength;
        int signatureOffset = macOffset + macLength;
        return new ParsedOffer(header, wrappedOffset, macOffset, signatureOffset);
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
        byte[] encoded = in.readNBytes(length);
        if (encoded.length != length) {
            throw new IOException("Oferta truncada.");
        }
        for (byte value : encoded) {
            if ((value & 0x80) != 0) {
                throw new IOException("Identificador contém bytes não ASCII.");
            }
        }
        String decoded = new String(encoded, StandardCharsets.US_ASCII);
        try {
            IdentityNames.requireValid(decoded, "Identificador");
        } catch (IllegalArgumentException exception) {
            throw new IOException("Identificador inválido.", exception);
        }
        return decoded;
    }

    private static byte[] wrap(byte[] material, java.security.PublicKey recipient)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, recipient, KeyFiles.oaepParameters(), CryptoProfile.RANDOM);
        return cipher.doFinal(material);
    }

    private static byte[] unwrap(byte[] wrapped, LocalIdentity recipient) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, recipient.transportPrivateKey(), KeyFiles.oaepParameters());
        return cipher.doFinal(wrapped);
    }

    private static Signature signer(LocalIdentity identity) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(KeyFiles.pssParameters());
        signature.initSign(identity.signingPrivateKey(), CryptoProfile.RANDOM);
        return signature;
    }

    private static Signature verifier(TrustedIdentity identity) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(KeyFiles.pssParameters());
        signature.initVerify(identity.signingPublicKey());
        return signature;
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

    record Pending(SecureSession session, byte[] encodedOffer) {
        Pending {
            encodedOffer = encodedOffer.clone();
        }

        @Override
        public byte[] encodedOffer() {
            return encodedOffer.clone();
        }
    }

    record Accepted(SecureSession session, byte[] encodedReady) {
        Accepted {
            encodedReady = encodedReady.clone();
        }

        @Override
        public byte[] encodedReady() {
            return encodedReady.clone();
        }
    }

    private record Header(String project, String sender, String recipient, UUID sessionId,
                          long issuedAtMillis, long expiresAtMillis, int wrappedKeysLength) {
    }

    private record ParsedOffer(Header header, int wrappedKeysOffset, int macOffset, int signatureOffset) {
    }
}
