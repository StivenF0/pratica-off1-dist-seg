package br.edu.ufersa.pratica.security.identity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import br.edu.ufersa.pratica.security.CryptoProfile;

final class KeyFiles {
    static final String TRANSPORT_PRIVATE = "transport-private.pem";
    static final String TRANSPORT_PUBLIC = "transport-public.pem";
    static final String SIGNING_PRIVATE = "signing-private.pem";
    static final String SIGNING_PUBLIC = "signing-public.pem";

    private static final String PRIVATE_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_END = "-----END PRIVATE KEY-----";
    private static final String PUBLIC_BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_END = "-----END PUBLIC KEY-----";
    private static final PSSParameterSpec PSS_PARAMETERS = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC);

    private KeyFiles() {
    }

    static KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(new RSAKeyGenParameterSpec(CryptoProfile.RSA_KEY_BITS, RSAKeyGenParameterSpec.F4),
                CryptoProfile.RANDOM);
        return generator.generateKeyPair();
    }

    static void writeIdentityKeys(Path directory, KeyPair transport, KeyPair signing)
            throws IOException, GeneralSecurityException {
        Files.createDirectories(directory);
        setDirectoryPermissions(directory);

        Path transportPrivate = directory.resolve(TRANSPORT_PRIVATE);
        Path transportPublic = directory.resolve(TRANSPORT_PUBLIC);
        Path signingPrivate = directory.resolve(SIGNING_PRIVATE);
        Path signingPublic = directory.resolve(SIGNING_PUBLIC);
        for (Path path : new Path[]{transportPrivate, transportPublic, signingPrivate, signingPublic}) {
            if (Files.exists(path)) {
                throw new IOException("O arquivo de chave já existe e não será sobrescrito: " + path);
            }
        }

        writePem(transportPrivate, PRIVATE_BEGIN, PRIVATE_END, transport.getPrivate().getEncoded());
        writePem(transportPublic, PUBLIC_BEGIN, PUBLIC_END, transport.getPublic().getEncoded());
        writePem(signingPrivate, PRIVATE_BEGIN, PRIVATE_END, signing.getPrivate().getEncoded());
        writePem(signingPublic, PUBLIC_BEGIN, PUBLIC_END, signing.getPublic().getEncoded());
    }

    static java.security.PublicKey readPublicKey(Path path) throws IOException, GeneralSecurityException {
        byte[] encoded = readPem(path, PUBLIC_BEGIN, PUBLIC_END);
        java.security.PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
        requireRsa3072(key, "chave pública");
        return key;
    }

    static java.security.PrivateKey readPrivateKey(Path path) throws IOException, GeneralSecurityException {
        byte[] encoded = readPem(path, PRIVATE_BEGIN, PRIVATE_END);
        java.security.PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        requireRsa3072(key, "chave privada");
        return key;
    }

    static void validateKeyPair(java.security.PublicKey publicKey, java.security.PrivateKey privateKey)
            throws GeneralSecurityException {
        requireRsa3072(publicKey, "chave pública");
        requireRsa3072(privateKey, "chave privada");

        byte[] challenge = new byte[32];
        CryptoProfile.RANDOM.nextBytes(challenge);
        Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(PSS_PARAMETERS);
        signer.initSign(privateKey, CryptoProfile.RANDOM);
        signer.update(challenge);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(PSS_PARAMETERS);
        verifier.initVerify(publicKey);
        verifier.update(challenge);
        if (!verifier.verify(signature)) {
            throw new GeneralSecurityException("As chaves pública e privada de assinatura não formam um par.");
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameters(), CryptoProfile.RANDOM);
        byte[] encrypted = cipher.doFinal(challenge);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameters());
        byte[] decrypted = cipher.doFinal(encrypted);
        if (!java.security.MessageDigest.isEqual(challenge, decrypted)) {
            throw new GeneralSecurityException("As chaves RSA de transporte não formam um par.");
        }
    }

    static byte[] wrapSessionKeys(java.security.PublicKey recipient, byte[] keys)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, recipient, oaepParameters(), CryptoProfile.RANDOM);
        return cipher.doFinal(keys);
    }

    static byte[] unwrapSessionKeys(java.security.PrivateKey recipient, byte[] wrapped)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, recipient, oaepParameters());
        return cipher.doFinal(wrapped);
    }

    static byte[] sign(java.security.PrivateKey key, byte[] value) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(pssParameters());
        signature.initSign(key, CryptoProfile.RANDOM);
        signature.update(value);
        return signature.sign();
    }

    static boolean verify(java.security.PublicKey key, byte[] value, byte[] signed)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(pssParameters());
        signature.initVerify(key);
        signature.update(value);
        return signature.verify(signed);
    }

    static OAEPParameterSpec oaepParameters() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    static PSSParameterSpec pssParameters() {
        return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32,
                PSSParameterSpec.TRAILER_FIELD_BC);
    }

    static void requireRsa3072(java.security.Key key, String description) throws GeneralSecurityException {
        if (!(key instanceof RSAKey rsaKey) || rsaKey.getModulus().bitLength() != CryptoProfile.RSA_KEY_BITS) {
            throw new GeneralSecurityException(description + " precisa usar RSA-3072.");
        }
    }

    private static void writePem(Path path, String begin, String end, byte[] encoded) throws IOException {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
        String pem = begin + "\n" + body + "\n" + end + "\n";
        boolean privateKey = begin.equals(PRIVATE_BEGIN);
        if (privateKey) {
            try {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(EnumSet.of(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
            } catch (UnsupportedOperationException ignored) {
                Files.createFile(path);
            }
        } else {
            Files.createFile(path);
        }
        Files.writeString(path, pem, StandardCharsets.US_ASCII, StandardOpenOption.WRITE);
        if (privateKey) {
            setPrivateFilePermissions(path);
        }
    }

    private static byte[] readPem(Path path, String begin, String end) throws IOException {
        String content = Files.readString(path, StandardCharsets.US_ASCII).trim();
        if (!content.startsWith(begin) || !content.endsWith(end)) {
            throw new IOException("Arquivo PEM inválido: " + path);
        }
        String encoded = content.substring(begin.length(), content.length() - end.length()).replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException exception) {
            throw new IOException("Conteúdo Base64 inválido no arquivo PEM: " + path, exception);
        }
    }

    private static void setDirectoryPermissions(Path directory) throws IOException {
        setPermissionsIfSupported(directory, EnumSet.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE));
    }

    private static void setPrivateFilePermissions(Path file) throws IOException {
        setPermissionsIfSupported(file, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
    }

    private static void setPermissionsIfSupported(Path path, Set<PosixFilePermission> permissions) throws IOException {
        try {
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX systems use their native file permission model.
        }
    }
}
