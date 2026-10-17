package br.edu.ufersa.pratica.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/** The local identity and its separate RSA key pairs for OAEP and PSS. */
public final class LocalIdentity {
    private final String project;
    private final String name;
    private final PublicKey transportPublicKey;
    private final PrivateKey transportPrivateKey;
    private final PublicKey signingPublicKey;
    private final PrivateKey signingPrivateKey;

    private LocalIdentity(String project, String name,
                          PublicKey transportPublicKey, PrivateKey transportPrivateKey,
                          PublicKey signingPublicKey, PrivateKey signingPrivateKey)
            throws GeneralSecurityException {
        this.project = IdentityNames.requireValid(project, "O projeto");
        this.name = IdentityNames.requireValid(name, "A identidade");
        KeyFiles.validateKeyPair(transportPublicKey, transportPrivateKey);
        KeyFiles.validateKeyPair(signingPublicKey, signingPrivateKey);
        this.transportPublicKey = transportPublicKey;
        this.transportPrivateKey = transportPrivateKey;
        this.signingPublicKey = signingPublicKey;
        this.signingPrivateKey = signingPrivateKey;
    }

    public static LocalIdentity generate(String project, String name, Path directory)
            throws IOException, GeneralSecurityException {
        IdentityNames.requireValid(project, "O projeto");
        IdentityNames.requireValid(name, "A identidade");
        KeyPair transport = KeyFiles.generateRsaKeyPair();
        KeyPair signing = KeyFiles.generateRsaKeyPair();
        KeyFiles.writeIdentityKeys(directory, transport, signing);
        return new LocalIdentity(project, name,
                transport.getPublic(), transport.getPrivate(), signing.getPublic(), signing.getPrivate());
    }

    public static LocalIdentity load(String project, String name, Path directory)
            throws IOException, GeneralSecurityException {
        IdentityNames.requireValid(project, "O projeto");
        IdentityNames.requireValid(name, "A identidade");
        Path root = directory.toRealPath();
        Path transportPrivatePath = requireRegularKeyFile(root.resolve(KeyFiles.TRANSPORT_PRIVATE), root);
        Path transportPublicPath = requireRegularKeyFile(root.resolve(KeyFiles.TRANSPORT_PUBLIC), root);
        Path signingPrivatePath = requireRegularKeyFile(root.resolve(KeyFiles.SIGNING_PRIVATE), root);
        Path signingPublicPath = requireRegularKeyFile(root.resolve(KeyFiles.SIGNING_PUBLIC), root);

        return new LocalIdentity(project, name,
                KeyFiles.readPublicKey(transportPublicPath), KeyFiles.readPrivateKey(transportPrivatePath),
                KeyFiles.readPublicKey(signingPublicPath), KeyFiles.readPrivateKey(signingPrivatePath));
    }

    public String project() {
        return project;
    }

    public String name() {
        return name;
    }

    public PublicKey transportPublicKey() {
        return transportPublicKey;
    }

    PrivateKey transportPrivateKey() {
        return transportPrivateKey;
    }

    public PublicKey signingPublicKey() {
        return signingPublicKey;
    }

    PrivateKey signingPrivateKey() {
        return signingPrivateKey;
    }

    private static Path requireRegularKeyFile(Path path, Path root) throws IOException {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path)) {
            throw new IOException("Arquivo de chave ausente, inválido ou simbólico: " + path);
        }
        Path realPath = path.toRealPath();
        if (!realPath.getParent().equals(root)) {
            throw new IOException("Arquivo de chave fora do diretório da identidade: " + path);
        }
        return realPath;
    }
}
