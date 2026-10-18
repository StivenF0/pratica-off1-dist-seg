package br.edu.ufersa.pratica.security.identity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/** A peer whose public keys were provisioned locally. */
public record TrustedIdentity(String name, PublicKey transportPublicKey, PublicKey signingPublicKey) {
    public TrustedIdentity {
        IdentityNames.requireValid(name, "A identidade");
        try {
            KeyFiles.requireRsa3072(transportPublicKey, "chave pública de transporte");
            KeyFiles.requireRsa3072(signingPublicKey, "chave pública de assinatura");
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException(exception.getMessage(), exception);
        }
    }

    public static TrustedIdentity load(String name, Path directory) throws IOException, GeneralSecurityException {
        IdentityNames.requireValid(name, "A identidade");
        Path root = directory.toRealPath();
        Path transport = root.resolve(KeyFiles.TRANSPORT_PUBLIC);
        Path signing = root.resolve(KeyFiles.SIGNING_PUBLIC);
        if (Files.isSymbolicLink(transport) || Files.isSymbolicLink(signing)
                || !Files.isRegularFile(transport) || !Files.isRegularFile(signing)) {
            throw new IOException("Chaves públicas ausentes ou inválidas para " + name + ".");
        }
        return new TrustedIdentity(name, KeyFiles.readPublicKey(transport), KeyFiles.readPublicKey(signing));
    }

    public byte[] wrapSessionKeys(byte[] keys) throws GeneralSecurityException {
        return KeyFiles.wrapSessionKeys(transportPublicKey, keys);
    }

    public boolean verify(byte[] value, byte[] signature) throws GeneralSecurityException {
        return KeyFiles.verify(signingPublicKey, value, signature);
    }
}
