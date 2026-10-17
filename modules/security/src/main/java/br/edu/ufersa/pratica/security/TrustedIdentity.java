package br.edu.ufersa.pratica.security;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

/** A public identity provisioned through a trusted local manifest. */
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
}
