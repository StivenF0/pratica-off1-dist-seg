package br.edu.ufersa.pratica.security;

/** A message had a structurally valid frame but an invalid keyed authentication code. */
public final class HmacValidationException extends SecurityProtocolException {
    public HmacValidationException() {
        super("Mensagem inválida ou não autenticada.");
    }
}
