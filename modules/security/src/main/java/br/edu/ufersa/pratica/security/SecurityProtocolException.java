package br.edu.ufersa.pratica.security;

import java.security.GeneralSecurityException;

/** A malformed, unauthenticated, expired, or otherwise unacceptable message. */
public class SecurityProtocolException extends GeneralSecurityException {
    public SecurityProtocolException(String message) {
        super(message);
    }

    public SecurityProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}
