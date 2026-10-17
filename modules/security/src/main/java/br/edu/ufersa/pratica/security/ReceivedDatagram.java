package br.edu.ufersa.pratica.security;

import java.net.InetSocketAddress;
import java.util.Objects;

/** A securely decoded UDP message, authenticated session, and network source. */
public record ReceivedDatagram(InetSocketAddress remoteAddress, SecureSession session, OpenedMessage message) {
    public ReceivedDatagram {
        Objects.requireNonNull(remoteAddress, "remoteAddress");
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(message, "message");
    }
}
