package br.edu.ufersa.pratica.security;

import java.util.Objects;
import java.util.UUID;

/** Authenticated metadata and plaintext returned by a session decoder. */
public record OpenedMessage(String project, String sender, String recipient, UUID sessionId,
                            long sequence, byte[] payload, boolean duplicate) {
    public OpenedMessage {
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(sender, "sender");
        Objects.requireNonNull(recipient, "recipient");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(payload, "payload");
        payload = payload.clone();
        if (duplicate && payload.length != 0) {
            throw new IllegalArgumentException("Uma mensagem repetida não deve expor novamente o payload.");
        }
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }
}
