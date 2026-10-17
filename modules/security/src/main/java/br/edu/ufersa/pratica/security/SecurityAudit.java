package br.edu.ufersa.pratica.security;

import java.time.Instant;
import java.util.UUID;

final class SecurityAudit {
    private SecurityAudit() {
    }

    static void hmac(String result, String project, String local, String peer,
                     UUID sessionId, String direction, String type) {
        String session = sessionId == null ? "desconhecida" : sessionId.toString().substring(0, 8);
        System.out.printf("%s security project=%s local=%s peer=%s session=%s direction=%s type=%s %s%n",
                Instant.now(), project, local, peer, session, direction, type, result);
    }

    static void rejected(String project, String local, String peer) {
        System.err.printf("%s security project=%s local=%s peer=%s REJECTED%n",
                Instant.now(), project, local, peer);
    }
}
