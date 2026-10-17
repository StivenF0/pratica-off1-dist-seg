package br.edu.ufersa.pratica.security.communication;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import br.edu.ufersa.pratica.security.CryptoProfile;
import br.edu.ufersa.pratica.security.HmacValidationException;
import br.edu.ufersa.pratica.security.SecurityProtocolException;
import br.edu.ufersa.pratica.security.cli.SecurityCli;
import br.edu.ufersa.pratica.security.identity.LocalIdentity;
import br.edu.ufersa.pratica.security.identity.TrustedIdentity;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecureSessionTest {
    @TempDir
    static Path temporaryDirectory;

    private static LocalIdentity alice;
    private static LocalIdentity bob;
    private static TrustedIdentity alicePublic;
    private static TrustedIdentity bobPublic;

    @BeforeAll
    static void createIdentities() throws Exception {
        Path keys = temporaryDirectory.resolve("keys");
        LocalIdentity.generate("demo", "alice", keys.resolve("alice"));
        LocalIdentity.generate("demo", "bob", keys.resolve("bob"));
        alice = LocalIdentity.load("demo", "alice", keys.resolve("alice"));
        bob = LocalIdentity.load("demo", "bob", keys.resolve("bob"));
        alicePublic = TrustedIdentity.load("alice", keys.resolve("alice"));
        bobPublic = TrustedIdentity.load("bob", keys.resolve("bob"));
    }

    @Test
    void rsaHandshakeAndSignedEncryptedMessagesWorkAndCanBeReplayed() throws Exception {
        try (Established pair = establish()) {
            byte[] payload = "mensagem privada".getBytes(StandardCharsets.UTF_8);
            byte[] frame = pair.initiator().seal(payload);
            assertFalse(contains(frame, payload));
            assertArrayEquals(payload, pair.responder().open(frame));
            assertArrayEquals(payload, pair.responder().open(frame));
            assertArrayEquals("OK".getBytes(StandardCharsets.UTF_8),
                    pair.initiator().open(pair.responder().seal("OK".getBytes(StandardCharsets.UTF_8))));
        }
    }

    @Test
    void rejectsChangedHmacAndSignature() throws Exception {
        try (Established pair = establish()) {
            byte[] frame = pair.initiator().seal(new byte[]{1, 2, 3});
            byte[] changedMac = frame.clone();
            changedMac[changedMac.length - CryptoProfile.SIGNATURE_BYTES - 1] ^= 1;
            assertThrows(HmacValidationException.class, () -> pair.responder().open(changedMac));

            byte[] changedSignature = frame.clone();
            changedSignature[changedSignature.length - 1] ^= 1;
            assertThrows(SecurityProtocolException.class, () -> pair.responder().open(changedSignature));
            assertArrayEquals(new byte[]{1, 2, 3}, pair.responder().open(frame));
        }
    }

    @Test
    void rejectsAnIdentityNotConfiguredLocally() throws Exception {
        SecureHandshake.Pending pending = SecureHandshake.create(alice, bobPublic);
        try {
            assertThrows(SecurityProtocolException.class,
                    () -> SecureHandshake.accept(pending.encodedOffer(), bob, Map.of()));
        } finally {
            pending.session().close();
        }
    }

    @Test
    void keyGenerationCommandCreatesLocalKeysOnly() throws Exception {
        Path directory = temporaryDirectory.resolve("cli");
        assertTrue(SecurityCli.run(new String[]{"generate-keys", "--project", "demo", "--identity", "node",
                "--directory", directory.toString()}) == 0);
        assertTrue(java.nio.file.Files.exists(directory.resolve("transport-private.pem")));
        assertTrue(java.nio.file.Files.exists(directory.resolve("signing-private.pem")));
    }

    private static Established establish() throws Exception {
        SecureHandshake.Pending pending = SecureHandshake.create(alice, bobPublic);
        SecureHandshake.Accepted accepted = SecureHandshake.accept(
                pending.encodedOffer(), bob, Map.of("alice", alicePublic));
        assertTrue(SecureHandshake.confirm(pending, accepted.encodedReady()));
        return new Established(pending.session(), accepted.session());
    }

    private static boolean contains(byte[] bytes, byte[] candidate) {
        outer:
        for (int start = 0; start <= bytes.length - candidate.length; start++) {
            for (int index = 0; index < candidate.length; index++) {
                if (bytes[start + index] != candidate[index]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private record Established(SecureSession initiator, SecureSession responder) implements AutoCloseable {
        @Override
        public void close() {
            initiator.close();
            responder.close();
        }
    }
}
