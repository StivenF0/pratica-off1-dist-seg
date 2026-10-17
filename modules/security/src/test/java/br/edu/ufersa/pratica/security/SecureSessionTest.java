package br.edu.ufersa.pratica.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecureSessionTest {
    private static final String PROJECT = "demo";

    @TempDir
    static Path temporaryDirectory;

    private static LocalIdentity alice;
    private static LocalIdentity bob;
    private static LocalIdentity carol;
    private static LocalIdentity dave;
    private static TrustStore trustStore;

    @BeforeAll
    static void createIdentities() throws Exception {
        Path keyRoot = temporaryDirectory.resolve("keys");
        LocalIdentity.generate(PROJECT, "alice", keyRoot.resolve("alice"));
        LocalIdentity.generate(PROJECT, "bob", keyRoot.resolve("bob"));
        LocalIdentity.generate(PROJECT, "carol", keyRoot.resolve("carol"));
        LocalIdentity.generate(PROJECT, "dave", keyRoot.resolve("dave"));
        alice = LocalIdentity.load(PROJECT, "alice", keyRoot.resolve("alice"));
        bob = LocalIdentity.load(PROJECT, "bob", keyRoot.resolve("bob"));
        carol = LocalIdentity.load(PROJECT, "carol", keyRoot.resolve("carol"));
        dave = LocalIdentity.load(PROJECT, "dave", keyRoot.resolve("dave"));
        Path manifest = keyRoot.resolve("trust.tsv");
        TrustStore.writeManifest(PROJECT, keyRoot, List.of("bob", "alice", "carol", "dave"), manifest);
        trustStore = TrustStore.load(manifest, PROJECT);
    }

    @Test
    void rsaHandshakeConfirmsThePeerAndSeveralMessagesUseTheSession() throws Exception {
        Established pair = establish();
        byte[] request = "mensagem privada".getBytes(StandardCharsets.UTF_8);
        byte[] firstFrame = pair.initiator().seal(request);
        byte[] secondFrame = pair.initiator().seal(request);

        assertFalse(Arrays.equals(firstFrame, secondFrame));
        assertFalse(contains(firstFrame, request));
        assertTrue(firstFrame.length < CryptoProfile.RSA_BYTES * 2);

        OpenedMessage first = pair.responder().open(firstFrame);
        OpenedMessage second = pair.responder().open(secondFrame);
        assertEquals("alice", first.sender());
        assertEquals("bob", first.recipient());
        assertEquals(pair.initiator().sessionId(), first.sessionId());
        assertEquals(0, first.sequence());
        assertArrayEquals(request, first.payload());
        assertEquals(1, second.sequence());
        assertArrayEquals(request, second.payload());

        OpenedMessage response = pair.initiator().open(pair.responder().seal("OK".getBytes(StandardCharsets.UTF_8)));
        assertEquals("bob", response.sender());
        assertArrayEquals("OK".getBytes(StandardCharsets.UTF_8), response.payload());
        pair.close();
    }

    @Test
    void hmacFailureDoesNotConsumeSequenceAndValidMacFramesAreReplayProtected() throws Exception {
        Established pair = establish();
        byte[] frame = pair.initiator().seal(new byte[]{1, 2, 3});
        byte[] alteredMac = frame.clone();
        alteredMac[alteredMac.length - 1] ^= 1;

        assertThrows(HmacValidationException.class, () -> pair.responder().open(alteredMac));
        assertArrayEquals(new byte[]{1, 2, 3}, pair.responder().open(frame).payload());
        OpenedMessage repeated = pair.responder().open(frame);
        assertTrue(repeated.duplicate());
        assertEquals(0, repeated.payload().length);
        pair.close();
    }

    @Test
    void validHmacCannotBypassTheGcmAuthenticationTag() throws Exception {
        byte[] aesKey = new byte[CryptoProfile.AES_KEY_BYTES];
        byte[] hmacKey = new byte[CryptoProfile.HMAC_KEY_BYTES];
        Arrays.fill(aesKey, (byte) 1);
        Arrays.fill(hmacKey, (byte) 2);
        java.util.UUID id = java.util.UUID.randomUUID();
        try (SecureSession sender = new SecureSession(PROJECT, "alice", "bob", id, aesKey, hmacKey, true);
             SecureSession receiver = new SecureSession(PROJECT, "bob", "alice", id, aesKey, hmacKey, false)) {
            byte[] original = sender.seal(new byte[]{7, 8, 9});
            int macOffset = original.length - CryptoProfile.HMAC_BYTES;
            byte[] unkeyedHash = original.clone();
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(Arrays.copyOf(original, macOffset));
            System.arraycopy(digest, 0, unkeyedHash, macOffset, digest.length);
            assertThrows(HmacValidationException.class, () -> receiver.open(unkeyedHash));
            assertThrows(SecurityProtocolException.class,
                    () -> receiver.open(Arrays.copyOf(original, macOffset)));

            byte[] changedCiphertext = original.clone();
            changedCiphertext[CryptoProfile.SESSION_HEADER_BYTES] ^= 1;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            byte[] replacement = mac.doFinal(Arrays.copyOf(changedCiphertext, macOffset));
            System.arraycopy(replacement, 0, changedCiphertext, macOffset, replacement.length);

            assertThrows(SecurityProtocolException.class, () -> receiver.open(changedCiphertext));
            assertArrayEquals(new byte[]{7, 8, 9}, receiver.open(original).payload());
        } finally {
            Arrays.fill(aesKey, (byte) 0);
            Arrays.fill(hmacKey, (byte) 0);
        }
    }

    @Test
    void sessionRejectsReusingTheAesKeyAsTheHmacKey() {
        byte[] reusedKey = new byte[CryptoProfile.AES_KEY_BYTES];
        assertThrows(IllegalArgumentException.class, () -> new SecureSession(
                PROJECT, "alice", "bob", java.util.UUID.randomUUID(), reusedKey, reusedKey, true));
    }

    @Test
    void receiveWindowAcceptsReorderingButNeverReappliesASequence() throws Exception {
        Established pair = establish();
        byte[] zero = pair.initiator().seal(new byte[]{0});
        byte[] one = pair.initiator().seal(new byte[]{1});
        byte[] two = pair.initiator().seal(new byte[]{2});

        assertArrayEquals(new byte[]{2}, pair.responder().open(two).payload());
        assertArrayEquals(new byte[]{0}, pair.responder().open(zero).payload());
        assertArrayEquals(new byte[]{1}, pair.responder().open(one).payload());
        assertTrue(pair.responder().open(zero).duplicate());
        pair.close();
    }

    @Test
    void rejectsInvalidSignatureWrongRecipientUntrustedPeerAndRepeatedOffer() throws Exception {
        SecureHandshake.Pending pending = SecureHandshake.create(alice, trustStore, "bob");
        byte[] modified = pending.encodedOffer();
        modified[modified.length - 1] ^= 1;
        ReplayGuard guard = testReplayGuard();
        assertThrows(SecurityProtocolException.class,
                () -> SecureHandshake.accept(modified, bob, trustStore, guard));
        assertEquals(0, guard.rememberedMessageCount());

        assertThrows(SecurityProtocolException.class,
                () -> SecureHandshake.accept(pending.encodedOffer(), alice, trustStore, testReplayGuard()));

        Path root = temporaryDirectory.resolve("keys");
        Path bobManifest = root.resolve("bob-only.tsv");
        TrustStore.writeManifest(PROJECT, root, List.of("bob"), bobManifest);
        TrustStore bobOnly = TrustStore.load(bobManifest, PROJECT);
        assertThrows(SecurityProtocolException.class,
                () -> SecureHandshake.accept(pending.encodedOffer(), bob, bobOnly, testReplayGuard()));

        ReplayGuard replayGuard = testReplayGuard();
        SecureHandshake.Accepted accepted = SecureHandshake.accept(
                pending.encodedOffer(), bob, trustStore, replayGuard);
        assertThrows(SecurityProtocolException.class,
                () -> SecureHandshake.accept(pending.encodedOffer(), bob, trustStore, replayGuard));
        assertTrue(SecureHandshake.confirm(pending, accepted.encodedReady()));
        pending.session().close();
        accepted.session().close();
    }

    @Test
    void alteredReadyIsReportedAsHmacFailureWithoutConsumingConfirmationSequence() throws Exception {
        SecureHandshake.Pending pending = SecureHandshake.create(alice, trustStore, "bob");
        SecureHandshake.Accepted accepted = SecureHandshake.accept(
                pending.encodedOffer(), bob, trustStore, testReplayGuard());
        byte[] ready = accepted.encodedReady();
        ready[ready.length - 1] ^= 1;

        assertThrows(HmacValidationException.class, () -> SecureHandshake.confirm(pending, ready));
        assertTrue(SecureHandshake.confirm(pending, accepted.encodedReady()));
        pending.session().close();
        accepted.session().close();
    }

    @Test
    void manifestFingerprintDetectsChangedPublicKeyFileAndCliCreatesOnlyPublicManifest()
            throws Exception {
        Path manifest = temporaryDirectory.resolve("keys/trust.tsv");
        List<String> lines = Files.readAllLines(manifest, StandardCharsets.UTF_8);
        String[] columns = lines.get(1).split("\\t", -1);
        columns[2] = (columns[2].charAt(0) == 'f' ? "0" : "f") + columns[2].substring(1);
        lines.set(1, String.join("\t", columns));
        Path badManifest = temporaryDirectory.resolve("keys/tampered.tsv");
        Files.write(badManifest, lines, StandardCharsets.UTF_8);
        assertThrows(IOException.class, () -> TrustStore.load(badManifest, PROJECT));

        Path root = temporaryDirectory.resolve("cli-keys");
        Path identityDirectory = root.resolve("cli-node");
        Path cliManifest = root.resolve("trust.tsv");
        assertEquals(0, SecurityCli.run(new String[]{"generate-keys", "--project", PROJECT,
                "--identity", "cli-node", "--directory", identityDirectory.toString()}));
        assertEquals(0, SecurityCli.run(new String[]{"create-trust-manifest", "--project", PROJECT,
                "--directory", root.toString(), "--output", cliManifest.toString(),
                "--identities", "cli-node"}));
        assertEquals("cli-node", TrustStore.load(cliManifest, PROJECT).requireIdentity("cli-node").name());
        assertFalse(Files.readString(cliManifest).contains("PRIVATE KEY"));
    }

    @Test
    void tcpFramesCarryAnAuthenticatedSessionAndRejectBadLengths() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (ServerSocket server = new ServerSocket(0, 1, loopback)) {
            CompletableFuture<SecureTcpChannel> acceptFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return SecureTcpChannel.accept(server.accept(), bob, trustStore, testReplayGuard());
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });
            try (Socket clientSocket = new Socket(loopback, server.getLocalPort());
                 SecureTcpChannel client = SecureTcpChannel.connect(
                         clientSocket, alice, trustStore, "bob", testReplayGuard());
                 SecureTcpChannel serverSide = acceptFuture.get(10, TimeUnit.SECONDS)) {
                client.send("TCP protegido".getBytes(StandardCharsets.UTF_8));
                OpenedMessage received = serverSide.receive();
                assertEquals("alice", received.sender());
                assertArrayEquals("TCP protegido".getBytes(StandardCharsets.UTF_8), received.payload());
                serverSide.send("resposta".getBytes(StandardCharsets.UTF_8));
                assertArrayEquals("resposta".getBytes(StandardCharsets.UTF_8), client.receive().payload());
            }
        }

        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             Socket rawClient = new Socket(loopback, server.getLocalPort());
             Socket acceptedSocket = server.accept()) {
            DataOutputStream rawOutput = new DataOutputStream(rawClient.getOutputStream());
            rawOutput.writeInt(CryptoProfile.MAX_TCP_ENVELOPE_BYTES + 1);
            rawOutput.flush();
            assertThrows(Exception.class,
                    () -> SecureTcpChannel.accept(acceptedSocket, bob, trustStore, testReplayGuard()));
        }

        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             Socket rawClient = new Socket(loopback, server.getLocalPort());
             Socket acceptedSocket = server.accept()) {
            DataOutputStream rawOutput = new DataOutputStream(rawClient.getOutputStream());
            rawOutput.writeInt(10);
            rawOutput.writeByte(1);
            rawOutput.flush();
            rawClient.shutdownOutput();
            assertThrows(EOFException.class,
                    () -> SecureTcpChannel.accept(acceptedSocket, bob, trustStore, testReplayGuard()));
        }
    }

    @Test
    void udpHandshakeUsesExact1200ByteLimitAndExchangesMultipleMessages() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (DatagramSocket serverSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
             DatagramSocket clientSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
             SecureUdpEndpoint server = new SecureUdpEndpoint(serverSocket, bob, trustStore, testReplayGuard());
             SecureUdpEndpoint client = new SecureUdpEndpoint(clientSocket, alice, trustStore, testReplayGuard())) {
            CompletableFuture<ReceivedDatagram> requestFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return server.receive();
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });
            SecureSession clientSession = client.connect(server.localAddress(), "bob");
            byte[] invalidFrame = clientSession.seal(new byte[]{0});
            invalidFrame[invalidFrame.length - 1] ^= 1;
            clientSocket.send(new DatagramPacket(invalidFrame, invalidFrame.length, server.localAddress()));
            byte[] maxUdpPayload = new byte[CryptoProfile.MAX_UDP_DATAGRAM_BYTES
                    - CryptoProfile.SESSION_HEADER_BYTES - CryptoProfile.GCM_TAG_BYTES - CryptoProfile.HMAC_BYTES];
            client.send(clientSession, maxUdpPayload);
            ReceivedDatagram request = requestFuture.get(10, TimeUnit.SECONDS);
            assertEquals("alice", request.message().sender());
            assertArrayEquals(maxUdpPayload, request.message().payload());

            assertThrows(IOException.class, () -> client.send(clientSession, new byte[maxUdpPayload.length + 1]));
            server.send(request.session(), "UDP protegido".getBytes(StandardCharsets.UTF_8));
            ReceivedDatagram response = client.receive();
            assertEquals("bob", response.message().sender());
            assertArrayEquals("UDP protegido".getBytes(StandardCharsets.UTF_8), response.message().payload());
        }
    }

    @Test
    void udpHandshakeResendsSameReadyForAnIdenticalOfferWithoutReinstallingSession() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (DatagramSocket serverSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
             DatagramSocket clientSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
             SecureUdpEndpoint server = new SecureUdpEndpoint(serverSocket, bob, trustStore, testReplayGuard())) {
            serverSocket.setSoTimeout(5_000);
            clientSocket.setSoTimeout(2_000);
            CompletableFuture<ReceivedDatagram> receiveFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return server.receive();
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });
            SecureHandshake.Pending pending = SecureHandshake.create(alice, trustStore, "bob");
            try {
                byte[] offer = pending.encodedOffer();
                clientSocket.send(new DatagramPacket(offer, offer.length, server.localAddress()));
                byte[] firstReady = receiveDatagram(clientSocket);
                clientSocket.send(new DatagramPacket(offer, offer.length, server.localAddress()));
                byte[] repeatedReady = receiveDatagram(clientSocket);

                assertArrayEquals(firstReady, repeatedReady);
                assertTrue(SecureHandshake.confirm(pending, firstReady));
                assertFalse(SecureHandshake.confirm(pending, repeatedReady));
                byte[] request = pending.session().seal("request".getBytes(StandardCharsets.UTF_8));
                clientSocket.send(new DatagramPacket(request, request.length, server.localAddress()));
                ReceivedDatagram received = receiveFuture.get(5, TimeUnit.SECONDS);
                assertEquals(pending.session().sessionId(), received.message().sessionId());
                assertArrayEquals("request".getBytes(StandardCharsets.UTF_8), received.message().payload());
            } finally {
                pending.session().close();
            }
        }
    }

    @Test
    void multicastContainerFitsThreeIndependentProtectedRecordsAndRejectsTampering() throws Exception {
        ArrayList<SecureHandshake.Pending> initiators = new ArrayList<>();
        ArrayList<SecureHandshake.Accepted> responders = new ArrayList<>();
        ArrayList<byte[]> records = new ArrayList<>();
        byte[] payload = new byte[313];
        try {
            for (int index = 0; index < 3; index++) {
                SecureHandshake.Pending pending = SecureHandshake.create(alice, trustStore, "bob");
                SecureHandshake.Accepted accepted = SecureHandshake.accept(
                        pending.encodedOffer(), bob, trustStore, testReplayGuard());
                assertTrue(SecureHandshake.confirm(pending, accepted.encodedReady()));
                initiators.add(pending);
                responders.add(accepted);
                records.add(accepted.session().seal(payload));
            }

            byte[] container = SecureUdpEndpoint.encodeMulticastRecords(records);
            assertEquals(CryptoProfile.MAX_UDP_DATAGRAM_BYTES, container.length);
            List<byte[]> decoded = SecureUdpEndpoint.decodeMulticastRecords(container);
            assertEquals(3, decoded.size());

            byte[] badRecord = decoded.getFirst().clone();
            badRecord[badRecord.length - 1] ^= 1;
            ArrayList<byte[]> corrupted = new ArrayList<>(decoded);
            corrupted.set(0, badRecord);
            assertThrows(HmacValidationException.class,
                    () -> initiators.getFirst().session().open(
                            SecureUdpEndpoint.decodeMulticastRecords(
                                    SecureUdpEndpoint.encodeMulticastRecords(corrupted)).getFirst()));
            for (int index = 0; index < decoded.size(); index++) {
                assertArrayEquals(payload, initiators.get(index).session().open(decoded.get(index)).payload());
            }

            ArrayList<byte[]> duplicate = new ArrayList<>(records);
            duplicate.set(1, records.getFirst());
            assertThrows(IOException.class, () -> SecureUdpEndpoint.encodeMulticastRecords(duplicate));
            assertThrows(IOException.class,
                    () -> SecureUdpEndpoint.decodeMulticastRecords(Arrays.copyOf(container, container.length - 1)));
        } finally {
            initiators.forEach(pending -> pending.session().close());
            responders.forEach(accepted -> accepted.session().close());
        }
    }

    @Test
    void udpEndpointDeliversThreeSessionSpecificRecordsOverRealMulticast() throws Exception {
        NetworkInterface networkInterface = multicastInterface();
        Assumptions.assumeTrue(networkInterface != null, "Nenhuma interface multicast IPv4 disponível.");
        InetAddress interfaceAddress = Collections.list(networkInterface.getInetAddresses()).stream()
                .filter(address -> address instanceof Inet4Address && !address.isLoopbackAddress())
                .findFirst().orElseThrow();
        InetAddress groupAddress = InetAddress.getByName("239.255.42.99");
        int groupPort;
        try (DatagramSocket reservation = new DatagramSocket(0)) {
            groupPort = reservation.getLocalPort();
        }

        MulticastSocket senderSocket = new MulticastSocket(null);
        senderSocket.setReuseAddress(true);
        senderSocket.bind(new InetSocketAddress(interfaceAddress, 0));
        senderSocket.setNetworkInterface(networkInterface);
        senderSocket.setTimeToLive(0);
        try (SecureUdpEndpoint server = new SecureUdpEndpoint(senderSocket, bob, trustStore, testReplayGuard())) {
            ArrayList<SecureUdpEndpoint> clients = new ArrayList<>();
            ArrayList<SecureSession> serverSessions = new ArrayList<>();
            try {
                LocalIdentity[] clientIdentities = {alice, carol, dave};
                for (LocalIdentity clientIdentity : clientIdentities) {
                    MulticastSocket clientSocket = new MulticastSocket(null);
                    clientSocket.setReuseAddress(true);
                    clientSocket.bind(new InetSocketAddress(groupPort));
                    clientSocket.setNetworkInterface(networkInterface);
                    clientSocket.joinGroup(new InetSocketAddress(groupAddress, groupPort), networkInterface);
                    clientSocket.setSoTimeout(5_000);
                    SecureUdpEndpoint client = new SecureUdpEndpoint(
                            clientSocket, clientIdentity, trustStore, testReplayGuard());
                    clients.add(client);

                    CompletableFuture<ReceivedDatagram> registration = CompletableFuture.supplyAsync(() -> {
                        try {
                            return server.receive();
                        } catch (Exception exception) {
                            throw new RuntimeException(exception);
                        }
                    });
                    SecureSession clientSession = client.connect(server.localAddress(), "bob");
                    client.send(clientSession, new byte[]{1});
                    serverSessions.add(registration.get(5, TimeUnit.SECONDS).session());
                }

                CompletableFuture<?>[] notifications = clients.stream()
                        .map(client -> CompletableFuture.runAsync(() -> {
                            try {
                                assertArrayEquals(new byte[]{9, 8, 7}, client.receive().message().payload());
                            } catch (Exception exception) {
                                throw new RuntimeException(exception);
                            }
                        })).toArray(CompletableFuture[]::new);
                server.sendMulticast(new InetSocketAddress(groupAddress, groupPort), serverSessions,
                        new byte[]{9, 8, 7});
                try {
                    CompletableFuture.allOf(notifications).get(5, TimeUnit.SECONDS);
                } catch (TimeoutException exception) {
                    Assumptions.abort("A interface de rede não entrega multicast local neste ambiente.");
                } catch (ExecutionException exception) {
                    Throwable cause = exception;
                    while (cause.getCause() != null) {
                        cause = cause.getCause();
                    }
                    if (cause instanceof java.net.SocketTimeoutException) {
                        Assumptions.abort("A interface de rede não entrega multicast local neste ambiente.");
                    }
                    throw exception;
                }
            } finally {
                clients.forEach(SecureUdpEndpoint::close);
            }
        }
    }

    private static NetworkInterface multicastInterface() throws SocketException {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface candidate = interfaces.nextElement();
            if (candidate.isUp() && candidate.supportsMulticast()
                    && Collections.list(candidate.getInetAddresses()).stream()
                    .anyMatch(address -> address instanceof Inet4Address && !address.isLoopbackAddress())) {
                return candidate;
            }
        }
        return null;
    }

    @Test
    void replayGuardStillRequiresStartupQuarantineBeforeHandshake() throws Exception {
        ReplayGuard productionGuard = new ReplayGuard();
        SecureHandshake.Pending pending = SecureHandshake.create(alice, trustStore, "bob");
        assertFalse(productionGuard.isReady());
        assertTrue(productionGuard.remainingQuarantine().compareTo(Duration.ZERO) > 0);
        assertThrows(SecurityProtocolException.class,
                () -> SecureHandshake.accept(pending.encodedOffer(), bob, trustStore, productionGuard));
        pending.session().close();
    }

    private static Established establish() throws Exception {
        SecureHandshake.Pending pending = SecureHandshake.create(alice, trustStore, "bob");
        SecureHandshake.Accepted accepted = SecureHandshake.accept(
                pending.encodedOffer(), bob, trustStore, testReplayGuard());
        assertTrue(SecureHandshake.confirm(pending, accepted.encodedReady()));
        return new Established(pending.session(), accepted.session());
    }

    private static ReplayGuard testReplayGuard() {
        return new ReplayGuard(Clock.systemUTC(), System::nanoTime, CryptoProfile.MAX_MESSAGE_LIFETIME,
                CryptoProfile.CLOCK_SKEW, Duration.ZERO, 100);
    }

    private static byte[] receiveDatagram(DatagramSocket socket) throws IOException {
        byte[] buffer = new byte[CryptoProfile.MAX_UDP_DATAGRAM_BYTES + 1];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        return Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
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
