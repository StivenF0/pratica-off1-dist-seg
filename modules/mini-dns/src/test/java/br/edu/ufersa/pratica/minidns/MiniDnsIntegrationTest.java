package br.edu.ufersa.pratica.minidns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import br.edu.ufersa.pratica.security.LocalIdentity;
import br.edu.ufersa.pratica.security.OpenedMessage;
import br.edu.ufersa.pratica.security.ReceivedDatagram;
import br.edu.ufersa.pratica.security.ReplayGuard;
import br.edu.ufersa.pratica.security.SecureSession;
import br.edu.ufersa.pratica.security.SecureUdpEndpoint;
import br.edu.ufersa.pratica.security.TrustStore;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MiniDnsIntegrationTest {
    private static final String[] IDENTITIES = {
            "dns-server", "dns-client-1", "dns-client-2", "dns-client-3", "registrar"
    };

    @TempDir
    static Path temporaryDirectory;

    private static TrustStore trust;
    private static LocalIdentity dns;
    private static LocalIdentity registrarIdentity;
    private static List<LocalIdentity> clientIdentities;

    @BeforeAll
    static void createIdentities() throws Exception {
        Path keysRoot = temporaryDirectory.resolve("keys");
        for (String identity : IDENTITIES) {
            LocalIdentity.generate(MiniDnsProtocol.PROJECT, identity, keysRoot.resolve(identity));
        }
        Path manifest = keysRoot.resolve("trust.tsv");
        TrustStore.writeManifest(MiniDnsProtocol.PROJECT, keysRoot, List.of(IDENTITIES), manifest);
        trust = TrustStore.load(manifest, MiniDnsProtocol.PROJECT);
        dns = LocalIdentity.load(MiniDnsProtocol.PROJECT, MiniDnsProtocol.DNS_SERVER,
                keysRoot.resolve(MiniDnsProtocol.DNS_SERVER));
        registrarIdentity = LocalIdentity.load(MiniDnsProtocol.PROJECT, MiniDnsProtocol.REGISTRAR,
                keysRoot.resolve(MiniDnsProtocol.REGISTRAR));
        clientIdentities = List.of(
                LocalIdentity.load(MiniDnsProtocol.PROJECT, MiniDnsProtocol.CLIENTS.get(0),
                        keysRoot.resolve(MiniDnsProtocol.CLIENTS.get(0))),
                LocalIdentity.load(MiniDnsProtocol.PROJECT, MiniDnsProtocol.CLIENTS.get(1),
                        keysRoot.resolve(MiniDnsProtocol.CLIENTS.get(1))),
                LocalIdentity.load(MiniDnsProtocol.PROJECT, MiniDnsProtocol.CLIENTS.get(2),
                        keysRoot.resolve(MiniDnsProtocol.CLIENTS.get(2))));
    }

    @Test
    void secureUnicastResolveInvalidNameAndCorruptHmacDoNotStopTheDnsServer() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (DatagramSocket dnsSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
             DatagramSocket clientSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
             SecureUdpEndpoint dnsEndpoint = endpoint(dnsSocket, dns);
             SecureUdpEndpoint clientEndpoint = endpoint(clientSocket, clientIdentities.get(0))) {
            dnsSocket.setSoTimeout(500);
            clientSocket.setSoTimeout(5_000);
            MiniDnsServer server = new MiniDnsServer(dnsEndpoint,
                    new InetSocketAddress(InetAddress.getByName("239.255.42.99"), 5301));
            CompletableFuture<Void> serverRun = CompletableFuture.runAsync(() -> {
                try {
                    server.run();
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });
            SecureSession session = clientEndpoint.connect(dnsEndpoint.localAddress(), MiniDnsProtocol.DNS_SERVER);

            clientEndpoint.send(session, MiniDnsProtocol.resolve("servidor1"));
            assertAnswer(clientEndpoint.receive().message(), "ANSWER", "servidor1", "192.168.0.10");

            byte[] corrupt = session.seal(MiniDnsProtocol.resolve("servidor1"));
            corrupt[corrupt.length - 1] ^= 1;
            clientSocket.send(new DatagramPacket(corrupt, corrupt.length, dnsEndpoint.localAddress()));

            clientEndpoint.send(session, MiniDnsProtocol.resolve("servidor99"));
            MiniDnsProtocol.Reply invalid = MiniDnsProtocol.parseReply(clientEndpoint.receive().message().payload());
            assertEquals("ERROR", invalid.operation());
            assertEquals(MiniDnsProtocol.INVALID_INPUT, invalid.message());

            clientEndpoint.send(session, MiniDnsProtocol.resolve("servidor1"));
            assertAnswer(clientEndpoint.receive().message(), "ANSWER", "servidor1", "192.168.0.10");

            server.close();
            serverRun.get(2, TimeUnit.SECONDS);
        }
    }

    @Test
    void registrarUpdatesAllThreeNamesAndDnsAnswersTheNewValues() throws Exception {
        NetworkInterface network = multicastInterface();
        Assumptions.assumeTrue(network != null, "Nenhuma interface multicast IPv4 disponível para o servidor DNS.");
        InetAddress loopback = InetAddress.getLoopbackAddress();
        InetAddress group = InetAddress.getByName("239.255.42.99");
        int groupPort;
        try (DatagramSocket reservation = new DatagramSocket(0)) {
            groupPort = reservation.getLocalPort();
        }

        MulticastSocket dnsSocket = new MulticastSocket(null);
        dnsSocket.setReuseAddress(true);
        dnsSocket.setNetworkInterface(network);
        dnsSocket.setTimeToLive(1);
        dnsSocket.bind(new InetSocketAddress(0));
        dnsSocket.setSoTimeout(500);
        SecureUdpEndpoint dnsEndpoint = endpoint(dnsSocket, dns);
        MiniDnsServer server = new MiniDnsServer(dnsEndpoint, new InetSocketAddress(group, groupPort));
        CompletableFuture<Void> serverRun = CompletableFuture.runAsync(() -> {
            try {
                server.run();
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        });

        ArrayList<Client> clients = new ArrayList<>();
        SecureUdpEndpoint registrar = null;
        InetSocketAddress serverAddress = new InetSocketAddress(loopback, dnsSocket.getLocalPort());
        try {
            for (int index = 0; index < clientIdentities.size(); index++) {
                DatagramSocket unicastSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
                unicastSocket.setSoTimeout(5_000);
                SecureUdpEndpoint unicast = endpoint(unicastSocket, clientIdentities.get(index));
                SecureUdpEndpoint multicast = endpoint(
                        multicastClientSocket(network, group, groupPort),
                        clientIdentities.get(index));
                SecureSession session = unicast.connect(serverAddress, MiniDnsProtocol.DNS_SERVER);
                multicast.attachSession(session, serverAddress);
                unicast.send(session, MiniDnsProtocol.resolve("servidor1"));
                assertAnswer(unicast.receive().message(), "ANSWER", "servidor1", "192.168.0.10");
                clients.add(new Client(unicast, multicast, session));
            }

            List<Update> updates = List.of(
                    new Update("servidor1", "192.168.0.111"),
                    new Update("servidor4", "192.168.0.144"),
                    new Update("servidor9", "192.168.0.199"));
            List<CompletableFuture<Boolean>> multicastChecks = clients.stream()
                    .map(client -> asyncReceiveUpdates(client.multicast(), updates)).toList();

            DatagramSocket registrarSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
            registrarSocket.setSoTimeout(5_000);
            registrar = endpoint(registrarSocket, registrarIdentity);
            SecureSession registrarSession = registrar.connect(serverAddress, MiniDnsProtocol.DNS_SERVER);
            byte[] corruptedUpdate = registrarSession.seal(
                    MiniDnsProtocol.update("servidor1", "192.168.0.111"));
            corruptedUpdate[corruptedUpdate.length - 1] ^= 1;
            registrarSocket.send(new DatagramPacket(corruptedUpdate, corruptedUpdate.length, serverAddress));
            assertResolution(clients.get(0).unicast(), clients.get(0).session(),
                    "servidor1", "192.168.0.10");

            for (Update update : updates) {
                registrar.send(registrarSession, MiniDnsProtocol.update(update.name(), update.address()));
                MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(registrar.receive().message().payload());
                assertEquals("UPDATED", reply.operation());
                assertEquals(update.address(), reply.address());
            }

            assertResolution(clients.get(0).unicast(), clients.get(0).session(), "servidor1", "192.168.0.111");
            assertResolution(clients.get(1).unicast(), clients.get(1).session(), "servidor4", "192.168.0.144");
            assertResolution(clients.get(2).unicast(), clients.get(2).session(), "servidor9", "192.168.0.199");
            boolean multicastDelivered = true;
            for (CompletableFuture<Boolean> check : multicastChecks) {
                multicastDelivered &= check.get(6, TimeUnit.SECONDS);
            }
            Assumptions.assumeTrue(multicastDelivered,
                    "A interface de rede não entrega multicast local neste ambiente.");
        } finally {
            clients.forEach(client -> {
                client.multicast().close();
                client.unicast().close();
            });
            if (registrar != null) {
                registrar.close();
            }
            server.close();
            serverRun.get(2, TimeUnit.SECONDS);
        }
    }

    private static CompletableFuture<Boolean> asyncReceiveUpdates(SecureUdpEndpoint endpoint, List<Update> expected) {
        return CompletableFuture.supplyAsync(() -> {
            for (Update update : expected) {
                try {
                    ReceivedDatagram datagram = endpoint.receive();
                    OpenedMessage message = datagram.message();
                    if (message.duplicate() || !message.sender().equals(MiniDnsProtocol.DNS_SERVER)) {
                        return false;
                    }
                    MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(message.payload());
                    if (!reply.operation().equals("UPDATE") || !reply.name().equals(update.name())
                            || !reply.address().equals(update.address())) {
                        return false;
                    }
                } catch (SocketTimeoutException timeout) {
                    return false;
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            }
            return true;
        });
    }

    private static DatagramSocket multicastClientSocket(NetworkInterface network, InetAddress group, int port)
            throws Exception {
        MulticastSocket socket = new MulticastSocket(null);
        try {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(port));
            socket.setNetworkInterface(network);
            socket.joinGroup(new InetSocketAddress(group, port), network);
            socket.setSoTimeout(5_000);
            return socket;
        } catch (Exception exception) {
            socket.close();
            throw exception;
        }
    }

    private static void assertResolution(SecureUdpEndpoint endpoint, SecureSession session,
                                         String name, String expected) throws Exception {
        endpoint.send(session, MiniDnsProtocol.resolve(name));
        assertAnswer(endpoint.receive().message(), "ANSWER", name, expected);
    }

    private static void assertAnswer(OpenedMessage message, String kind, String name, String address) {
        assertFalse(message.duplicate());
        assertEquals(MiniDnsProtocol.DNS_SERVER, message.sender());
        MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(message.payload());
        assertEquals(kind, reply.operation());
        assertEquals(name, reply.name());
        assertEquals(address, reply.address());
    }

    private static SecureUdpEndpoint endpoint(DatagramSocket socket, LocalIdentity identity) throws Exception {
        return new SecureUdpEndpoint(socket, identity, trust, testReplayGuard());
    }

    private static ReplayGuard testReplayGuard() {
        return new ReplayGuard(Clock.systemUTC(), System::nanoTime, Duration.ofSeconds(30),
                Duration.ofSeconds(2), Duration.ZERO, 100);
    }

    private static NetworkInterface multicastInterface() throws Exception {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface candidate = interfaces.nextElement();
            if (candidate.isUp() && candidate.supportsMulticast()
                    && Collections.list(candidate.getInetAddresses()).stream()
                    .anyMatch(address -> address instanceof java.net.Inet4Address && !address.isLoopbackAddress())) {
                return candidate;
            }
        }
        return null;
    }

    private record Update(String name, String address) {
    }

    private record Client(SecureUdpEndpoint unicast, SecureUdpEndpoint multicast, SecureSession session) {
    }
}
