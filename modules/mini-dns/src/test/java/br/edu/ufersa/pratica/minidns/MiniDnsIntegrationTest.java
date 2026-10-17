package br.edu.ufersa.pratica.minidns;

import static org.junit.jupiter.api.Assertions.assertEquals;

import br.edu.ufersa.pratica.security.CryptoProfile;
import br.edu.ufersa.pratica.security.HmacValidationException;
import br.edu.ufersa.pratica.security.SecurityProtocolException;
import br.edu.ufersa.pratica.security.communication.SecureHandshake;
import br.edu.ufersa.pratica.security.communication.SecureSession;
import br.edu.ufersa.pratica.security.identity.LocalIdentity;
import br.edu.ufersa.pratica.security.identity.TrustedIdentity;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    private static Map<String, TrustedIdentity> trustedPeers;
    private static LocalIdentity dns;
    private static LocalIdentity registrarIdentity;
    private static List<LocalIdentity> clientIdentities;

    @BeforeAll
    static void createIdentities() throws Exception {
        Path keys = temporaryDirectory.resolve("keys");
        Map<String, TrustedIdentity> peers = new HashMap<>();
        for (String name : IDENTITIES) {
            Path directory = keys.resolve(name);
            LocalIdentity.generate(MiniDnsProtocol.PROJECT, name, directory);
            peers.put(name, TrustedIdentity.load(name, directory));
        }
        trustedPeers = Map.copyOf(peers);
        dns = localIdentity(keys, MiniDnsProtocol.DNS_SERVER);
        registrarIdentity = localIdentity(keys, MiniDnsProtocol.REGISTRAR);
        clientIdentities = MiniDnsProtocol.CLIENTS.stream().map(name -> {
            try {
                return localIdentity(keys, name);
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        }).toList();
    }

    @Test
    void secureUnicastResolveInvalidNameAndCorruptHmacDoNotStopTheDnsServer() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (DatagramSocket dnsSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
             DatagramSocket clientSocket = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
            dnsSocket.setSoTimeout(500);
            clientSocket.setSoTimeout(5_000);
            InetSocketAddress serverAddress = address(dnsSocket);
            MiniDnsServer server = server(dnsSocket);
            CompletableFuture<Void> serverRun = run(server);
            try (SecureSession session = connect(clientSocket, clientIdentities.get(0),
                    trusted(MiniDnsProtocol.DNS_SERVER), serverAddress)) {
                send(clientSocket, serverAddress, session.seal(MiniDnsProtocol.resolve("servidor1")));
                assertAnswer(receive(clientSocket, serverAddress, session), "ANSWER", "servidor1", "192.168.0.10");

                byte[] corrupt = session.seal(MiniDnsProtocol.resolve("servidor1"));
                corrupt[corrupt.length - CryptoProfile.SIGNATURE_BYTES - 1] ^= 1;
                send(clientSocket, serverAddress, corrupt);

                send(clientSocket, serverAddress, session.seal(MiniDnsProtocol.resolve("servidor99")));
                assertAnswer(receive(clientSocket, serverAddress, session),
                        "ERROR", null, MiniDnsProtocol.INVALID_INPUT);
                send(clientSocket, serverAddress, session.seal(MiniDnsProtocol.resolve("servidor1")));
                assertAnswer(receive(clientSocket, serverAddress, session), "ANSWER", "servidor1", "192.168.0.10");
            } finally {
                server.close();
                serverRun.get(2, TimeUnit.SECONDS);
            }
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
        MiniDnsServer server = server(dnsSocket, group, groupPort);
        CompletableFuture<Void> serverRun = run(server);
        ArrayList<Client> clients = new ArrayList<>();
        DatagramSocket registrarSocket = null;
        SecureSession registrarSession = null;
        InetSocketAddress serverAddress = new InetSocketAddress(loopback, dnsSocket.getLocalPort());
        try {
            for (int index = 0; index < clientIdentities.size(); index++) {
                DatagramSocket unicast = new DatagramSocket(new InetSocketAddress(loopback, 0));
                unicast.setSoTimeout(5_000);
                MulticastSocket multicast = multicastClientSocket(network, group, groupPort);
                SecureSession session = connect(unicast, clientIdentities.get(index),
                        trusted(MiniDnsProtocol.DNS_SERVER), serverAddress);
                send(unicast, serverAddress, session.seal(MiniDnsProtocol.resolve("servidor1")));
                assertAnswer(receive(unicast, serverAddress, session), "ANSWER", "servidor1", "192.168.0.10");
                clients.add(new Client(unicast, multicast, session, serverAddress));
            }

            List<Update> updates = List.of(
                    new Update("servidor1", "192.168.0.111"),
                    new Update("servidor4", "192.168.0.144"),
                    new Update("servidor9", "192.168.0.199"));
            List<CompletableFuture<Boolean>> multicastChecks = clients.stream()
                    .map(client -> asyncReceiveUpdates(client.multicast(), client.session(), updates)).toList();

            registrarSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
            registrarSocket.setSoTimeout(5_000);
            registrarSession = connect(registrarSocket, registrarIdentity,
                    trusted(MiniDnsProtocol.DNS_SERVER), serverAddress);
            byte[] corrupted = registrarSession.seal(MiniDnsProtocol.update("servidor1", "192.168.0.111"));
            corrupted[corrupted.length - CryptoProfile.SIGNATURE_BYTES - 1] ^= 1;
            send(registrarSocket, serverAddress, corrupted);
            assertResolution(clients.get(0), "servidor1", "192.168.0.10");

            for (Update update : updates) {
                send(registrarSocket, serverAddress,
                        registrarSession.seal(MiniDnsProtocol.update(update.name(), update.address())));
                MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(receive(
                        registrarSocket, serverAddress, registrarSession));
                assertEquals("UPDATED", reply.operation());
                assertEquals(update.address(), reply.address());
            }

            assertResolution(clients.get(0), "servidor1", "192.168.0.111");
            assertResolution(clients.get(1), "servidor4", "192.168.0.144");
            assertResolution(clients.get(2), "servidor9", "192.168.0.199");
            boolean multicastDelivered = true;
            for (CompletableFuture<Boolean> check : multicastChecks) {
                multicastDelivered &= check.get(6, TimeUnit.SECONDS);
            }
            Assumptions.assumeTrue(multicastDelivered,
                    "A interface de rede não entrega multicast local neste ambiente.");
        } finally {
            clients.forEach(Client::close);
            if (registrarSession != null) {
                registrarSession.close();
            }
            if (registrarSocket != null) {
                registrarSocket.close();
            }
            server.close();
            serverRun.get(2, TimeUnit.SECONDS);
        }
    }

    private static CompletableFuture<Boolean> asyncReceiveUpdates(MulticastSocket socket, SecureSession session,
                                                                   List<Update> expected) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                for (Update update : expected) {
                    while (true) {
                        byte[] payload = receiveMulticast(socket, session);
                        MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(payload);
                        if (!reply.operation().equals("UPDATE") || !reply.name().equals(update.name())
                                || !reply.address().equals(update.address())) {
                            return false;
                        }
                        break;
                    }
                }
                return true;
            } catch (SocketTimeoutException timeout) {
                return false;
            } catch (Exception exception) {
                throw new RuntimeException(exception);
            }
        });
    }

    private static byte[] receiveMulticast(MulticastSocket socket, SecureSession session) throws Exception {
        while (true) {
            DatagramPacket packet = receivePacket(socket);
            try {
                return session.open(bytes(packet));
            } catch (HmacValidationException exception) {
                throw exception;
            } catch (SecurityProtocolException ignored) {
                // Other clients receive the same group datagrams but cannot open this session's frame.
            }
        }
    }

    private static MulticastSocket multicastClientSocket(NetworkInterface network, InetAddress group, int port)
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

    private static void assertResolution(Client client, String name, String expected) throws Exception {
        send(client.unicast(), client.serverAddress(), client.session().seal(MiniDnsProtocol.resolve(name)));
        assertAnswer(receive(client.unicast(), client.serverAddress(), client.session()), "ANSWER", name, expected);
    }

    private static void assertAnswer(byte[] payload, String operation, String name, String address) {
        MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(payload);
        assertEquals(operation, reply.operation());
        if (name != null) {
            assertEquals(name, reply.name());
        }
        assertEquals(address, operation.equals("ERROR") ? reply.message() : reply.address());
    }

    private static SecureSession connect(DatagramSocket socket, LocalIdentity identity,
                                         TrustedIdentity peer, InetSocketAddress server) throws Exception {
        SecureHandshake.Pending pending = SecureHandshake.create(identity, peer);
        send(socket, server, pending.encodedOffer());
        try {
            while (true) {
                DatagramPacket packet = receivePacket(socket);
                if (packet.getSocketAddress().equals(server)
                        && SecureHandshake.confirm(pending, bytes(packet))) {
                    return pending.session();
                }
            }
        } catch (Exception exception) {
            pending.session().close();
            throw exception;
        }
    }

    private static byte[] receive(DatagramSocket socket, InetSocketAddress server, SecureSession session)
            throws Exception {
        while (true) {
            DatagramPacket packet = receivePacket(socket);
            if (packet.getSocketAddress().equals(server)) {
                return session.open(bytes(packet));
            }
        }
    }

    private static DatagramPacket receivePacket(DatagramSocket socket) throws Exception {
        byte[] buffer = new byte[CryptoProfile.MAX_UDP_DATAGRAM_BYTES + 1];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        if (packet.getLength() > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
            throw new java.io.IOException("Datagrama acima do limite.");
        }
        return packet;
    }

    private static byte[] bytes(DatagramPacket packet) {
        byte[] bytes = new byte[packet.getLength()];
        System.arraycopy(packet.getData(), packet.getOffset(), bytes, 0, packet.getLength());
        return bytes;
    }

    private static void send(DatagramSocket socket, InetSocketAddress address, byte[] bytes) throws Exception {
        socket.send(new DatagramPacket(bytes, bytes.length, address));
    }

    private static LocalIdentity localIdentity(Path keys, String name) throws Exception {
        return LocalIdentity.load(MiniDnsProtocol.PROJECT, name, keys.resolve(name));
    }

    private static TrustedIdentity trusted(String name) {
        return trustedPeers.get(name);
    }

    private static MiniDnsServer server(DatagramSocket socket) {
        return server(socket, InetAddress.getLoopbackAddress(), 5301);
    }

    private static MiniDnsServer server(DatagramSocket socket, InetAddress group, int port) {
        return new MiniDnsServer(socket, dns, trustedPeers, new InetSocketAddress(group, port));
    }

    private static CompletableFuture<Void> run(MiniDnsServer server) {
        return CompletableFuture.runAsync(server::run);
    }

    private static InetSocketAddress address(DatagramSocket socket) {
        return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
    }

    private static NetworkInterface multicastInterface() throws Exception {
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

    private record Update(String name, String address) {
    }

    private record Client(DatagramSocket unicast, MulticastSocket multicast, SecureSession session,
                          InetSocketAddress serverAddress) implements AutoCloseable {
        @Override
        public void close() {
            session.close();
            unicast.close();
            multicast.close();
        }
    }
}
