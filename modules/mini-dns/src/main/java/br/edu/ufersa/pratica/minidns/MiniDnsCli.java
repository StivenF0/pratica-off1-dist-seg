package br.edu.ufersa.pratica.minidns;

import br.edu.ufersa.pratica.security.LocalIdentity;
import br.edu.ufersa.pratica.security.OpenedMessage;
import br.edu.ufersa.pratica.security.ReceivedDatagram;
import br.edu.ufersa.pratica.security.ReplayGuard;
import br.edu.ufersa.pratica.security.SecureSession;
import br.edu.ufersa.pratica.security.SecureUdpEndpoint;
import br.edu.ufersa.pratica.security.TrustStore;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/** Process entry point for the DNS server, three clients, registrar, and explicit HMAC test. */
public final class MiniDnsCli {
    private static final String DEFAULT_KEYS = "security-keys/mini-dns";
    private static final String DEFAULT_GROUP = "239.255.42.99";
    private static final int DEFAULT_PORT = 5300;
    private static final int DEFAULT_GROUP_PORT = 5301;

    private MiniDnsCli() {
    }

    public static void main(String[] args) {
        try {
            run(args);
        } catch (Exception exception) {
            System.err.println("Mini-DNS: " + exception.getMessage());
            System.exit(1);
        }
    }

    static void run(String[] args) throws Exception {
        if (args == null || args.length == 0 || args[0].equals("help")) {
            printUsage();
            return;
        }
        switch (args[0]) {
            case "server" -> runServer(parse(args, Set.of(
                    "keys-dir", "trust", "interface", "port", "group", "group-port")));
            case "client" -> runClient(parse(args, Set.of(
                    "keys-dir", "trust", "interface", "identity", "server", "port", "group", "group-port")));
            case "registrar" -> runRegistrar(parse(args, Set.of("keys-dir", "trust", "server", "port")));
            case "test-corrupt-hmac" -> runCorruptHmacTest(parse(args, Set.of(
                    "keys-dir", "trust", "interface", "server", "port", "group", "group-port")));
            default -> {
                printUsage();
                throw new IllegalArgumentException("Papel Mini-DNS desconhecido.");
            }
        }
    }

    private static void runServer(Map<String, String> options) throws Exception {
        IdentityConfig config = identityConfig(options, MiniDnsProtocol.DNS_SERVER);
        ReplayGuard replay = readyReplayGuard();
        TrustStore trust = TrustStore.load(config.trustManifest(), MiniDnsProtocol.PROJECT);
        NetworkInterface network = multicastInterface(required(options, "interface"));
        int port = port(options, "port", DEFAULT_PORT);
        InetAddress groupAddress = multicastGroup(options.getOrDefault("group", DEFAULT_GROUP));
        int groupPort = port(options, "group-port", DEFAULT_GROUP_PORT);

        MulticastSocket socket = new MulticastSocket(null);
        socket.setReuseAddress(true);
        socket.setNetworkInterface(network);
        socket.setTimeToLive(1);
        socket.bind(new InetSocketAddress(port));
        socket.setSoTimeout(1_000);
        SecureUdpEndpoint endpoint = new SecureUdpEndpoint(socket, config.identity(), trust, replay);
        try (MiniDnsServer server = new MiniDnsServer(endpoint, new InetSocketAddress(groupAddress, groupPort))) {
            server.run();
        }
    }

    private static void runClient(Map<String, String> options) throws Exception {
        String identityName = requireClientIdentity(required(options, "identity"));
        IdentityConfig config = identityConfig(options, identityName);
        ReplayGuard replay = readyReplayGuard();
        TrustStore trust = TrustStore.load(config.trustManifest(), MiniDnsProtocol.PROJECT);
        InetSocketAddress server = serverAddress(options);
        InetAddress groupAddress = multicastGroup(options.getOrDefault("group", DEFAULT_GROUP));
        int groupPort = port(options, "group-port", DEFAULT_GROUP_PORT);
        NetworkInterface network = multicastInterface(required(options, "interface"));

        try (DatagramSocket unicastSocket = new DatagramSocket();
             SecureUdpEndpoint unicast = new SecureUdpEndpoint(
                     unicastSocket, config.identity(), trust, replay);
             SecureUdpEndpoint multicast = new SecureUdpEndpoint(
                     multicastClientSocket(network, groupAddress, groupPort), config.identity(), trust, replay)) {
            unicastSocket.setSoTimeout(1_000);
            SecureSession session = unicast.connect(server, MiniDnsProtocol.DNS_SERVER);
            multicast.attachSession(session, server);
            unicast.send(session, MiniDnsProtocol.resolve("servidor1"));
            ConcurrentHashMap<String, String> localTable = new ConcurrentHashMap<>();
            awaitInitialAnswer(unicast, identityName, localTable);

            AtomicBoolean stopping = new AtomicBoolean();
            Thread unicastReceiver = receiverThread(unicast, identityName, localTable, stopping, "unicast");
            Thread multicastReceiver = receiverThread(multicast, identityName, localTable, stopping, "multicast");
            unicastReceiver.start();
            multicastReceiver.start();

            System.out.println("Digite um nome (ex.: servidor4), ou 'sair'.");
            try (Scanner input = new Scanner(System.in)) {
                while (input.hasNextLine()) {
                    String name = input.nextLine().trim();
                    if (name.equalsIgnoreCase("sair")) {
                        break;
                    }
                    try {
                        unicast.send(session, MiniDnsProtocol.resolve(name));
                    } catch (IllegalArgumentException exception) {
                        System.out.println(MiniDnsProtocol.INVALID_INPUT);
                    }
                }
            } finally {
                stopping.set(true);
            }
        }
    }

    private static Thread receiverThread(SecureUdpEndpoint endpoint, String identity,
                                         Map<String, String> localTable, AtomicBoolean stopping, String type) {
        Thread receiver = new Thread(() -> receiveUpdates(endpoint, identity, localTable, stopping),
                "mini-dns-client-" + type + "-" + identity);
        receiver.setDaemon(true);
        return receiver;
    }

    private static void runRegistrar(Map<String, String> options) throws Exception {
        IdentityConfig config = identityConfig(options, MiniDnsProtocol.REGISTRAR);
        ReplayGuard replay = readyReplayGuard();
        TrustStore trust = TrustStore.load(config.trustManifest(), MiniDnsProtocol.PROJECT);
        InetSocketAddress server = serverAddress(options);
        try (DatagramSocket socket = new DatagramSocket();
             SecureUdpEndpoint endpoint = new SecureUdpEndpoint(socket, config.identity(), trust, replay)) {
            socket.setSoTimeout(10_000);
            SecureSession session = endpoint.connect(server, MiniDnsProtocol.DNS_SERVER);
            for (Update update : List.of(
                    new Update("servidor1", "192.168.0.111"),
                    new Update("servidor4", "192.168.0.144"),
                    new Update("servidor9", "192.168.0.199"))) {
                endpoint.send(session, MiniDnsProtocol.update(update.name(), update.address()));
                OpenedMessage reply = receiveReply(endpoint, MiniDnsProtocol.DNS_SERVER);
                MiniDnsProtocol.Reply parsed = MiniDnsProtocol.parseReply(reply.payload());
                if (!parsed.operation().equals("UPDATED") || !parsed.name().equals(update.name())
                        || !parsed.address().equals(update.address())) {
                    throw new IOException(parsed.message() == null
                            ? MiniDnsProtocol.INVALID_INPUT : parsed.message());
                }
                System.out.printf("Registrador confirmou %s -> %s.%n", parsed.name(), parsed.address());
            }
        }
    }

    private static void runCorruptHmacTest(Map<String, String> options) throws Exception {
        // Preserve as três sessões de clientes usadas no multicast durante o teste de falha.
        IdentityConfig config = identityConfig(options, MiniDnsProtocol.REGISTRAR);
        ReplayGuard replay = readyReplayGuard();
        TrustStore trust = TrustStore.load(config.trustManifest(), MiniDnsProtocol.PROJECT);
        InetSocketAddress server = serverAddress(options);
        InetAddress groupAddress = multicastGroup(options.getOrDefault("group", DEFAULT_GROUP));
        int groupPort = port(options, "group-port", DEFAULT_GROUP_PORT);
        NetworkInterface network = multicastInterface(required(options, "interface"));
        MulticastSocket socket = multicastClientSocket(network, groupAddress, groupPort);
        try (SecureUdpEndpoint endpoint = new SecureUdpEndpoint(socket, config.identity(), trust, replay)) {
            SecureSession session = endpoint.connect(server, MiniDnsProtocol.DNS_SERVER);
            byte[] frame = session.seal(MiniDnsProtocol.update("servidor1", "192.168.0.111"));
            frame[frame.length - 1] ^= 1;
            socket.send(new DatagramPacket(frame, frame.length, server));
            System.out.println("Pacote de teste com HMAC adulterado enviado; o DNS deve descartá-lo e registrar HMAC_FAIL.");
        }
    }

    private static void awaitInitialAnswer(SecureUdpEndpoint endpoint, String identity,
                                           Map<String, String> localTable) throws Exception {
        while (true) {
            ReceivedDatagram datagram = endpoint.receive();
            if (datagram.message().duplicate() || !datagram.message().sender().equals(MiniDnsProtocol.DNS_SERVER)) {
                continue;
            }
            MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(datagram.message().payload());
            if (reply.operation().equals("UPDATE")) {
                showUpdate(identity, reply, localTable);
                continue;
            }
            if (reply.operation().equals("ERROR")) {
                System.out.println(reply.message());
                continue;
            }
            if (!reply.operation().equals("ANSWER")) {
                continue;
            }
            localTable.put(reply.name(), reply.address());
            System.out.printf("%s recebeu %s -> %s; HMAC validado.%n",
                    identity, reply.name(), reply.address());
            return;
        }
    }

    private static void receiveUpdates(SecureUdpEndpoint endpoint, String identity,
                                       Map<String, String> localTable, AtomicBoolean stopping) {
        while (!stopping.get()) {
            try {
                ReceivedDatagram datagram = endpoint.receive();
                if (datagram.message().duplicate() || !datagram.message().sender().equals(MiniDnsProtocol.DNS_SERVER)) {
                    continue;
                }
                MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(datagram.message().payload());
                switch (reply.operation()) {
                    case "ANSWER" -> {
                        localTable.put(reply.name(), reply.address());
                        System.out.printf("%s recebeu %s -> %s.%n", identity, reply.name(), reply.address());
                    }
                    case "UPDATE" -> showUpdate(identity, reply, localTable);
                    case "ERROR" -> System.out.println(reply.message());
                    default -> System.err.println("Resposta DNS inesperada.");
                }
            } catch (SocketTimeoutException timeout) {
                // Check the stop flag after the socket timeout.
            } catch (IOException | GeneralSecurityException | IllegalArgumentException exception) {
                if (!stopping.get()) {
                    System.err.println("Mensagem DNS descartada: " + exception.getMessage());
                }
            }
        }
    }

    private static void showUpdate(String identity, MiniDnsProtocol.Reply update,
                                   Map<String, String> localTable) {
        localTable.put(update.name(), update.address());
        System.out.printf("%s recebeu atualização %s -> %s; tabela local atualizada: %s.%n",
                identity, update.name(), update.address(), localTable);
    }

    private static OpenedMessage receiveReply(SecureUdpEndpoint endpoint, String expectedSender)
            throws IOException, GeneralSecurityException {
        while (true) {
            OpenedMessage message = endpoint.receive().message();
            if (!message.duplicate() && message.sender().equals(expectedSender)) {
                return message;
            }
        }
    }

    private static MulticastSocket multicastClientSocket(NetworkInterface network, InetAddress group, int port)
            throws IOException {
        MulticastSocket socket = new MulticastSocket(null);
        try {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(port));
            socket.setNetworkInterface(network);
            socket.joinGroup(new InetSocketAddress(group, port), network);
            socket.setSoTimeout(1_000);
            return socket;
        } catch (IOException | RuntimeException exception) {
            socket.close();
            throw exception;
        }
    }

    private static NetworkInterface multicastInterface(String name) throws SocketException {
        NetworkInterface network = NetworkInterface.getByName(name);
        if (network == null || !network.isUp() || !network.supportsMulticast()
                || network.getInterfaceAddresses().stream()
                .noneMatch(address -> address.getAddress() instanceof Inet4Address)) {
            throw new IllegalArgumentException("Interface multicast IPv4 inválida ou inativa: " + name);
        }
        return network;
    }

    private static InetAddress multicastGroup(String value) throws IOException {
        InetAddress group = InetAddress.getByName(value);
        if (!(group instanceof Inet4Address) || !group.isMulticastAddress()) {
            throw new IllegalArgumentException("Informe um grupo multicast IPv4.");
        }
        return group;
    }

    private static IdentityConfig identityConfig(Map<String, String> options, String name)
            throws IOException, GeneralSecurityException {
        Path keysRoot = Path.of(options.getOrDefault("keys-dir", DEFAULT_KEYS));
        Path trustManifest = Path.of(options.getOrDefault("trust", keysRoot.resolve("trust.tsv").toString()));
        LocalIdentity identity = LocalIdentity.load(MiniDnsProtocol.PROJECT, name, keysRoot.resolve(name));
        return new IdentityConfig(identity, trustManifest);
    }

    private static ReplayGuard readyReplayGuard() throws InterruptedException {
        ReplayGuard replay = new ReplayGuard();
        if (!replay.isReady()) {
            System.out.println("Aguardando a quarentena antirreplay do handshake (34 s).");
            while (!replay.isReady()) {
                Duration remaining = replay.remainingQuarantine();
                Thread.sleep(Math.max(1, remaining.toMillis()));
            }
        }
        return replay;
    }

    private static InetSocketAddress serverAddress(Map<String, String> options) throws IOException {
        InetAddress host = InetAddress.getByName(options.getOrDefault("server", "127.0.0.1"));
        return new InetSocketAddress(host, port(options, "port", DEFAULT_PORT));
    }

    private static int port(Map<String, String> options, String name, int defaultValue) {
        String value = options.get(name);
        int port = value == null ? defaultValue : Integer.parseInt(value);
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("Porta inválida: " + name);
        }
        return port;
    }

    private static String requireClientIdentity(String identity) {
        if (!MiniDnsProtocol.CLIENTS.contains(identity)) {
            throw new IllegalArgumentException("Use dns-client-1, dns-client-2 ou dns-client-3.");
        }
        return identity;
    }

    private static String required(Map<String, String> options, String key) {
        String value = options.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Informe --" + key + ".");
        }
        return value;
    }

    private static Map<String, String> parse(String[] args, Set<String> allowed) {
        Map<String, String> options = new HashMap<>();
        for (int index = 1; index < args.length; index += 2) {
            String option = args[index];
            if (!option.startsWith("--") || option.length() <= 2 || index + 1 >= args.length) {
                throw new IllegalArgumentException("Opção incompleta ou inválida: " + option);
            }
            String name = option.substring(2);
            if (!allowed.contains(name)) {
                throw new IllegalArgumentException("Opção desconhecida para " + args[0] + ": " + option);
            }
            if (options.putIfAbsent(name, args[index + 1]) != null) {
                throw new IllegalArgumentException("Opção repetida: " + option);
            }
        }
        return options;
    }

    private static void printUsage() {
        System.out.println("Mini-DNS protegido (cada papel é um processo separado):");
        System.out.println("  server --keys-dir <raiz> --trust <manifesto> --interface <iface> [--port 5300]");
        System.out.println("  client --identity <dns-client-1|dns-client-2|dns-client-3> --keys-dir <raiz>"
                + " --trust <manifesto> --interface <iface> [--server 127.0.0.1]");
        System.out.println("  registrar --keys-dir <raiz> --trust <manifesto> [--server 127.0.0.1]");
        System.out.println("  test-corrupt-hmac --keys-dir <raiz> --trust <manifesto>"
                + " --interface <iface> [--server 127.0.0.1]");
    }

    private record IdentityConfig(LocalIdentity identity, Path trustManifest) {
    }

    private record Update(String name, String address) {
    }
}
