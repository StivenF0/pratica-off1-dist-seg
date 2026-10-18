package br.edu.ufersa.pratica.minidns;

import br.edu.ufersa.pratica.security.CryptoProfile;
import br.edu.ufersa.pratica.security.HmacValidationException;
import br.edu.ufersa.pratica.security.SecurityProtocolException;
import br.edu.ufersa.pratica.security.communication.SecureHandshake;
import br.edu.ufersa.pratica.security.communication.SecureSession;
import br.edu.ufersa.pratica.security.identity.LocalIdentity;
import br.edu.ufersa.pratica.security.identity.TrustedIdentity;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/** Each Mini-DNS role runs as its own process and uses Java UDP sockets directly. */
public final class MiniDnsCli {
    private static final String DEFAULT_KEYS = "security-keys/mini-dns";
    private static final String DEFAULT_GROUP = "239.255.42.99";
    private static final int DEFAULT_PORT = 5300;
    private static final int DEFAULT_GROUP_PORT = 5301;
    private static final int HANDSHAKE_TIMEOUT_MILLIS = 10_000;

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
                    "keys-dir", "interface", "port", "group", "group-port")));
            case "client" -> runClient(parse(args, Set.of(
                    "keys-dir", "interface", "identity", "server", "port", "group", "group-port")));
            case "registrar" -> runRegistrar(parse(args, Set.of("keys-dir", "server", "port")));
            case "test-corrupt-hmac" -> runCorruptHmacTest(parse(args, Set.of(
                    "keys-dir", "server", "port")));
            default -> {
                printUsage();
                throw new IllegalArgumentException("Papel Mini-DNS desconhecido.");
            }
        }
    }

    private static void runServer(Map<String, String> options) throws Exception {
        Path keys = keysDirectory(options);
        LocalIdentity identity = localIdentity(keys, MiniDnsProtocol.DNS_SERVER);
        Map<String, TrustedIdentity> peers = new HashMap<>();
        for (String name : MiniDnsProtocol.CLIENTS) {
            peers.put(name, trustedIdentity(keys, name));
        }
        peers.put(MiniDnsProtocol.REGISTRAR, trustedIdentity(keys, MiniDnsProtocol.REGISTRAR));

        NetworkInterface network = multicastInterface(required(options, "interface"));
        int port = port(options, "port", DEFAULT_PORT);
        InetAddress group = multicastGroup(options.getOrDefault("group", DEFAULT_GROUP));
        int groupPort = port(options, "group-port", DEFAULT_GROUP_PORT);
        MulticastSocket socket = new MulticastSocket(null);
        socket.setReuseAddress(true);
        socket.setNetworkInterface(network);
        socket.setTimeToLive(1);
        socket.bind(new InetSocketAddress(port));
        socket.setSoTimeout(1_000);
        try (MiniDnsServer server = new MiniDnsServer(
                socket, identity, peers, new InetSocketAddress(group, groupPort))) {
            server.run();
        }
    }

    private static void runClient(Map<String, String> options) throws Exception {
        String name = requireClientIdentity(required(options, "identity"));
        Path keys = keysDirectory(options);
        LocalIdentity identity = localIdentity(keys, name);
        TrustedIdentity dns = trustedIdentity(keys, MiniDnsProtocol.DNS_SERVER);
        InetSocketAddress server = serverAddress(options);
        InetAddress group = multicastGroup(options.getOrDefault("group", DEFAULT_GROUP));
        int groupPort = port(options, "group-port", DEFAULT_GROUP_PORT);
        NetworkInterface network = multicastInterface(required(options, "interface"));
        Map<String, String> localTable = new ConcurrentHashMap<>();

        try (DatagramSocket unicast = new DatagramSocket();
             MulticastSocket multicast = multicastClientSocket(network, group, groupPort);
             SecureSession session = connect(unicast, identity, dns, server)) {
            unicast.setSoTimeout(HANDSHAKE_TIMEOUT_MILLIS);
            send(unicast, server, session.seal(MiniDnsProtocol.resolve("servidor1")));
            awaitInitialAnswer(unicast, server, session, name, localTable);
            unicast.setSoTimeout(1_000);

            AtomicBoolean stopping = new AtomicBoolean();
            Thread unicastReceiver = receiverThread(unicast, server, session, name, localTable, stopping, "unicast");
            Thread multicastReceiver = receiverThread(multicast, null, session, name, localTable, stopping, "multicast");
            unicastReceiver.start();
            multicastReceiver.start();

            System.out.println("Digite um nome (ex.: servidor4), ou 'sair'.");
            try (Scanner input = new Scanner(System.in)) {
                while (input.hasNextLine()) {
                    String request = input.nextLine().trim();
                    if (request.equalsIgnoreCase("sair")) {
                        break;
                    }
                    try {
                        send(unicast, server, session.seal(MiniDnsProtocol.resolve(request)));
                    } catch (IllegalArgumentException exception) {
                        System.out.println(MiniDnsProtocol.INVALID_INPUT);
                    }
                }
            } finally {
                stopping.set(true);
            }
        }
    }

    private static void awaitInitialAnswer(DatagramSocket socket, InetSocketAddress server, SecureSession session,
                                           String identity, Map<String, String> table) throws Exception {
        while (true) {
            MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(receive(socket, server, session));
            switch (reply.operation()) {
                case "UPDATE" -> showUpdate(identity, reply, table);
                case "ERROR" -> System.out.println(reply.message());
                case "ANSWER" -> {
                    table.put(reply.name(), reply.address());
                    System.out.printf("%s recebeu %s -> %s; HMAC validado.%n", identity, reply.name(), reply.address());
                    return;
                }
            }
        }
    }

    private static Thread receiverThread(DatagramSocket socket, InetSocketAddress expectedRemote,
                                         SecureSession session, String identity,
                                         Map<String, String> table, AtomicBoolean stopping, String type) {
        Thread receiver = new Thread(() -> {
            while (!stopping.get()) {
                try {
                    MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(receive(socket, expectedRemote, session));
                    switch (reply.operation()) {
                        case "ANSWER" -> {
                            table.put(reply.name(), reply.address());
                            System.out.printf("%s recebeu %s -> %s.%n", identity, reply.name(), reply.address());
                        }
                        case "UPDATE" -> showUpdate(identity, reply, table);
                        case "ERROR" -> System.out.println(reply.message());
                        default -> System.err.println("Resposta DNS inesperada.");
                    }
                } catch (SocketTimeoutException timeout) {
                    // Check the stop flag after the socket timeout.
                } catch (IOException | GeneralSecurityException | IllegalArgumentException exception) {
                    if (!stopping.get()) {
                        System.err.println("Mensagem DNS descartada (" + type + "): " + exception.getMessage());
                    }
                }
            }
        }, "mini-dns-client-" + type + "-" + identity);
        receiver.setDaemon(true);
        return receiver;
    }

    private static void runRegistrar(Map<String, String> options) throws Exception {
        Path keys = keysDirectory(options);
        LocalIdentity identity = localIdentity(keys, MiniDnsProtocol.REGISTRAR);
        TrustedIdentity dns = trustedIdentity(keys, MiniDnsProtocol.DNS_SERVER);
        InetSocketAddress server = serverAddress(options);
        try (DatagramSocket socket = new DatagramSocket();
             SecureSession session = connect(socket, identity, dns, server)) {
            socket.setSoTimeout(HANDSHAKE_TIMEOUT_MILLIS);
            for (Update update : List.of(
                    new Update("servidor1", "192.168.0.111"),
                    new Update("servidor4", "192.168.0.144"),
                    new Update("servidor9", "192.168.0.199"))) {
                send(socket, server, session.seal(MiniDnsProtocol.update(update.name(), update.address())));
                MiniDnsProtocol.Reply reply = MiniDnsProtocol.parseReply(receive(socket, server, session));
                if (!reply.operation().equals("UPDATED") || !reply.name().equals(update.name())
                        || !reply.address().equals(update.address())) {
                    throw new IOException(reply.message() == null ? MiniDnsProtocol.INVALID_INPUT : reply.message());
                }
                System.out.printf("Registrador confirmou %s -> %s.%n", reply.name(), reply.address());
            }
        }
    }

    private static void runCorruptHmacTest(Map<String, String> options) throws Exception {
        Path keys = keysDirectory(options);
        LocalIdentity identity = localIdentity(keys, MiniDnsProtocol.REGISTRAR);
        TrustedIdentity dns = trustedIdentity(keys, MiniDnsProtocol.DNS_SERVER);
        InetSocketAddress server = serverAddress(options);
        try (DatagramSocket socket = new DatagramSocket();
             SecureSession session = connect(socket, identity, dns, server)) {
            byte[] frame = session.seal(MiniDnsProtocol.update("servidor1", "192.168.0.111"));
            frame[frame.length - CryptoProfile.SIGNATURE_BYTES - 1] ^= 1;
            send(socket, server, frame);
            System.out.println("Pacote com HMAC adulterado enviado; o DNS deve descartá-lo e registrar HMAC_FAIL.");
        }
    }

    private static SecureSession connect(DatagramSocket socket, LocalIdentity local, TrustedIdentity server,
                                         InetSocketAddress address) throws Exception {
        SecureHandshake.Pending pending = SecureHandshake.create(local, server);
        int previousTimeout = socket.getSoTimeout();
        socket.setSoTimeout(HANDSHAKE_TIMEOUT_MILLIS);
        boolean confirmed = false;
        try {
            send(socket, address, pending.encodedOffer());
            while (true) {
                DatagramPacket packet = receivePacket(socket);
                if (!packet.getSocketAddress().equals(address)) {
                    continue;
                }
                try {
                    SecureHandshake.confirm(pending, bytes(packet));
                    System.out.printf("HMAC_OK %s -> %s READY%n", server.name(), local.name());
                    confirmed = true;
                    return pending.session();
                } catch (GeneralSecurityException exception) {
                    System.err.println("REJECTED confirmação de sessão inválida.");
                }
            }
        } finally {
            socket.setSoTimeout(previousTimeout);
            if (!confirmed) {
                pending.session().close();
            }
        }
    }

    private static byte[] receive(DatagramSocket socket, InetSocketAddress expectedRemote, SecureSession session)
            throws IOException, GeneralSecurityException {
        while (true) {
            DatagramPacket packet = receivePacket(socket);
            if (expectedRemote != null && !packet.getSocketAddress().equals(expectedRemote)) {
                continue;
            }
            try {
                byte[] payload = session.open(bytes(packet));
                System.out.printf("HMAC_OK %s -> %s DATA%n", session.remoteIdentity(), session.localIdentity());
                return payload;
            } catch (HmacValidationException exception) {
                System.err.println("HMAC_FAIL mensagem descartada.");
            } catch (SecurityProtocolException exception) {
                if (expectedRemote != null) {
                    System.err.println("REJECTED mensagem de sessão inválida.");
                }
                // Multicast packets for other clients have a different session ID.
            }
        }
    }

    private static DatagramPacket receivePacket(DatagramSocket socket) throws IOException {
        byte[] buffer = new byte[CryptoProfile.MAX_UDP_DATAGRAM_BYTES + 1];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        if (packet.getLength() > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
            throw new IOException("Datagrama excede 1200 bytes.");
        }
        return packet;
    }

    private static byte[] bytes(DatagramPacket packet) {
        byte[] bytes = new byte[packet.getLength()];
        System.arraycopy(packet.getData(), packet.getOffset(), bytes, 0, packet.getLength());
        return bytes;
    }

    private static void send(DatagramSocket socket, InetSocketAddress target, byte[] frame) throws IOException {
        if (frame.length > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
            throw new IOException("Datagrama excede 1200 bytes.");
        }
        socket.send(new DatagramPacket(frame, frame.length, target));
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

    private static Path keysDirectory(Map<String, String> options) {
        return Path.of(options.getOrDefault("keys-dir", DEFAULT_KEYS));
    }

    private static LocalIdentity localIdentity(Path keys, String name) throws Exception {
        return LocalIdentity.load(MiniDnsProtocol.PROJECT, name, keys.resolve(name));
    }

    private static TrustedIdentity trustedIdentity(Path keys, String name) throws Exception {
        return TrustedIdentity.load(name, keys.resolve(name));
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

    private static void showUpdate(String identity, MiniDnsProtocol.Reply update, Map<String, String> table) {
        table.put(update.name(), update.address());
        System.out.printf("%s recebeu atualização %s -> %s; tabela local atualizada: %s.%n",
                identity, update.name(), update.address(), table);
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
            if (!allowed.contains(name) || options.putIfAbsent(name, args[index + 1]) != null) {
                throw new IllegalArgumentException("Opção desconhecida ou repetida: " + option);
            }
        }
        return options;
    }

    private static void printUsage() {
        System.out.println("Mini-DNS protegido (cada papel é um processo separado):");
        System.out.println("  server --keys-dir <raiz> --interface <iface> [--port 5300]");
        System.out.println("  client --identity <dns-client-1|dns-client-2|dns-client-3> --keys-dir <raiz>"
                + " --interface <iface> [--server 127.0.0.1]");
        System.out.println("  registrar --keys-dir <raiz> [--server 127.0.0.1]");
        System.out.println("  test-corrupt-hmac --keys-dir <raiz> [--server 127.0.0.1]");
    }

    private record Update(String name, String address) {
    }
}
