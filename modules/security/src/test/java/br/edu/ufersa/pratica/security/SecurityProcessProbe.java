package br.edu.ufersa.pratica.security;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;

/** Small child-JVM entry point used only by the multiprocess integration test. */
public final class SecurityProcessProbe {
    private SecurityProcessProbe() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 6) {
            throw new IllegalArgumentException("Esperados: protocolo projeto identidade chave-dir manifesto porta.");
        }
        String protocol = args[0];
        String project = args[1];
        String identityName = args[2];
        Path identityDirectory = Path.of(args[3]);
        Path manifest = Path.of(args[4]);
        int port = Integer.parseInt(args[5]);

        LocalIdentity identity = LocalIdentity.load(project, identityName, identityDirectory);
        TrustStore peers = TrustStore.load(manifest, project);
        ReplayGuard replay = new ReplayGuard(Clock.systemUTC(), System::nanoTime,
                CryptoProfile.MAX_MESSAGE_LIFETIME, CryptoProfile.CLOCK_SKEW, Duration.ZERO, 32);

        switch (protocol) {
            case "tcp-server" -> runTcpServer(identity, peers, replay, port);
            case "tcp-client" -> runTcpClient(identity, peers, replay, port);
            case "udp-server" -> runUdpServer(identity, peers, replay, port);
            case "udp-client" -> runUdpClient(identity, peers, replay, port);
            default -> throw new IllegalArgumentException("Protocolo desconhecido: " + protocol);
        }
    }

    private static void runTcpServer(LocalIdentity identity, TrustStore peers, ReplayGuard replay, int port)
            throws Exception {
        try (ServerSocket server = new ServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
            System.out.println("READY");
            System.out.flush();
            try (Socket socket = server.accept();
                 SecureTcpChannel channel = SecureTcpChannel.accept(socket, identity, peers, replay)) {
                OpenedMessage request = channel.receive();
                requirePayload(request, "tcp-client", "ping-tcp");
                channel.send("pong-tcp".getBytes(StandardCharsets.UTF_8));
            }
        }
        System.out.println("SERVER_OK");
    }

    private static void runTcpClient(LocalIdentity identity, TrustStore peers, ReplayGuard replay, int port)
            throws Exception {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port);
             SecureTcpChannel channel = SecureTcpChannel.connect(socket, identity, peers, "tcp-server", replay)) {
            channel.send("ping-tcp".getBytes(StandardCharsets.UTF_8));
            requirePayload(channel.receive(), "tcp-server", "pong-tcp");
        }
        System.out.println("CLIENT_OK");
    }

    private static void runUdpServer(LocalIdentity identity, TrustStore peers, ReplayGuard replay, int port)
            throws Exception {
        try (DatagramSocket socket = new DatagramSocket(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
             SecureUdpEndpoint endpoint = new SecureUdpEndpoint(socket, identity, peers, replay)) {
            socket.setSoTimeout(10_000);
            System.out.println("READY");
            System.out.flush();
            ReceivedDatagram request = endpoint.receive();
            requirePayload(request.message(), "udp-client", "ping-udp");
            endpoint.send(request.session(), "pong-udp".getBytes(StandardCharsets.UTF_8));
        }
        System.out.println("SERVER_OK");
    }

    private static void runUdpClient(LocalIdentity identity, TrustStore peers, ReplayGuard replay, int port)
            throws Exception {
        try (DatagramSocket socket = new DatagramSocket(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
             SecureUdpEndpoint endpoint = new SecureUdpEndpoint(socket, identity, peers, replay)) {
            socket.setSoTimeout(10_000);
            SecureSession session = endpoint.connect(
                    new InetSocketAddress(InetAddress.getLoopbackAddress(), port), "udp-server");
            endpoint.send(session, "ping-udp".getBytes(StandardCharsets.UTF_8));
            requirePayload(endpoint.receive().message(), "udp-server", "pong-udp");
        }
        System.out.println("CLIENT_OK");
    }

    private static void requirePayload(OpenedMessage message, String expectedSender, String expectedPayload) {
        if (message.duplicate() || !message.sender().equals(expectedSender)
                || !new String(message.payload(), StandardCharsets.UTF_8).equals(expectedPayload)) {
            throw new IllegalStateException("Mensagem de processo inesperada.");
        }
    }
}
