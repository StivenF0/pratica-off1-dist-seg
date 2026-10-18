package br.edu.ufersa.pratica.minidns;

import br.edu.ufersa.pratica.security.CryptoProfile;
import br.edu.ufersa.pratica.security.HmacValidationException;
import br.edu.ufersa.pratica.security.communication.SecureHandshake;
import br.edu.ufersa.pratica.security.communication.SecureSession;
import br.edu.ufersa.pratica.security.identity.LocalIdentity;
import br.edu.ufersa.pratica.security.identity.TrustedIdentity;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/** UDP DNS process. Socket operations are kept here so the exercise shows them directly. */
public final class MiniDnsServer implements AutoCloseable {
    private final DatagramSocket socket;
    private final LocalIdentity identity;
    private final Map<String, TrustedIdentity> trustedPeers;
    private final InetSocketAddress multicastGroup;
    private final Map<InetSocketAddress, SecureSession> sessions = new HashMap<>();
    private final Map<String, SecureSession> clientSessions = new HashMap<>();
    private final Map<String, String> records = MiniDnsProtocol.initialRecords();
    private final AtomicBoolean closed = new AtomicBoolean();

    public MiniDnsServer(DatagramSocket socket, LocalIdentity identity,
                         Map<String, TrustedIdentity> trustedPeers, InetSocketAddress multicastGroup) {
        this.socket = socket;
        this.identity = identity;
        this.trustedPeers = Map.copyOf(trustedPeers);
        this.multicastGroup = multicastGroup;
    }

    public void run() {
        System.out.println("Mini-DNS ativo em " + socket.getLocalSocketAddress() + ".");
        while (!closed.get()) {
            try {
                Packet packet = receive();
                if (packet != null) {
                    handle(packet);
                }
            } catch (SocketTimeoutException timeout) {
                // Periodic timeout lets close() stop this process cleanly.
            } catch (SocketException exception) {
                if (!closed.get()) {
                    System.err.println("Falha no socket DNS: " + exception.getMessage());
                }
                return;
            } catch (HmacValidationException exception) {
                System.err.println("HMAC_FAIL mensagem DNS descartada.");
            } catch (IOException | GeneralSecurityException | IllegalArgumentException exception) {
                if (!closed.get()) {
                    System.err.println("Pacote DNS rejeitado: " + exception.getMessage());
                }
            }
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            socket.close();
            sessions.values().forEach(SecureSession::close);
            sessions.clear();
        }
    }

    private void handle(Packet packet) throws IOException, GeneralSecurityException {
        if (SecureHandshake.isOffer(packet.bytes())) {
            SecureHandshake.Accepted accepted = SecureHandshake.accept(packet.bytes(), identity, trustedPeers);
            SecureSession previous = sessions.put(packet.remote(), accepted.session());
            if (previous != null) {
                previous.close();
            }
            send(packet.remote(), accepted.encodedReady());
            System.out.printf("HMAC_OK %s -> %s KEY_EXCHANGE%n",
                    accepted.session().remoteIdentity(), identity.name());
            return;
        }

        SecureSession session = sessions.get(packet.remote());
        if (session == null) {
            throw new IOException("Datagrama sem sessão autenticada.");
        }
        byte[] payload = session.open(packet.bytes());
        System.out.printf("HMAC_OK %s -> %s DATA%n", session.remoteIdentity(), identity.name());
        handle(session, packet.remote(), payload);
    }

    private void handle(SecureSession session, InetSocketAddress remote, byte[] payload)
            throws IOException, GeneralSecurityException {
        MiniDnsProtocol.Request request;
        try {
            request = MiniDnsProtocol.parseRequest(payload);
        } catch (IllegalArgumentException exception) {
            send(session, remote, MiniDnsProtocol.error());
            return;
        }

        String sender = session.remoteIdentity();
        if (sender.equals(MiniDnsProtocol.REGISTRAR)) {
            update(session, remote, request);
        } else if (MiniDnsProtocol.CLIENTS.contains(sender) && request.operation().equals("RESOLVE")) {
            resolve(session, remote, sender, request.name());
        } else {
            send(session, remote, MiniDnsProtocol.error());
        }
    }

    private void resolve(SecureSession session, InetSocketAddress remote, String client, String name)
            throws IOException, GeneralSecurityException {
        String address = records.get(name);
        if (address == null) {
            send(session, remote, MiniDnsProtocol.error());
            System.out.printf("DNS rejeitou consulta de %s para %s.%n", client, name);
            return;
        }
        clientSessions.put(client, session);
        send(session, remote, MiniDnsProtocol.answer(name, address));
        System.out.printf("DNS resolveu %s -> %s para %s.%n", name, address, client);
    }

    private void update(SecureSession registrarSession, InetSocketAddress remote,
                        MiniDnsProtocol.Request request) throws IOException, GeneralSecurityException {
        if (!request.operation().equals("UPDATE")
                || !MiniDnsProtocol.allowedUpdate(request.name(), request.address())
                || !MiniDnsProtocol.CLIENTS.stream().allMatch(clientSessions::containsKey)) {
            send(registrarSession, remote, MiniDnsProtocol.error());
            return;
        }

        records.put(request.name(), request.address());
        try {
            for (String client : MiniDnsProtocol.CLIENTS) {
                SecureSession session = clientSessions.get(client);
                send(multicastGroup, session.seal(
                        MiniDnsProtocol.updateNotice(request.name(), request.address())));
            }
        } catch (IOException | GeneralSecurityException exception) {
            System.err.printf("Falha ao enviar todas as notificações multicast para %s; o registro foi mantido.%n",
                    request.name());
            send(registrarSession, remote, MiniDnsProtocol.error());
            return;
        }
        send(registrarSession, remote, MiniDnsProtocol.updated(request.name(), request.address()));
        System.out.printf("DNS atualizou %s -> %s e notificou C1, C2 e C3 via multicast.%n",
                request.name(), request.address());
    }

    private Packet receive() throws IOException {
        byte[] buffer = new byte[CryptoProfile.MAX_UDP_DATAGRAM_BYTES + 1];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        if (packet.getLength() > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
            System.err.println("REJECTED datagrama maior que 1200 bytes.");
            return null;
        }
        byte[] bytes = new byte[packet.getLength()];
        System.arraycopy(packet.getData(), packet.getOffset(), bytes, 0, packet.getLength());
        return new Packet(bytes, (InetSocketAddress) packet.getSocketAddress());
    }

    private void send(SecureSession session, InetSocketAddress remote, byte[] payload)
            throws IOException, GeneralSecurityException {
        send(remote, session.seal(payload));
    }

    private void send(InetSocketAddress remote, byte[] bytes) throws IOException {
        if (bytes.length > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
            throw new IOException("Datagrama excede 1200 bytes.");
        }
        socket.send(new DatagramPacket(bytes, bytes.length, remote));
    }

    private record Packet(byte[] bytes, InetSocketAddress remote) {
    }
}
