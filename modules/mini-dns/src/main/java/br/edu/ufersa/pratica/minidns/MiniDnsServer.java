package br.edu.ufersa.pratica.minidns;

import br.edu.ufersa.pratica.security.OpenedMessage;
import br.edu.ufersa.pratica.security.ReceivedDatagram;
import br.edu.ufersa.pratica.security.SecureSession;
import br.edu.ufersa.pratica.security.SecureUdpEndpoint;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/** UDP DNS process; identities and sessions come only from the shared security module. */
public final class MiniDnsServer implements AutoCloseable {
    private final SecureUdpEndpoint endpoint;
    private final InetSocketAddress multicastGroup;
    private final Map<String, String> records = MiniDnsProtocol.initialRecords();
    private final Map<String, SecureSession> clientSessions = new HashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean();

    public MiniDnsServer(SecureUdpEndpoint endpoint, InetSocketAddress multicastGroup) {
        this.endpoint = endpoint;
        this.multicastGroup = multicastGroup;
    }

    public void run() throws IOException {
        System.out.println("Mini-DNS ativo em " + endpoint.localAddress() + ".");
        while (!closed.get()) {
            try {
                handle(endpoint.receive());
            } catch (SocketTimeoutException timeout) {
                // Periodic timeout lets close() stop this process cleanly.
            } catch (SocketException exception) {
                if (!closed.get()) {
                    System.err.println("Falha no socket DNS: " + exception.getMessage());
                }
                return;
            } catch (IOException | GeneralSecurityException exception) {
                if (!closed.get()) {
                    System.err.println("Pacote DNS rejeitado: " + exception.getMessage());
                }
            }
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            endpoint.close();
        }
    }

    private void handle(ReceivedDatagram datagram) throws IOException, GeneralSecurityException {
        OpenedMessage message = datagram.message();
        if (message.duplicate()) {
            return;
        }

        MiniDnsProtocol.Request request;
        try {
            request = MiniDnsProtocol.parseRequest(message.payload());
        } catch (IllegalArgumentException exception) {
            endpoint.send(datagram.session(), MiniDnsProtocol.error());
            return;
        }

        if (message.sender().equals(MiniDnsProtocol.REGISTRAR)) {
            update(datagram.session(), request);
        } else if (isClient(message.sender()) && request.operation().equals("RESOLVE")) {
            resolve(datagram.session(), message.sender(), request.name());
        } else {
            endpoint.send(datagram.session(), MiniDnsProtocol.error());
        }
    }

    private void resolve(SecureSession session, String client, String name)
            throws IOException, GeneralSecurityException {
        String address = records.get(name);
        if (address == null) {
            endpoint.send(session, MiniDnsProtocol.error());
            System.out.printf("DNS rejeitou consulta de %s para %s.%n", client, name);
            return;
        }

        clientSessions.put(client, session);
        endpoint.send(session, MiniDnsProtocol.answer(name, address));
        System.out.printf("DNS resolveu %s -> %s para %s.%n", name, address, client);
    }

    private void update(SecureSession registrarSession, MiniDnsProtocol.Request request)
            throws IOException, GeneralSecurityException {
        if (!request.operation().equals("UPDATE")
                || !MiniDnsProtocol.allowedUpdate(request.name(), request.address())
                || !allClientsRegistered()) {
            endpoint.send(registrarSession, MiniDnsProtocol.error());
            return;
        }

        List<SecureSession> recipients = new ArrayList<>(MiniDnsProtocol.CLIENTS.size());
        for (String client : MiniDnsProtocol.CLIENTS) {
            recipients.add(clientSessions.get(client));
        }
        String previous = records.put(request.name(), request.address());
        try {
            endpoint.sendMulticast(multicastGroup, recipients,
                    MiniDnsProtocol.updateNotice(request.name(), request.address()));
        } catch (IOException | GeneralSecurityException exception) {
            records.put(request.name(), previous);
            endpoint.send(registrarSession, MiniDnsProtocol.error());
            throw exception;
        }
        endpoint.send(registrarSession, MiniDnsProtocol.updated(request.name(), request.address()));
        System.out.printf("DNS atualizou %s -> %s e notificou C1, C2 e C3 via multicast.%n",
                request.name(), request.address());
    }

    private boolean allClientsRegistered() {
        for (String client : MiniDnsProtocol.CLIENTS) {
            if (!clientSessions.containsKey(client)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isClient(String identity) {
        for (String client : MiniDnsProtocol.CLIENTS) {
            if (client.equals(identity)) {
                return true;
            }
        }
        return false;
    }
}
