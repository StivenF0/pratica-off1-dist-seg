package br.edu.ufersa.pratica.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** UDP endpoint with RSA session setup, authenticated AES/HMAC frames, and a 1200-byte packet limit. */
public final class SecureUdpEndpoint implements AutoCloseable {
    private static final int MAX_PENDING_MESSAGES = 64;
    private static final long RETRY_MILLIS = 1_000;
    private static final int MULTICAST_MAGIC = 0x4D554C32; // MUL2
    private static final int MULTICAST_VERSION = 2;
    private static final int MULTICAST_RECORDS = 3;
    private static final int MULTICAST_HEADER_BYTES = Integer.BYTES + 2;

    private final DatagramSocket socket;
    private final LocalIdentity localIdentity;
    private final TrustStore trustStore;
    private final ReplayGuard replayGuard;
    private final Map<UUID, Peer> sessions = new ConcurrentHashMap<>();
    private final ArrayDeque<ReceivedDatagram> pendingMessages = new ArrayDeque<>();
    private final Object receiveLock = new Object();

    public SecureUdpEndpoint(DatagramSocket socket, LocalIdentity localIdentity,
                             TrustStore trustStore, ReplayGuard replayGuard)
            throws SecurityProtocolException {
        this.socket = Objects.requireNonNull(socket, "socket");
        this.localIdentity = Objects.requireNonNull(localIdentity, "localIdentity");
        this.trustStore = Objects.requireNonNull(trustStore, "trustStore");
        this.replayGuard = Objects.requireNonNull(replayGuard, "replayGuard");
        if (socket.isClosed()) {
            throw new IllegalArgumentException("O socket UDP está fechado.");
        }
        trustStore.requireLocalIdentity(localIdentity);
    }

    /** Performs the retransmittable key-offer/READY handshake with one UDP peer. */
    public SecureSession connect(InetSocketAddress target, String recipient)
            throws IOException, GeneralSecurityException {
        return connect(target, recipient, CryptoProfile.DEFAULT_HANDSHAKE_TIMEOUT);
    }

    public SecureSession connect(InetSocketAddress target, String recipient, Duration timeout)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(target, "target");
        if (target.isUnresolved()) {
            throw new IOException("O destino UDP precisa estar resolvido.");
        }
        long timeoutMillis = requireHandshakeTimeout(timeout);
        replayGuard.ensureReady();
        SecureHandshake.Pending pending = SecureHandshake.create(localIdentity, trustStore, recipient);
        byte[] offer = pending.encodedOffer();
        int previousTimeout = socket.getSoTimeout();
        long started = System.nanoTime();
        long timeoutNanos = Duration.ofMillis(timeoutMillis).toNanos();
        boolean firstAttempt = true;
        try {
            synchronized (receiveLock) {
                while (System.nanoTime() - started < timeoutNanos) {
                    if (firstAttempt) {
                        sendRaw(target, offer);
                        firstAttempt = false;
                    }
                    long remainingNanos = timeoutNanos - (System.nanoTime() - started);
                    long remainingMillis = Math.max(1, (remainingNanos + 999_999) / 1_000_000);
                    socket.setSoTimeout((int) Math.min(RETRY_MILLIS, remainingMillis));
                    Datagram datagram = null;
                    try {
                        datagram = readDatagram();
                        if (datagram == null) {
                            continue;
                        }
                        if (SecureHandshake.isOffer(datagram.bytes())) {
                            processOffer(datagram);
                            continue;
                        }
                        if (datagram.remote().equals(target) && pending.session().matchesReady(datagram.bytes())) {
                            if (!SecureHandshake.confirm(pending, datagram.bytes())) {
                                throw new SecurityProtocolException("O peer não confirmou a sessão nova.");
                            }
                            register(new Peer(pending.session(), target, offer, null));
                            SecurityAudit.hmac("HMAC_OK", localIdentity.project(), localIdentity.name(), recipient,
                                    pending.session().sessionId(), "RECEIVE", "READY");
                            return pending.session();
                        }
                        queueIfApplication(datagram);
                    } catch (SocketTimeoutException timeoutException) {
                        if (System.nanoTime() - started < timeoutNanos) {
                            sendRaw(target, offer);
                        }
                    } catch (SecurityProtocolException exception) {
                        if (datagram != null) {
                            auditFailure(exception, datagram, "HANDSHAKE");
                        }
                    }
                }
            }
            pending.session().close();
            throw new SocketTimeoutException("Tempo esgotado ao negociar a sessão UDP.");
        } catch (IOException | GeneralSecurityException | RuntimeException exception) {
            pending.session().close();
            throw exception;
        } finally {
            restoreTimeout(previousTimeout);
        }
    }

    /** Sends a session-bound datagram to the peer address authenticated during setup. */
    public void send(SecureSession session, byte[] payload) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(payload, "payload");
        Peer peer = sessions.get(session.sessionId());
        if (peer == null || peer.session() != session || !session.localIdentity().equals(localIdentity.name())
                || !session.project().equals(localIdentity.project())) {
            throw new SecurityProtocolException("A sessão UDP não pertence a este endpoint.");
        }
        int maximumPayload = CryptoProfile.MAX_UDP_DATAGRAM_BYTES - CryptoProfile.SESSION_HEADER_BYTES
                - CryptoProfile.GCM_TAG_BYTES - CryptoProfile.HMAC_BYTES;
        if (payload.length > maximumPayload) {
            throw new IOException("O payload excede o limite UDP de 1200 bytes; a mensagem não foi enviada.");
        }
        byte[] frame = session.seal(payload);
        if (frame.length > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
            throw new IOException("O frame excede o limite UDP de 1200 bytes; a mensagem não foi enviada.");
        }
        sendRaw(peer.remote(), frame);
    }

    /** Sends one payload as three individually authenticated session records in one multicast datagram. */
    public void sendMulticast(InetSocketAddress group, List<SecureSession> peerSessions, byte[] payload)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(group, "group");
        Objects.requireNonNull(peerSessions, "peerSessions");
        Objects.requireNonNull(payload, "payload");
        if (group.isUnresolved() || !group.getAddress().isMulticastAddress()
                || peerSessions.size() != MULTICAST_RECORDS) {
            throw new IllegalArgumentException("Informe um grupo multicast resolvido e as três sessões de clientes.");
        }
        int maximumPayload = (CryptoProfile.MAX_UDP_DATAGRAM_BYTES - MULTICAST_HEADER_BYTES
                - MULTICAST_RECORDS * Short.BYTES) / MULTICAST_RECORDS
                - CryptoProfile.SESSION_HEADER_BYTES - CryptoProfile.GCM_TAG_BYTES - CryptoProfile.HMAC_BYTES;
        if (payload.length > maximumPayload) {
            throw new IOException("O payload excede o limite do datagrama multicast protegido.");
        }

        HashSet<String> recipients = new HashSet<>();
        for (SecureSession session : peerSessions) {
            Objects.requireNonNull(session, "peer session");
            Peer peer = sessions.get(session.sessionId());
            if (peer == null || peer.session() != session
                    || !session.localIdentity().equals(localIdentity.name())
                    || !recipients.add(session.remoteIdentity())) {
                throw new SecurityProtocolException("Sessões multicast inválidas ou repetidas.");
            }
        }
        ArrayList<byte[]> frames = new ArrayList<>(MULTICAST_RECORDS);
        for (SecureSession session : peerSessions) {
            frames.add(session.seal(payload));
        }
        sendRaw(group, encodeMulticastRecords(frames));
    }

    /** Receives a message, automatically accepts signed offers, and silently drops invalid UDP packets. */
    public ReceivedDatagram receive() throws IOException, GeneralSecurityException {
        replayGuard.ensureReady();
        synchronized (receiveLock) {
            if (!pendingMessages.isEmpty()) {
                return pendingMessages.removeFirst();
            }
            while (true) {
                Datagram datagram = readDatagram();
                if (datagram == null) {
                    SecurityAudit.rejected(localIdentity.project(), localIdentity.name(), "datagrama-excessivo");
                    continue;
                }
                try {
                    if (SecureHandshake.isOffer(datagram.bytes())) {
                        processOffer(datagram);
                        continue;
                    }
                    ReceivedDatagram message = openDatagram(datagram);
                    if (message != null) {
                        return message;
                    }
                } catch (IOException | SecurityProtocolException exception) {
                    auditFailure(exception, datagram, "DATAGRAM");
                }
            }
        }
    }

    public InetSocketAddress localAddress() {
        return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
    }

    @Override
    public void close() {
        socket.close();
        sessions.values().forEach(peer -> peer.session().close());
        sessions.clear();
        synchronized (receiveLock) {
            pendingMessages.clear();
        }
    }

    private void processOffer(Datagram datagram) throws IOException, GeneralSecurityException {
        UUID sessionId;
        try {
            sessionId = SecureHandshake.sessionIdFromOffer(datagram.bytes());
        } catch (IOException exception) {
            throw new SecurityProtocolException("Oferta de sessão inválida.", exception);
        }
        Peer existing = sessions.get(sessionId);
        if (existing != null) {
            if (existing.remote().equals(datagram.remote()) && existing.ready() != null
                    && Arrays.equals(existing.offer(), datagram.bytes())) {
                sendRaw(existing.remote(), existing.ready());
                return;
            }
            throw new SecurityProtocolException("Oferta de sessão repetida ou conflitante.");
        }
        SecureHandshake.Accepted accepted = SecureHandshake.accept(
                datagram.bytes(), localIdentity, trustStore, replayGuard);
        Peer peer = new Peer(accepted.session(), datagram.remote(), datagram.bytes(), accepted.encodedReady());
        register(peer);
        SecurityAudit.hmac("HMAC_OK", localIdentity.project(), localIdentity.name(),
                accepted.session().remoteIdentity(), sessionId, "RECEIVE", "KEY_EXCHANGE");
        sendRaw(peer.remote(), peer.ready());
    }

    private void queueIfApplication(Datagram datagram) throws IOException, GeneralSecurityException {
        try {
            ReceivedDatagram opened = openDatagram(datagram);
            if (opened != null && pendingMessages.size() < MAX_PENDING_MESSAGES) {
                pendingMessages.addLast(opened);
            }
        } catch (IOException | SecurityProtocolException exception) {
            auditFailure(exception, datagram, "DATAGRAM");
        }
    }

    private ReceivedDatagram openMessage(Datagram datagram) throws IOException, GeneralSecurityException {
        if (!SecureSession.isSessionFrame(datagram.bytes())) {
            throw new SecurityProtocolException("Datagrama desconhecido.");
        }
        UUID sessionId = SecureSession.sessionIdFromFrame(datagram.bytes());
        Peer peer = sessions.get(sessionId);
        if (peer == null || !peer.remote().equals(datagram.remote())) {
            throw new SecurityProtocolException("Datagrama sem sessão UDP correspondente.");
        }
        if (SecureSession.frameType(datagram.bytes()) == SecureSession.READY) {
            if (!peer.session().isInitiator()) {
                throw new SecurityProtocolException("Confirmação READY recebida na direção incorreta.");
            }
            boolean fresh = peer.session().confirmReady(datagram.bytes());
            if (fresh) {
                SecurityAudit.hmac("HMAC_OK", localIdentity.project(), localIdentity.name(),
                        peer.session().remoteIdentity(), sessionId, "RECEIVE", "READY");
            }
            return null;
        }
        OpenedMessage message = peer.session().open(datagram.bytes());
        SecurityAudit.hmac("HMAC_OK", localIdentity.project(), localIdentity.name(),
                peer.session().remoteIdentity(), sessionId, "RECEIVE", "DATA");
        return new ReceivedDatagram(datagram.remote(), peer.session(), message);
    }

    private ReceivedDatagram openDatagram(Datagram datagram) throws IOException, GeneralSecurityException {
        return isMulticastContainer(datagram.bytes()) ? openMulticast(datagram) : openMessage(datagram);
    }

    private ReceivedDatagram openMulticast(Datagram datagram) throws IOException, GeneralSecurityException {
        ReceivedDatagram matched = null;
        for (byte[] frame : decodeMulticastRecords(datagram.bytes())) {
            UUID sessionId = SecureSession.sessionIdFromFrame(frame);
            Peer peer = sessions.get(sessionId);
            if (peer == null) {
                continue;
            }
            // The authenticated session binds a multicast record; the group's source port may differ.
            if (SecureSession.frameType(frame) != SecureSession.APPLICATION) {
                throw new SecurityProtocolException("Registro multicast não contém dados de aplicação.");
            }
            OpenedMessage message = peer.session().open(frame);
            SecurityAudit.hmac("HMAC_OK", localIdentity.project(), localIdentity.name(),
                    peer.session().remoteIdentity(), sessionId, "RECEIVE", "MULTICAST");
            matched = new ReceivedDatagram(datagram.remote(), peer.session(), message);
        }
        if (matched == null) {
            throw new SecurityProtocolException("Nenhum registro multicast pertence a este endpoint.");
        }
        return matched;
    }

    static byte[] encodeMulticastRecords(List<byte[]> records) throws IOException {
        if (records == null || records.size() != MULTICAST_RECORDS) {
            throw new IOException("O multicast precisa conter exatamente três registros.");
        }
        HashSet<UUID> sessionIds = new HashSet<>();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(CryptoProfile.MAX_UDP_DATAGRAM_BYTES);
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeInt(MULTICAST_MAGIC);
        out.writeByte(MULTICAST_VERSION);
        out.writeByte(MULTICAST_RECORDS);
        for (byte[] frame : records) {
            if (frame == null || frame.length > CryptoProfile.MAX_UDP_DATAGRAM_BYTES
                    || !SecureSession.isSessionFrame(frame)) {
                throw new IOException("Registro multicast inválido.");
            }
            UUID sessionId = SecureSession.sessionIdFromFrame(frame);
            if (!sessionIds.add(sessionId)) {
                throw new IOException("O contêiner multicast repete uma sessão.");
            }
            out.writeShort(frame.length);
            out.write(frame);
        }
        out.flush();
        if (bytes.size() > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
            throw new IOException("Contêiner multicast excede 1200 bytes.");
        }
        return bytes.toByteArray();
    }

    static List<byte[]> decodeMulticastRecords(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length > CryptoProfile.MAX_UDP_DATAGRAM_BYTES
                || encoded.length < MULTICAST_HEADER_BYTES + MULTICAST_RECORDS * Short.BYTES) {
            throw new IOException("Tamanho inválido do contêiner multicast.");
        }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(encoded));
        if (in.readInt() != MULTICAST_MAGIC || in.readUnsignedByte() != MULTICAST_VERSION
                || in.readUnsignedByte() != MULTICAST_RECORDS) {
            throw new IOException("Contêiner multicast inválido.");
        }
        HashSet<UUID> sessionIds = new HashSet<>();
        ArrayList<byte[]> records = new ArrayList<>(MULTICAST_RECORDS);
        for (int index = 0; index < MULTICAST_RECORDS; index++) {
            int length = in.readUnsignedShort();
            if (length < CryptoProfile.SESSION_HEADER_BYTES + CryptoProfile.GCM_TAG_BYTES + CryptoProfile.HMAC_BYTES
                    || length > CryptoProfile.MAX_UDP_DATAGRAM_BYTES || length > in.available()) {
                throw new IOException("Comprimento inválido em registro multicast.");
            }
            byte[] frame = in.readNBytes(length);
            if (!SecureSession.isSessionFrame(frame)) {
                throw new IOException("Registro multicast não é um frame de sessão.");
            }
            UUID sessionId = SecureSession.sessionIdFromFrame(frame);
            if (!sessionIds.add(sessionId)) {
                throw new IOException("O contêiner multicast repete uma sessão.");
            }
            records.add(frame);
        }
        if (in.available() != 0) {
            throw new IOException("Bytes excedentes no contêiner multicast.");
        }
        return List.copyOf(records);
    }

    private static boolean isMulticastContainer(byte[] encoded) {
        return encoded.length >= Integer.BYTES
                && java.nio.ByteBuffer.wrap(encoded).getInt() == MULTICAST_MAGIC;
    }

    private void register(Peer peer) throws SecurityProtocolException {
        synchronized (sessions) {
            Peer sameId = sessions.get(peer.session().sessionId());
            if (sameId != null && sameId.session() != peer.session()) {
                throw new SecurityProtocolException("Identificador de sessão duplicado.");
            }
            for (Map.Entry<UUID, Peer> entry : sessions.entrySet()) {
                Peer previous = entry.getValue();
                if (!entry.getKey().equals(peer.session().sessionId())
                        && previous.session().remoteIdentity().equals(peer.session().remoteIdentity())) {
                    sessions.remove(entry.getKey());
                    previous.session().close();
                }
            }
            int peerCapacity = Math.max(0, trustStore.identityCount() - 1);
            if (sameId == null && sessions.size() >= peerCapacity) {
                throw new SecurityProtocolException("Limite de pares confiáveis para sessões UDP atingido.");
            }
            sessions.put(peer.session().sessionId(), peer);
        }
    }

    private Datagram readDatagram() throws IOException {
        byte[] buffer = new byte[CryptoProfile.MAX_UDP_DATAGRAM_BYTES + 1];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        if (packet.getLength() > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
            return null;
        }
        byte[] bytes = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
        return new Datagram(bytes, (InetSocketAddress) packet.getSocketAddress());
    }

    private void sendRaw(InetSocketAddress target, byte[] bytes) throws IOException {
        if (bytes.length < 1 || bytes.length > CryptoProfile.MAX_UDP_DATAGRAM_BYTES) {
            throw new IOException("Datagrama UDP excede o limite de 1200 bytes.");
        }
        socket.send(new DatagramPacket(bytes, bytes.length, target));
    }

    private long requireHandshakeTimeout(Duration timeout) {
        Objects.requireNonNull(timeout, "timeout");
        long millis;
        try {
            millis = timeout.toMillis();
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("Timeout de handshake fora do limite.", exception);
        }
        if (millis < 1 || millis > CryptoProfile.MAX_MESSAGE_LIFETIME.toMillis()) {
            throw new IllegalArgumentException("Timeout de handshake deve estar entre 1 ms e 30 s.");
        }
        return millis;
    }

    private void restoreTimeout(int timeout) {
        if (!socket.isClosed()) {
            try {
                socket.setSoTimeout(timeout);
            } catch (IOException ignored) {
                // The socket is already unusable for this operation.
            }
        }
    }

    private void auditFailure(Exception exception, Datagram datagram, String type) {
        UUID sessionId = null;
        try {
            if (SecureSession.isSessionFrame(datagram.bytes())) {
                sessionId = SecureSession.sessionIdFromFrame(datagram.bytes());
            } else if (SecureHandshake.isOffer(datagram.bytes())) {
                sessionId = SecureHandshake.sessionIdFromOffer(datagram.bytes());
            } else if (isMulticastContainer(datagram.bytes())) {
                for (byte[] record : decodeMulticastRecords(datagram.bytes())) {
                    UUID candidate = SecureSession.sessionIdFromFrame(record);
                    if (sessions.containsKey(candidate)) {
                        sessionId = candidate;
                        break;
                    }
                }
            }
        } catch (IOException ignored) {
            // A malformed packet has no trustworthy session identifier.
        }
        String peer = datagram.remote().toString();
        if (exception instanceof HmacValidationException) {
            SecurityAudit.hmac("HMAC_FAIL", localIdentity.project(), localIdentity.name(), peer,
                    sessionId, "RECEIVE", type);
        } else {
            SecurityAudit.rejected(localIdentity.project(), localIdentity.name(), peer);
        }
    }

    private record Datagram(byte[] bytes, InetSocketAddress remote) {
    }

    private record Peer(SecureSession session, InetSocketAddress remote, byte[] offer, byte[] ready) {
        Peer {
            offer = offer.clone();
            ready = ready == null ? null : ready.clone();
        }

        @Override
        public byte[] offer() {
            return offer.clone();
        }

        @Override
        public byte[] ready() {
            return ready == null ? null : ready.clone();
        }
    }
}
