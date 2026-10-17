package br.edu.ufersa.pratica.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecurityMultiprocessTest {
    @TempDir
    static Path temporaryDirectory;

    private static Path keysRoot;
    private static Path trustManifest;
    private static String childClasspath;

    @BeforeAll
    static void prepareKeysAndClasspath() throws Exception {
        keysRoot = temporaryDirectory.resolve("keys");
        for (String identity : new String[]{"tcp-server", "tcp-client", "udp-server", "udp-client"}) {
            LocalIdentity.generate("multiprocess", identity, keysRoot.resolve(identity));
        }
        trustManifest = keysRoot.resolve("trust.tsv");
        TrustStore.writeManifest("multiprocess", keysRoot,
                java.util.List.of("tcp-server", "tcp-client", "udp-server", "udp-client"), trustManifest);

        String testClasses = Path.of(SecurityProcessProbe.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).toString();
        String mainClasses = Path.of(LocalIdentity.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).toString();
        childClasspath = mainClasses + System.getProperty("path.separator") + testClasses;
    }

    @Test
    void twoSeparateJvmsEstablishHmacSessionsOverTcpAndUdp() throws Exception {
        exchange("tcp", "tcp-server", "tcp-client");
        exchange("udp", "udp-server", "udp-client");
    }

    private void exchange(String protocol, String serverIdentity, String clientIdentity) throws Exception {
        int port = reserveLoopbackPort();
        ChildJvm server = startProcess(protocol + "-server", serverIdentity, port);
        try {
            assertEquals("READY", server.firstLine());
            ChildJvm client = startProcess(protocol + "-client", clientIdentity, port);
            try {
                assertTrue(client.waitFor(), "Processo cliente expirou: " + protocol);
                assertEquals(0, client.exitValue(), client.output());
                assertTrue(client.output().contains("CLIENT_OK"));
                assertTrue(client.output().contains("HMAC_OK"));
                assertTrue(server.waitFor(), "Processo servidor expirou: " + protocol);
                assertEquals(0, server.exitValue(), server.output());
                assertTrue(server.output().contains("SERVER_OK"));
                assertTrue(server.output().contains("HMAC_OK"));
            } finally {
                client.destroyIfAlive();
            }
        } finally {
            server.destroyIfAlive();
        }
    }

    private ChildJvm startProcess(String mode, String identity, int port) throws IOException {
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        Process process = new ProcessBuilder(java.toString(), "-cp", childClasspath,
                SecurityProcessProbe.class.getName(), mode, "multiprocess", identity,
                keysRoot.resolve(identity).toString(), trustManifest.toString(), Integer.toString(port))
                .redirectErrorStream(true)
                .start();
        return new ChildJvm(process);
    }

    private static int reserveLoopbackPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    private static final class ChildJvm {
        private final Process process;
        private final StringBuilder output = new StringBuilder();
        private final CompletableFuture<String> firstLine = new CompletableFuture<>();
        private final CompletableFuture<Void> outputDrained = new CompletableFuture<>();

        private ChildJvm(Process process) {
            this.process = process;
            Thread reader = new Thread(this::collectOutput, "security-test-process-output");
            reader.setDaemon(true);
            reader.start();
        }

        String firstLine() throws Exception {
            try {
                return firstLine.get(15, TimeUnit.SECONDS);
            } catch (Exception exception) {
                destroyIfAlive();
                throw exception;
            }
        }

        boolean waitFor() throws InterruptedException {
            return process.waitFor(15, TimeUnit.SECONDS);
        }

        int exitValue() {
            return process.exitValue();
        }

        String output() throws Exception {
            outputDrained.get(5, TimeUnit.SECONDS);
            synchronized (output) {
                return output.toString();
            }
        }

        void destroyIfAlive() {
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }

        private void collectOutput() {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    synchronized (output) {
                        output.append(line).append('\n');
                    }
                    firstLine.complete(line);
                }
                firstLine.complete(null);
                outputDrained.complete(null);
            } catch (IOException exception) {
                firstLine.completeExceptionally(exception);
                outputDrained.completeExceptionally(exception);
            }
        }
    }
}
