package br.edu.ufersa.pratica.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Public keys pinned locally to project identities and key purposes. */
public final class TrustStore {
    private static final String MANIFEST_VERSION = "security-trust-v1";
    private static final int MAX_MANIFEST_BYTES = 1_048_576;
    private static final int MAX_IDENTITIES = 1_024;

    private final String project;
    private final Map<String, TrustedIdentity> identities;

    private TrustStore(String project, Map<String, TrustedIdentity> identities) {
        this.project = project;
        this.identities = Map.copyOf(identities);
    }

    /**
     * Loads a UTF-8 trust manifest and verifies each public key against its
     * SHA-256 fingerprint. Key files must remain beneath the manifest directory.
     */
    public static TrustStore load(Path manifest, String expectedProject) throws IOException, GeneralSecurityException {
        IdentityNames.requireValid(expectedProject, "O projeto");
        if (Files.size(manifest) > MAX_MANIFEST_BYTES) {
            throw new IOException("Manifesto de confiança excede o limite permitido.");
        }

        Path realManifest = manifest.toRealPath();
        Path realRoot = realManifest.getParent().toRealPath();
        List<String> lines = Files.readAllLines(realManifest, StandardCharsets.UTF_8);
        if (lines.isEmpty() || !lines.get(0).equals(MANIFEST_VERSION + "\t" + expectedProject)) {
            throw new IOException("Versão ou projeto do manifesto de confiança inválido.");
        }

        Map<String, TrustedIdentity> identities = new LinkedHashMap<>();
        for (int index = 1; index < lines.size(); index++) {
            String line = lines.get(index);
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            if (line.length() > 4_096) {
                throw new IOException("Linha excessiva no manifesto de confiança.");
            }

            String[] columns = line.split("\\t", -1);
            if (columns.length != 5) {
                throw new IOException("Linha inválida no manifesto de confiança: " + (index + 1));
            }
            String name;
            try {
                name = IdentityNames.requireValid(columns[0], "A identidade");
            } catch (IllegalArgumentException exception) {
                throw new IOException("Identidade inválida no manifesto de confiança.", exception);
            }
            if (identities.containsKey(name)) {
                throw new IOException("Identidade duplicada no manifesto de confiança: " + name);
            }

            Path transportPath = resolvePublicKey(realRoot, columns[1]);
            PublicKey transportKey = readVerifiedPublicKey(transportPath, columns[2]);
            Path signingPath = resolvePublicKey(realRoot, columns[3]);
            PublicKey signingKey = readVerifiedPublicKey(signingPath, columns[4]);
            identities.put(name, new TrustedIdentity(name, transportKey, signingKey));
            if (identities.size() > MAX_IDENTITIES) {
                throw new IOException("Manifesto contém identidades demais.");
            }
        }

        if (identities.isEmpty()) {
            throw new IOException("O manifesto de confiança não contém identidades.");
        }
        return new TrustStore(expectedProject, identities);
    }

    /**
     * Creates a manifest from generated key directories named after each
     * identity. The manifest must be a new direct child of {@code keysRoot}.
     */
    public static void writeManifest(String project, Path keysRoot, Collection<String> names, Path manifest)
            throws IOException, GeneralSecurityException {
        IdentityNames.requireValid(project, "O projeto");
        Path root = keysRoot.toRealPath();
        Path output = manifest.toAbsolutePath().normalize();
        if (!root.equals(output.getParent())) {
            throw new IOException("O manifesto deve ser criado diretamente no diretório raiz das chaves.");
        }
        if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("O manifesto já existe e não será sobrescrito: " + output);
        }
        if (names == null || names.isEmpty() || names.size() > MAX_IDENTITIES) {
            throw new IllegalArgumentException("Informe entre 1 e " + MAX_IDENTITIES + " identidades.");
        }

        List<String> sortedNames = new ArrayList<>(names);
        sortedNames.replaceAll(name -> IdentityNames.requireValid(name, "A identidade"));
        sortedNames.sort(String::compareTo);
        if (sortedNames.stream().distinct().count() != sortedNames.size()) {
            throw new IllegalArgumentException("A lista de identidades contém nomes duplicados.");
        }

        StringBuilder contents = new StringBuilder(MANIFEST_VERSION).append('\t').append(project).append('\n');
        for (String name : sortedNames) {
            Path identityDirectory = root.resolve(name).normalize();
            if (!identityDirectory.getParent().equals(root) || Files.isSymbolicLink(identityDirectory)) {
                throw new IOException("Diretório de identidade inválido: " + name);
            }
            Path realIdentityDirectory = identityDirectory.toRealPath();
            if (!realIdentityDirectory.getParent().equals(root)) {
                throw new IOException("Diretório de identidade fora da raiz de chaves: " + name);
            }
            Path transportPath = realIdentityDirectory.resolve(KeyFiles.TRANSPORT_PUBLIC);
            Path signingPath = realIdentityDirectory.resolve(KeyFiles.SIGNING_PUBLIC);
            if (Files.isSymbolicLink(transportPath) || Files.isSymbolicLink(signingPath)) {
                throw new IOException("A chave pública da identidade não pode ser um link simbólico: " + name);
            }
            PublicKey transportKey = KeyFiles.readPublicKey(transportPath);
            PublicKey signingKey = KeyFiles.readPublicKey(signingPath);
            String transportFingerprint = fingerprint(transportKey);
            String signingFingerprint = fingerprint(signingKey);
            contents.append(name).append('\t')
                    .append(name).append('/').append(KeyFiles.TRANSPORT_PUBLIC).append('\t')
                    .append(transportFingerprint).append('\t')
                    .append(name).append('/').append(KeyFiles.SIGNING_PUBLIC).append('\t')
                    .append(signingFingerprint).append('\n');
        }

        Files.writeString(output, contents, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    public String project() {
        return project;
    }

    int identityCount() {
        return identities.size();
    }

    public TrustedIdentity requireIdentity(String name) throws SecurityProtocolException {
        TrustedIdentity identity = identities.get(name);
        if (identity == null) {
            throw new SecurityProtocolException("Identidade não confiável para este projeto.");
        }
        return identity;
    }

    void requireLocalIdentity(LocalIdentity local) throws SecurityProtocolException {
        if (!project.equals(local.project())) {
            throw new SecurityProtocolException("A identidade local pertence a outro projeto.");
        }
        TrustedIdentity trusted = requireIdentity(local.name());
        if (!MessageDigest.isEqual(trusted.transportPublicKey().getEncoded(), local.transportPublicKey().getEncoded())
                || !MessageDigest.isEqual(trusted.signingPublicKey().getEncoded(), local.signingPublicKey().getEncoded())) {
            throw new SecurityProtocolException("As chaves locais não correspondem ao manifesto de confiança.");
        }
    }

    static String fingerprint(PublicKey key) throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
        return HexFormat.of().formatHex(digest);
    }

    private static Path resolvePublicKey(Path root, String relativeName) throws IOException {
        if (relativeName.isBlank()) {
            throw new IOException("Caminho vazio no manifesto de confiança.");
        }
        Path relative = Path.of(relativeName);
        if (relative.isAbsolute()) {
            throw new IOException("O manifesto contém um caminho absoluto.");
        }
        Path resolved = root.resolve(relative).normalize();
        if (!resolved.startsWith(root) || Files.isSymbolicLink(resolved) || !Files.isRegularFile(resolved)) {
            throw new IOException("Caminho de chave inválido no manifesto de confiança.");
        }
        Path realPath = resolved.toRealPath();
        if (!realPath.startsWith(root)) {
            throw new IOException("A chave pública referenciada está fora do manifesto.");
        }
        return realPath;
    }

    private static PublicKey readVerifiedPublicKey(Path path, String expectedFingerprint)
            throws IOException, GeneralSecurityException {
        if (!expectedFingerprint.matches("[0-9a-f]{64}")) {
            throw new IOException("Fingerprint inválido no manifesto de confiança.");
        }
        PublicKey key = KeyFiles.readPublicKey(path);
        byte[] expected = expectedFingerprint.getBytes(StandardCharsets.US_ASCII);
        byte[] actual = fingerprint(key).getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new IOException("Fingerprint da chave pública não confere: " + path.getFileName());
        }
        return key;
    }
}
