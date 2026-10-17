package br.edu.ufersa.pratica.security;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Local key provisioning commands; private keys are never sent over the network. */
public final class SecurityCli {
    private SecurityCli() {
    }

    public static void main(String[] args) {
        int exitCode = run(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    public static int run(String[] args) {
        if (args == null || args.length == 0) {
            printUsage();
            return 2;
        }
        try {
            Map<String, String> options = parseOptions(args);
            switch (args[0]) {
                case "generate-keys" -> {
                    requireOnly(options, Set.of("project", "identity", "directory"));
                    generateKeys(options);
                }
                case "create-trust-manifest" -> {
                    requireOnly(options, Set.of("project", "directory", "output", "identities"));
                    createManifest(options);
                }
                default -> {
                    printUsage();
                    return 2;
                }
            }
            return 0;
        } catch (IllegalArgumentException | java.io.IOException | java.security.GeneralSecurityException exception) {
            System.err.println("Erro de segurança: " + exception.getMessage());
            return 1;
        }
    }

    private static void generateKeys(Map<String, String> options)
            throws java.io.IOException, java.security.GeneralSecurityException {
        String project = required(options, "project");
        String identity = required(options, "identity");
        Path directory = Path.of(required(options, "directory"));
        LocalIdentity.generate(project, identity, directory);
        System.out.println("Chaves RSA-3072 geradas para " + project + "/" + identity + ".");
        System.out.println("As chaves privadas foram gravadas localmente; não as compartilhe nem as versione.");
    }

    private static void createManifest(Map<String, String> options)
            throws java.io.IOException, java.security.GeneralSecurityException {
        String project = required(options, "project");
        Path directory = Path.of(required(options, "directory"));
        Path output = Path.of(required(options, "output"));
        List<String> identities = Arrays.stream(required(options, "identities").split(",", -1))
                .map(String::trim)
                .toList();
        TrustStore.writeManifest(project, directory, identities, output);
        System.out.println("Manifesto de confiança criado: " + output.toAbsolutePath().normalize());
        System.out.println("Distribua-o por um canal local confiável e confira os fingerprints antes da execução.");
    }

    private static Map<String, String> parseOptions(String[] args) {
        Map<String, String> options = new LinkedHashMap<>();
        for (int index = 1; index < args.length; index += 2) {
            String option = args[index];
            if (!option.startsWith("--") || option.length() <= 2 || index + 1 >= args.length) {
                throw new IllegalArgumentException("Opção incompleta ou inválida: " + option);
            }
            String key = option.substring(2);
            if (!List.of("project", "identity", "directory", "output", "identities").contains(key)) {
                throw new IllegalArgumentException("Opção desconhecida: " + option);
            }
            if (options.putIfAbsent(key, args[index + 1]) != null) {
                throw new IllegalArgumentException("Opção repetida: " + option);
            }
        }
        return options;
    }

    private static String required(Map<String, String> options, String name) {
        String value = options.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Informe --" + name + ".");
        }
        return value;
    }

    private static void requireOnly(Map<String, String> options, Set<String> allowed) {
        for (String option : options.keySet()) {
            if (!allowed.contains(option)) {
                throw new IllegalArgumentException("A opção --" + option + " não se aplica a este comando.");
            }
        }
    }

    private static void printUsage() {
        System.out.println("Uso:");
        System.out.println("  generate-keys --project <projeto> --identity <id> --directory <diretório-da-identidade>");
        System.out.println("  create-trust-manifest --project <projeto> --directory <raiz-das-chaves> "
                + "--output <raiz/trust.tsv> --identities <id1,id2,...>");
        System.out.println("Exemplo: ./gradlew :security:run --args='generate-keys --project mini-dns "
                + "--identity dns-server --directory security-keys/mini-dns/dns-server'");
    }
}
