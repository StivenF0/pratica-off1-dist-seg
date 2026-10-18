package br.edu.ufersa.pratica.security.cli;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashMap;
import br.edu.ufersa.pratica.security.identity.LocalIdentity;

/** Generates a local identity's RSA key pairs. */
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
        if (args == null || args.length == 0 || !args[0].equals("generate-keys")) {
            printUsage();
            return 2;
        }
        try {
            Map<String, String> options = parse(args);
            if (!options.keySet().equals(Set.of("project", "identity", "directory"))) {
                throw new IllegalArgumentException("Informe --project, --identity e --directory.");
            }
            LocalIdentity.generate(options.get("project"), options.get("identity"),
                    Path.of(options.get("directory")));
            System.out.printf("Chaves RSA-3072 geradas para %s/%s; não compartilhe nem versione as privadas.%n",
                    options.get("project"), options.get("identity"));
            return 0;
        } catch (IllegalArgumentException | java.io.IOException | java.security.GeneralSecurityException exception) {
            System.err.println("Erro de segurança: " + exception.getMessage());
            return 1;
        }
    }

    private static Map<String, String> parse(String[] args) {
        Map<String, String> options = new LinkedHashMap<>();
        for (int i = 1; i < args.length; i += 2) {
            if (!args[i].startsWith("--") || i + 1 == args.length) {
                throw new IllegalArgumentException("Opção incompleta ou inválida: " + args[i]);
            }
            String key = args[i].substring(2);
            if (!Set.of("project", "identity", "directory").contains(key)
                    || options.putIfAbsent(key, args[i + 1]) != null || args[i + 1].isBlank()) {
                throw new IllegalArgumentException("Opção desconhecida, repetida ou vazia: " + args[i]);
            }
        }
        return options;
    }

    private static void printUsage() {
        System.out.println("Uso: generate-keys --project <projeto> --identity <id> --directory <diretório>");
    }
}
