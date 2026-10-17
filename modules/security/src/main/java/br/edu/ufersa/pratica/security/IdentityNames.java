package br.edu.ufersa.pratica.security;

import java.util.regex.Pattern;

final class IdentityNames {
    private static final Pattern VALID_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");

    private IdentityNames() {
    }

    static String requireValid(String value, String description) {
        if (value == null || !VALID_NAME.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    description + " deve conter entre 1 e 64 caracteres: letras, números, ponto, hífen ou underscore.");
        }
        return value;
    }
}
