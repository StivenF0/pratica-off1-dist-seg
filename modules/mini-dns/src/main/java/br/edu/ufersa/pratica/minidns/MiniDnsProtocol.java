package br.edu.ufersa.pratica.minidns;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

final class MiniDnsProtocol {
    static final String PROJECT = "mini-dns";
    static final String DNS_SERVER = "dns-server";
    static final String REGISTRAR = "registrar";
    static final String INVALID_INPUT = "Erro na entrada de dados. Tente outra vez!";
    static final List<String> CLIENTS = List.of("dns-client-1", "dns-client-2", "dns-client-3");
    private static final Pattern NAME = Pattern.compile("servidor[0-9]{1,2}");
    private static final Pattern OCTET = Pattern.compile("[0-9]{1,3}");
    private static final int MAX_MESSAGE_BYTES = 256;

    private MiniDnsProtocol() {
    }

    static Map<String, String> initialRecords() {
        Map<String, String> records = new LinkedHashMap<>();
        for (int number = 1; number <= 10; number++) {
            records.put("servidor" + number, "192.168.0." + number * 10);
        }
        return records;
    }

    static byte[] resolve(String name) {
        requireName(name);
        return encode("RESOLVE\t" + name);
    }

    static byte[] update(String name, String address) {
        requireName(name);
        if (!validIpv4(address)) {
            throw new IllegalArgumentException(INVALID_INPUT);
        }
        return encode("UPDATE\t" + name + "\t" + address);
    }

    static byte[] answer(String name, String address) {
        return encode("ANSWER\t" + name + "\t" + address);
    }

    static byte[] updateNotice(String name, String address) {
        return encode("UPDATE\t" + name + "\t" + address);
    }

    static byte[] updated(String name, String address) {
        return encode("UPDATED\t" + name + "\t" + address);
    }

    static byte[] error() {
        return encode("ERROR\t" + INVALID_INPUT);
    }

    static Request parseRequest(byte[] payload) {
        String[] fields = fields(payload);
        if (fields.length == 2 && fields[0].equals("RESOLVE") && isName(fields[1])) {
            return new Request("RESOLVE", fields[1], null);
        }
        if (fields.length == 3 && fields[0].equals("UPDATE") && isName(fields[1])
                && validIpv4(fields[2])) {
            return new Request("UPDATE", fields[1], fields[2]);
        }
        throw new IllegalArgumentException(INVALID_INPUT);
    }

    static Reply parseReply(byte[] payload) {
        String[] fields = fields(payload);
        if (fields.length == 2 && fields[0].equals("ERROR")) {
            return new Reply("ERROR", null, null, fields[1]);
        }
        if (fields.length == 3 && (fields[0].equals("ANSWER") || fields[0].equals("UPDATE")
                || fields[0].equals("UPDATED")) && isName(fields[1]) && validIpv4(fields[2])) {
            return new Reply(fields[0], fields[1], fields[2], null);
        }
        throw new IllegalArgumentException(INVALID_INPUT);
    }

    static boolean allowedUpdate(String name, String address) {
        return switch (name) {
            case "servidor1" -> address.equals("192.168.0.111");
            case "servidor4" -> address.equals("192.168.0.144");
            case "servidor9" -> address.equals("192.168.0.199");
            default -> false;
        };
    }

    static boolean isName(String value) {
        return value != null && NAME.matcher(value).matches();
    }

    static boolean validIpv4(String address) {
        if (address == null) {
            return false;
        }
        String[] octets = address.split("\\.", -1);
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (!OCTET.matcher(octet).matches() || Integer.parseInt(octet) > 255) {
                return false;
            }
        }
        return true;
    }

    private static byte[] encode(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        if (bytes.length > MAX_MESSAGE_BYTES) {
            throw new IllegalArgumentException(INVALID_INPUT);
        }
        return bytes;
    }

    private static String[] fields(byte[] payload) {
        if (payload == null || payload.length == 0 || payload.length > MAX_MESSAGE_BYTES) {
            throw new IllegalArgumentException(INVALID_INPUT);
        }
        for (byte value : payload) {
            int character = Byte.toUnsignedInt(value);
            if (character != '\t' && (character < 0x20 || character > 0x7e)) {
                throw new IllegalArgumentException(INVALID_INPUT);
            }
        }
        return new String(payload, StandardCharsets.US_ASCII).split("\\t", -1);
    }

    private static void requireName(String name) {
        if (!isName(name)) {
            throw new IllegalArgumentException(INVALID_INPUT);
        }
    }

    record Request(String operation, String name, String address) {
    }

    record Reply(String operation, String name, String address, String message) {
    }
}
