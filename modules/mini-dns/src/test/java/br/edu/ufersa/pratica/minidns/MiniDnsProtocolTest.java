package br.edu.ufersa.pratica.minidns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MiniDnsProtocolTest {
    @Test
    void startsWithTheTenRequiredDnsRecords() {
        Map<String, String> records = MiniDnsProtocol.initialRecords();

        assertEquals(10, records.size());
        for (int number = 1; number <= 10; number++) {
            assertEquals("192.168.0." + number * 10, records.get("servidor" + number));
        }
    }

    @Test
    void parsesBoundedResolveAndUpdateRequests() {
        MiniDnsProtocol.Request query = MiniDnsProtocol.parseRequest(MiniDnsProtocol.resolve("servidor1"));
        assertEquals("RESOLVE", query.operation());
        assertEquals("servidor1", query.name());

        MiniDnsProtocol.Request invalidName = MiniDnsProtocol.parseRequest(MiniDnsProtocol.resolve("servidor99"));
        assertEquals("servidor99", invalidName.name());

        MiniDnsProtocol.Request update = MiniDnsProtocol.parseRequest(
                MiniDnsProtocol.update("servidor1", "192.168.0.111"));
        assertEquals("UPDATE", update.operation());
        assertEquals("192.168.0.111", update.address());
    }

    @Test
    void rejectsMalformedFieldsAndInvalidIpv4WithoutParsingHostnames() {
        assertThrows(IllegalArgumentException.class, () -> MiniDnsProtocol.parseRequest(
                "UPDATE\tservidor1\tlocalhost".getBytes(StandardCharsets.US_ASCII)));
        assertThrows(IllegalArgumentException.class, () -> MiniDnsProtocol.parseRequest(
                "RESOLVE\tservidor1\textra".getBytes(StandardCharsets.US_ASCII)));
        assertThrows(IllegalArgumentException.class, () -> MiniDnsProtocol.parseRequest(new byte[257]));
        assertFalse(MiniDnsProtocol.validIpv4("192.168.0.256"));
        assertFalse(MiniDnsProtocol.validIpv4("192.168.0.1/24"));
        assertTrue(MiniDnsProtocol.validIpv4("192.168.0.111"));
    }

    @Test
    void onlyTheThreeRequiredRegistrarUpdatesAreAllowed() {
        assertTrue(MiniDnsProtocol.allowedUpdate("servidor1", "192.168.0.111"));
        assertTrue(MiniDnsProtocol.allowedUpdate("servidor4", "192.168.0.144"));
        assertTrue(MiniDnsProtocol.allowedUpdate("servidor9", "192.168.0.199"));
        assertFalse(MiniDnsProtocol.allowedUpdate("servidor2", "192.168.0.22"));
        assertFalse(MiniDnsProtocol.allowedUpdate("servidor1", "192.168.0.1"));
    }

    @Test
    void encodesTheExactDomainErrorAndAuthenticatedReplyTypes() {
        MiniDnsProtocol.Reply error = MiniDnsProtocol.parseReply(MiniDnsProtocol.error());
        assertEquals("ERROR", error.operation());
        assertEquals("Erro na entrada de dados. Tente outra vez!", error.message());

        MiniDnsProtocol.Reply notification = MiniDnsProtocol.parseReply(
                MiniDnsProtocol.updateNotice("servidor4", "192.168.0.144"));
        assertEquals("UPDATE", notification.operation());
        assertEquals("servidor4", notification.name());
        assertEquals("192.168.0.144", notification.address());
    }
}
