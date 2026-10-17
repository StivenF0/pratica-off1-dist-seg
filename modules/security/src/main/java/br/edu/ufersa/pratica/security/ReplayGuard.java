package br.edu.ufersa.pratica.security;

import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.LongSupplier;

/** Bounded, in-memory replay protection with a fail-closed startup quarantine. */
public final class ReplayGuard {
    private final Clock clock;
    private final LongSupplier monotonicNanos;
    private final long startedAtNanos;
    private final long maxLifetimeMillis;
    private final long clockSkewMillis;
    private final long quarantineNanos;
    private final int capacity;
    private final Map<MessageKey, Long> seen = new HashMap<>();

    public ReplayGuard() {
        this(Clock.systemUTC(), System::nanoTime,
                CryptoProfile.MAX_MESSAGE_LIFETIME, CryptoProfile.CLOCK_SKEW,
                CryptoProfile.MAX_MESSAGE_LIFETIME.plus(CryptoProfile.CLOCK_SKEW.multipliedBy(2)),
                CryptoProfile.DEFAULT_REPLAY_CAPACITY);
    }

    /** Configurable constructor, useful for controlled clocks in tests and local scenarios. */
    public ReplayGuard(Clock clock, LongSupplier monotonicNanos, Duration maxLifetime,
                      Duration clockSkew, Duration startupQuarantine, int capacity) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.monotonicNanos = Objects.requireNonNull(monotonicNanos, "monotonicNanos");
        this.maxLifetimeMillis = requireNonNegativeMillis(maxLifetime, "maxLifetime", false);
        if (this.maxLifetimeMillis == 0) {
            throw new IllegalArgumentException("maxLifetime precisa ser de pelo menos um milissegundo.");
        }
        this.clockSkewMillis = requireNonNegativeMillis(clockSkew, "clockSkew", true);
        this.quarantineNanos = requireNonNegativeNanos(startupQuarantine, "startupQuarantine");
        if (capacity < 1) {
            throw new IllegalArgumentException("A capacidade do cache antirreplay deve ser positiva.");
        }
        this.capacity = capacity;
        this.startedAtNanos = monotonicNanos.getAsLong();
    }

    public boolean isReady() {
        return monotonicNanos.getAsLong() - startedAtNanos >= quarantineNanos;
    }

    public Duration remainingQuarantine() {
        long elapsed = monotonicNanos.getAsLong() - startedAtNanos;
        long remaining = Math.max(0, quarantineNanos - elapsed);
        return Duration.ofNanos(remaining);
    }

    public int rememberedMessageCount() {
        synchronized (seen) {
            return seen.size();
        }
    }

    void ensureReady() throws SecurityProtocolException {
        if (!isReady()) {
            throw new SecurityProtocolException("Recepção bloqueada durante a janela inicial de proteção antirreplay.");
        }
    }

    void validateTimestamps(long issuedAtMillis, long expiresAtMillis) throws SecurityProtocolException {
        validateTimestampsAt(clock.millis(), issuedAtMillis, expiresAtMillis);
    }

    private void validateTimestampsAt(long now, long issuedAtMillis, long expiresAtMillis)
            throws SecurityProtocolException {
        if (issuedAtMillis <= 0 || expiresAtMillis <= issuedAtMillis) {
            throw new SecurityProtocolException("Validade da mensagem inválida.");
        }
        if (issuedAtMillis > saturatingAdd(now, clockSkewMillis)) {
            throw new SecurityProtocolException("A mensagem foi emitida no futuro.");
        }
        if (expiresAtMillis < saturatingSubtract(now, clockSkewMillis)) {
            throw new SecurityProtocolException("A mensagem expirou.");
        }
        if (expiresAtMillis > saturatingAdd(issuedAtMillis, maxLifetimeMillis)) {
            throw new SecurityProtocolException("A mensagem excede a validade máxima permitida.");
        }
    }

    boolean claim(String sender, UUID messageId, long issuedAtMillis, long expiresAtMillis)
            throws SecurityProtocolException {
        ensureReady();
        MessageKey key = new MessageKey(sender, messageId);
        synchronized (seen) {
            long now = clock.millis();
            Iterator<Map.Entry<MessageKey, Long>> iterator = seen.entrySet().iterator();
            while (iterator.hasNext()) {
                if (iterator.next().getValue() < now) {
                    iterator.remove();
                }
            }

            // Recheck under the replay-cache lock so expiry cannot race the claim.
            validateTimestampsAt(now, issuedAtMillis, expiresAtMillis);
            if (seen.containsKey(key)) {
                return false;
            }
            if (seen.size() >= capacity) {
                throw new SecurityProtocolException("Cache antirreplay cheio; novas mensagens foram rejeitadas.");
            }
            seen.put(key, saturatingAdd(expiresAtMillis, clockSkewMillis));
            return true;
        }
    }

    private static long requireNonNegativeMillis(Duration duration, String name, boolean allowZero) {
        Objects.requireNonNull(duration, name);
        if (duration.isNegative() || (!allowZero && duration.isZero())) {
            throw new IllegalArgumentException(name + " possui duração inválida.");
        }
        try {
            return duration.toMillis();
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException(name + " excede o limite suportado.", exception);
        }
    }

    private static long requireNonNegativeNanos(Duration duration, String name) {
        Objects.requireNonNull(duration, name);
        if (duration.isNegative()) {
            throw new IllegalArgumentException(name + " não pode ser negativo.");
        }
        try {
            return duration.toNanos();
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException(name + " excede o limite suportado.", exception);
        }
    }

    private static long saturatingAdd(long left, long right) {
        try {
            return Math.addExact(left, right);
        } catch (ArithmeticException ignored) {
            return Long.MAX_VALUE;
        }
    }

    private static long saturatingSubtract(long left, long right) {
        try {
            return Math.subtractExact(left, right);
        } catch (ArithmeticException ignored) {
            return Long.MIN_VALUE;
        }
    }

    private record MessageKey(String sender, UUID messageId) {
    }
}
