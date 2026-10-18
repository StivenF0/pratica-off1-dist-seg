package br.edu.ufersa.pratica.security;

import java.security.SecureRandom;

/** Fixed cryptographic parameters for the practice protocol. */
public final class CryptoProfile {
    public static final int RSA_KEY_BITS = 3072;
    public static final int AES_KEY_BITS = 256;
    public static final int AES_KEY_BYTES = AES_KEY_BITS / Byte.SIZE;
    public static final int HMAC_KEY_BYTES = 32;
    public static final int HMAC_BYTES = 32;
    public static final int GCM_IV_BYTES = 12;
    public static final int GCM_TAG_BITS = 128;
    public static final int GCM_TAG_BYTES = GCM_TAG_BITS / Byte.SIZE;
    public static final int RSA_BYTES = RSA_KEY_BITS / Byte.SIZE;
    public static final int SIGNATURE_BYTES = RSA_BYTES;
    public static final int MAX_FRAME_BYTES = 1_048_576;
    public static final int SESSION_HEADER_BYTES = 35;
    public static final int MAX_SESSION_PAYLOAD_BYTES = MAX_FRAME_BYTES
            - SESSION_HEADER_BYTES - GCM_TAG_BYTES - HMAC_BYTES - SIGNATURE_BYTES;
    public static final int MAX_UDP_DATAGRAM_BYTES = 1_200;

    public static final SecureRandom RANDOM = new SecureRandom();

    private CryptoProfile() {
    }
}
