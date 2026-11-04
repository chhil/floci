package io.github.hectorvent.floci.services.paymentcryptography.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * The block ciphers the data plane's MACs are built from.
 *
 * <p>The Triple DES and the Single DES are the two the ISO 9797-1 MACs and the DUKPT
 * derivations use, and both are used in ECB mode over a single block. BouncyCastle is used
 * for them rather than the JCE, whose {@code DESede} takes a three-key key alone and
 * whose provider defaults differ: the two-key form is widened here, so both the cipher
 * and the key are the ones the MAC is defined over.
 *
 * <p>ECB is the mode the block ciphers implement themselves, so one block goes in and one
 * block comes out, which is what the MACs read.
 */
public final class Ciphers {

    /** The block the ciphers encrypt, in bytes. */
    private static final int BLOCK = 8;

    private Ciphers() {
    }

    /**
     * The Triple DES encryption of a block under a two-key key, in ECB mode.
     *
     * <p>The two-key form is K1||K2, and the cipher takes three keys, so it is widened to
     * K1||K2||K1, which is what the two-key form means.
     *
     * @param block8 the eight-byte block to encrypt
     * @param key16 the sixteen-byte key
     * @return the encrypted block
     */
    public static byte[] tdes2Encrypt(byte[] block8, byte[] key16) {
        return tdes3Encrypt(block8, widenTdesKey(key16));
    }

    /**
     * The Triple DES encryption of a block under a three-key key, in ECB mode.
     *
     * @param block8 the eight-byte block to encrypt
     * @param key24 the twenty-four-byte key
     * @return the encrypted block
     */
    public static byte[] tdes3Encrypt(byte[] block8, byte[] key24) {
        return encrypt(new DESedeEngine(), block8, key24);
    }

    /**
     * The Single DES encryption of a block under a key, in ECB mode.
     *
     * @param block8 the eight-byte block to encrypt
     * @param key8 the eight-byte key
     * @return the encrypted block
     */
    public static byte[] tdesSingleDesEncrypt(byte[] block8, byte[] key8) {
        return encrypt(new DESEngine(), block8, key8);
    }

    /**
     * The exclusive-or of two byte arrays of the same length.
     *
     * @param a the first bytes
     * @param b the second bytes
     * @return the exclusive-or of the two
     */
    public static byte[] xor(byte[] a, byte[] b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("both byte arrays are required");
        }
        if (a.length != b.length) {
            throw new IllegalArgumentException("the byte arrays are of different lengths: "
                    + a.length + " and " + b.length);
        }
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    /**
     * A two-key Triple DES key widened to the three the cipher takes, by appending its own
     * first eight bytes: K1||K2 becomes K1||K2||K1.
     *
     * @param key16 the sixteen-byte key
     * @return the twenty-four-byte key
     */
    public static byte[] widenTdesKey(byte[] key16) {
        if (key16 == null || key16.length != 16) {
            throw new IllegalArgumentException("the key is "
                    + (key16 == null ? "missing" : key16.length + " bytes") + "; it is 16");
        }
        byte[] wide = Arrays.copyOf(key16, 24);
        System.arraycopy(key16, 0, wide, 16, 8);
        return wide;
    }

    /**
     * The encryption of one block under a key, in the cipher's own ECB mode.
     */
    private static byte[] encrypt(BlockCipher cipher, byte[] block8, byte[] key) {
        if (block8 == null || block8.length != BLOCK) {
            throw new IllegalArgumentException("the block is "
                    + (block8 == null ? "missing" : block8.length + " bytes") + "; it is " + BLOCK);
        }
        if (key == null) {
            throw new IllegalArgumentException("key is required");
        }
        cipher.init(true, new KeyParameter(key));
        byte[] out = new byte[BLOCK];
        cipher.processBlock(block8, 0, out, 0);
        return out;
    }
}
