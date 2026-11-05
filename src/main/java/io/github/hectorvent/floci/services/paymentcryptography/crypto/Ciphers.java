package io.github.hectorvent.floci.services.paymentcryptography.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

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
     * K1||K2||K1, which is what the two-key form means. A three-key key is taken as it is.
     *
     * @param block8 the eight-byte block to encrypt
     * @param key the sixteen- or twenty-four-byte key
     * @return the encrypted block
     */
    public static byte[] tdes2Encrypt(byte[] block8, byte[] key) {
        return tdes3Encrypt(block8, widenTdesKey(key));
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
     * The Triple DES encryption of data under a two-key key, in CBC mode.
     *
     * <p>The two-key form is K1||K2, and the cipher takes three keys, so it is widened to
     * K1||K2||K1, which is what the two-key form means. A three-key key is taken as it is.
     * The cipher pads no data, so the data fills whole blocks of eight bytes.
     *
     * @param data the data to encrypt, a whole number of blocks
     * @param key the sixteen- or twenty-four-byte key
     * @param iv8 the eight-byte vector to encrypt under
     * @return the encrypted bytes
     */
    public static byte[] tdesCbcEncrypt(byte[] data, byte[] key, byte[] iv8) {
        return tdesCbc(true, data, key, iv8);
    }

    /**
     * The Triple DES decryption of data under a two-key key, in CBC mode.
     *
     * @param data the encrypted bytes, a whole number of blocks
     * @param key the sixteen- or twenty-four-byte key
     * @param iv8 the eight-byte vector to decrypt under
     * @return the plaintext
     */
    public static byte[] tdesCbcDecrypt(byte[] data, byte[] key, byte[] iv8) {
        return tdesCbc(false, data, key, iv8);
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
     * first eight bytes: K1||K2 becomes K1||K2||K1. A three-key key is taken as it is.
     *
     * @param key the sixteen- or twenty-four-byte key
     * @return the twenty-four-byte key
     */
    public static byte[] widenTdesKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("key is required");
        }
        if (key.length == 24) {
            return key;
        }
        if (key.length != 16) {
            throw new IllegalArgumentException("the Triple DES key is " + key.length
                    + " bytes; it is 16 or 24");
        }
        byte[] wide = Arrays.copyOf(key, 24);
        System.arraycopy(key, 0, wide, 16, 8);
        return wide;
    }

    /**
     * The encryption or decryption of whole blocks under a key, in CBC mode.
     */
    private static byte[] tdesCbc(boolean encrypt, byte[] data, byte[] key, byte[] iv8) {
        if (data == null || data.length == 0 || data.length % BLOCK != 0) {
            throw new IllegalArgumentException("the data is "
                    + (data == null ? "missing" : data.length + " bytes") + "; it is a whole number of "
                    + BLOCK + "-byte blocks");
        }
        if (key == null) {
            throw new IllegalArgumentException("key is required");
        }
        if (iv8 == null || iv8.length != BLOCK) {
            throw new IllegalArgumentException("the initialization vector is "
                    + (iv8 == null ? "missing" : iv8.length + " bytes") + "; it is " + BLOCK);
        }
        CBCBlockCipher cipher = new CBCBlockCipher(new DESedeEngine());
        cipher.init(encrypt, new ParametersWithIV(new KeyParameter(widenTdesKey(key)), iv8));
        byte[] out = new byte[data.length];
        for (int offset = 0; offset < data.length; offset += BLOCK) {
            cipher.processBlock(data, offset, out, offset);
        }
        return out;
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
