package io.github.hectorvent.floci.services.paymentcryptography.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
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
 * <p>The JCE's Triple DES is not registered in the native image, so a request that needs
 * it there hangs until the job is cancelled at its timeout, and the suite that would have
 * caught it never answers. Every cipher here is BouncyCastle's, so none of them depends
 * on what the image happens to carry.
 *
 * <p>ECB is the mode the block ciphers implement themselves, so one block goes in and one
 * block comes out, which is what the MACs read.
 */
public final class Ciphers {

    /** The block the Triple DES ciphers encrypt, in bytes. */
    private static final int BLOCK = 8;

    /** The block AES encrypts, in bytes. */
    private static final int AES_BLOCK = 16;

    private Ciphers() {
    }

    /**
     * The AES encryption of data under a key and an initialization vector, in CBC mode, without
     * padding.
     *
     * <p>The cipher pads no data, so the caller supplies whole blocks: a partial block is
     * refused rather than padded.
     *
     * @param data the bytes to encrypt
     * @param key the sixteen-, twenty-four- or thirty-two-byte key
     * @param iv16 the sixteen-byte vector to encrypt under
     * @return the encrypted bytes
     */
    public static byte[] aesCbcEncrypt(byte[] data, byte[] key, byte[] iv16) {
        return aesCbc(true, data, key, iv16);
    }

    /**
     * The AES decryption of data under a key and an initialization vector, in CBC mode, without
     * padding.
     *
     * @param data the bytes to decrypt
     * @param key the sixteen-, twenty-four- or thirty-two-byte key
     * @param iv16 the sixteen-byte vector to decrypt under
     * @return the decrypted bytes
     */
    public static byte[] aesCbcDecrypt(byte[] data, byte[] key, byte[] iv16) {
        return aesCbc(false, data, key, iv16);
    }

    /**
     * One block of AES in ECB mode.
     *
     * @param block16 the sixteen-byte block to encrypt
     * @param key the sixteen-, twenty-four- or thirty-two-byte key
     * @return the encrypted bytes
     */
    public static byte[] aesEcbEncrypt(byte[] block16, byte[] key) {
        return encrypt(new AESEngine(), block16, key);
    }

    /**
     * One block of AES in ECB mode, the other way round.
     *
     * @param block16 the sixteen-byte block to decrypt
     * @param key the sixteen-, twenty-four- or thirty-two-byte key
     * @return the decrypted bytes
     */
    public static byte[] aesEcbDecrypt(byte[] block16, byte[] key) {
        return decrypt(new AESEngine(), block16, key);
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
     * The ISO 9797-1 MAC algorithm 1 over Triple DES, with padding method 1.
     *
     * <p>Algorithm 1 is the CBC mode's chain over the zero-padded message, so the last
     * block it leaves is the MAC.
     *
     * @param key16 the sixteen-byte key
     * @param data the message to authenticate
     * @return the eight-byte MAC
     */
    public static byte[] iso9797Alg1(byte[] key16, byte[] data) {
        CBCBlockCipherMac mac = new CBCBlockCipherMac(new DESedeEngine(), 64, null);
        mac.init(new ParametersWithIV(new KeyParameter(key16), new byte[8]));
        byte[] padded = padZero(data);
        mac.update(padded, 0, padded.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    /**
     * The ISO 9797-1 MAC algorithm 3 over Triple DES, with padding method 1.
     *
     * <p>Algorithm 3 is the retail MAC: a single-DES chain under K1 for all but the
     * last block, then a final EDE under K1||K2.
     *
     * @param key16 the sixteen-byte key
     * @param data the message to authenticate
     * @return the eight-byte MAC
     */
    public static byte[] iso9797Alg3(byte[] key16, byte[] data) {
        ISO9797Alg3Mac mac = new ISO9797Alg3Mac(new DESEngine());
        mac.init(new KeyParameter(key16));
        mac.update(data, 0, data.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    /**
     * The zero padding of ISO 9797-1's padding method 1: to the next eight-byte boundary.
     *
     * <p>An empty message becomes one zero block, which is what the standard says.
     *
     * @param data the message to pad
     * @return the padded message
     */
    public static byte[] padZero(byte[] data) {
        if (data.length == 0) {
            return new byte[8];
        }
        int rem = data.length % 8;
        if (rem == 0) {
            return data;
        }
        byte[] out = new byte[data.length + (8 - rem)];
        System.arraycopy(data, 0, out, 0, data.length);
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
    private static byte[] encrypt(BlockCipher cipher, byte[] block, byte[] key) {
        int size = cipher.getBlockSize();
        if (block == null || block.length != size) {
            throw new IllegalArgumentException("the block is "
                    + (block == null ? "missing" : block.length + " bytes") + "; it is " + size);
        }
        if (key == null) {
            throw new IllegalArgumentException("key is required");
        }
        cipher.init(true, new KeyParameter(key));
        byte[] out = new byte[size];
        cipher.processBlock(block, 0, out, 0);
        return out;
    }

    /**
     * The decryption of one block under a key, in the cipher's own ECB mode.
     */
    private static byte[] decrypt(BlockCipher cipher, byte[] block, byte[] key) {
        int size = cipher.getBlockSize();
        if (block == null || block.length != size) {
            throw new IllegalArgumentException("the block is "
                    + (block == null ? "missing" : block.length + " bytes") + "; it is " + size);
        }
        if (key == null) {
            throw new IllegalArgumentException("key is required");
        }
        cipher.init(false, new KeyParameter(key));
        byte[] out = new byte[size];
        cipher.processBlock(block, 0, out, 0);
        return out;
    }

    /**
     * The encryption or decryption of whole blocks under a key, in CBC mode.
     */
    private static byte[] aesCbc(boolean encrypt, byte[] data, byte[] key, byte[] iv16) {
        if (data == null || data.length % AES_BLOCK != 0) {
            throw new IllegalArgumentException("the data is "
                    + (data == null ? "missing" : data.length + " bytes")
                    + "; it is a whole number of " + AES_BLOCK + "-byte blocks");
        }
        if (key == null) {
            throw new IllegalArgumentException("key is required");
        }
        if (iv16 == null || iv16.length != AES_BLOCK) {
            throw new IllegalArgumentException("the initialization vector is "
                    + (iv16 == null ? "missing" : iv16.length + " bytes") + "; it is " + AES_BLOCK);
        }
        CBCBlockCipher cipher = new CBCBlockCipher(new AESEngine());
        cipher.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv16));
        byte[] out = new byte[data.length];
        for (int offset = 0; offset < data.length; offset += AES_BLOCK) {
            cipher.processBlock(data, offset, out, offset);
        }
        return out;
    }
}
