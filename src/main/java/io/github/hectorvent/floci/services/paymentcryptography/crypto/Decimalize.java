package io.github.hectorvent.floci.services.paymentcryptography.crypto;

/**
 * The decimalization the Visa PIN Verification Value is made of.
 *
 * <p>The digits of the enciphered block are taken first, and the letters are turned into
 * numbers only if there are not enough digits: a letter stands for its position in the
 * alphabet, ten for A, eleven for B, and so on.
 */
public final class Decimalize {

    private Decimalize() {
    }

    /**
     * The first n digits of a hexadecimal string, decimalized.
     *
     * @param hex the hexadecimal string
     * @param n the number of digits wanted
     * @return the digits, which may be shorter than n when the string holds too few
     */
    public static String of(String hex, int n) {
        StringBuilder out = new StringBuilder(n);
        for (int i = 0; i < hex.length() && out.length() < n; i++) {
            char c = hex.charAt(i);
            if (c >= '0' && c <= '9') {
                out.append(c);
            }
        }
        if (out.length() < n) {
            for (int i = 0; i < hex.length() && out.length() < n; i++) {
                int v = Character.digit(hex.charAt(i), 16);
                if (v >= 10) {
                    out.append(v - 10);
                }
            }
        }
        return out.toString();
    }
}
