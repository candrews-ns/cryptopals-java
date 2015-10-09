package com.cryptopals;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.*;

/**
 * Created by candrews on 12/06/15.
 */
public class Utils {

    public static ArrayList<String> readLinesFromClasspath(String filename) throws Exception {
        InputStream in = Utils.class.getResourceAsStream(filename);
        if (in == null)
            throw new Exception("can't open " + filename);

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(in));
        String line;
        ArrayList<String> lines = new ArrayList<>();

        while ((line = bufferedReader.readLine()) != null) {
            lines.add(line);
        }

        return lines;
    }

    public static String readFromClasspath(String filename) throws Exception {
        ArrayList<String> lines = readLinesFromClasspath(filename);
        StringBuilder text = new StringBuilder();
        for (String line : lines) {
            text.append(line);
        }
        return text.toString();
    }

    public static class ScoreComparator<K extends Comparable<K>, V extends Comparable<V>> implements Comparator<Map.Entry<K, V>> {
        public int compare(Map.Entry<K, V> o1, Map.Entry<K, V> o2) {
            int r = o1.getValue().compareTo(o2.getValue());
            if (r != 0) {
                return r;
            } else {
                return o2.getKey().compareTo(o1.getKey());
            }
        }
    }

    public static CryptoBuffer randomKey(int len) {
        Random r = new Random();
        byte[] bytes = new byte[len];
        r.nextBytes(bytes);
        return new CryptoBuffer(bytes);
    }

    public static String stringOfLength(char c, int len) {
        StringBuilder s = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            s.append(c);
        }
        return s.toString();
    }

    public static CryptoBuffer bufferOfLength(byte b, int len) {
        byte[] bytes = new byte[len];
        for (int i = 0; i < len; i++) {
            bytes[i] = b;
        }
        return new CryptoBuffer(bytes);
    }

    public static CryptoBuffer aesEcbEncryptWithKey(CryptoBuffer key, CryptoBuffer plaintext) {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        try {
            aes.init(Cipher.ENCRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) {
        }

        CryptoBuffer ciphertext = new CryptoBuffer();
        try {
            ciphertext = Modes.ecb(aes, plaintext);
        } catch (BadPaddingException | IllegalBlockSizeException ignored) {
        }

        return ciphertext;
    }

    public static CryptoBuffer aesCbcEncryptWithKey(CryptoBuffer key, CryptoBuffer iv, CryptoBuffer plaintext) {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        try {
            aes.init(Cipher.ENCRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) {
        }

        CryptoBuffer ciphertext = new CryptoBuffer();
        try {
            ciphertext = Modes.cbcEncrypt(aes, iv, plaintext);
        } catch (BadPaddingException | IllegalBlockSizeException ignored) {
        }

        return ciphertext;
    }

    public static CryptoBuffer aesCbcDecryptWithKey(CryptoBuffer key, CryptoBuffer iv, CryptoBuffer ciphertext) throws BadPaddingException {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        try {
            aes.init(Cipher.DECRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) {
        }

        CryptoBuffer plaintext = new CryptoBuffer();
        try {
            plaintext = Modes.cbcDecrypt(aes, iv, ciphertext);
        } catch (IllegalBlockSizeException ignored) {
        }

        return plaintext;
    }

    public static CryptoBuffer aesCtrEncryptWithKey(CryptoBuffer key, CryptoBuffer nonce, CryptoBuffer plaintext) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        aes.init(Cipher.ENCRYPT_MODE, skey);
        return Modes.ctr(aes, nonce, plaintext);
    }

    public static HashMap<String, String> parseCookieString(String cookie) {
        HashMap<String, String> c = new HashMap<>();
        String[] chunks = cookie.split(";");
        for (String chunk : chunks) {
            String[] kv = chunk.split("=");
            if (kv.length == 2) {
                c.put(kv[0], kv[1]);
            }
        }

        return c;
    }

    private static final BigInteger THREE = BigInteger.valueOf(3);

    public static BigInteger cubeRoot(BigInteger n) {
        // Using Newton's method, we approximate the cube root
        // of n by the sequence:
        // x_{i + 1} = \frac{1}{3} \left( \frac{n}{x_i^2} + 2 x_i \right).
        // See http://en.wikipedia.org/wiki/Cube_root#Numerical_methods.
        //
        // Implementation based on Section 1.7.1 of
        // "A Course in Computational Algebraic Number Theory"
        // by Henri Cohen.
        BigInteger x = BigInteger.ZERO.setBit(n.bitLength() / 3 + 1);
        while (true) {
            BigInteger y = x.shiftLeft(1).add(n.divide(x.multiply(x))).divide(THREE);
            if (y.compareTo(x) >= 0) {
                break;
            }

            x = y;
        }

        return x;
    }
}