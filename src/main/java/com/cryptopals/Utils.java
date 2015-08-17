package com.cryptopals;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Map;
import java.util.Random;

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

    public static CryptoBuffer aesCbcEncryptWithKey(CryptoBuffer key, CryptoBuffer plaintext, CryptoBuffer iv) {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        try {
            aes.init(Cipher.ENCRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) {
        }

        CryptoBuffer ciphertext = new CryptoBuffer();
        try {
            ciphertext = Modes.cbcEncrypt(aes, plaintext, iv);
        } catch (BadPaddingException | IllegalBlockSizeException ignored) {
        }

        return ciphertext;
    }

    public static CryptoBuffer aesCbcDecryptWithKey(CryptoBuffer key, CryptoBuffer ciphertext, CryptoBuffer iv) {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        try {
            aes.init(Cipher.DECRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) {
        }

        CryptoBuffer plaintext = new CryptoBuffer();
        try {
            plaintext = Modes.cbcDecrypt(aes, ciphertext, iv);
        } catch (BadPaddingException | IllegalBlockSizeException ignored) {
        }

        return plaintext;
    }
}