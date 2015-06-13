package com.cryptopals;

import java.util.AbstractMap;
import java.util.Map;
import java.util.TreeSet;

/**
 * Created by candrews on 04/06/15.
 */
public class XorCipher {

    public static CryptoBuffer xorCharacter(CryptoBuffer buffer, Character c) {
        byte[] chars = new byte[buffer.length()];
        for (int i = 0; i < buffer.length(); i++)
            chars[i] = ((byte) c.charValue());
        return buffer.xorWith(new CryptoBuffer(chars));
    }

    public static CryptoBuffer xorString(CryptoBuffer buffer, String str) {
        int repeats = (int)Math.ceil(buffer.length() / (double)str.length());
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < repeats; i++)
            s.append(str);
        return buffer.xorWith(new CryptoBuffer(s.toString()));
    }

    public static char findXorKey(CryptoBuffer ciphertext) {
        TreeSet<Map.Entry<Character, Double>> scores = new TreeSet<>(new Utils.ScoreComparator<Double>());
        for (Character c = 0; c < 256; c++) {
            String plaintext = xorCharacter(ciphertext, c).toString();
            double score = Metrics.freqScore(Metrics.characterFreqs(plaintext));
            scores.add(new AbstractMap.SimpleImmutableEntry<>(c, score));
        }
        return scores.first().getKey();
    }
}
