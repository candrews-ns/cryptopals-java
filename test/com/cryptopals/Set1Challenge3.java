package com.cryptopals;

import org.junit.Test;

import java.util.*;
import java.util.stream.Stream;

/**
 * Created by candrews on 05/06/15.
 */
public class Set1Challenge3 {

    @Test
    public void decryptXorCipher() throws Exception {

        CryptoBuffer ciphertext = CryptoBuffer.fromHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

        HashMap<Character, String> decrypts = new HashMap<Character, String>();
        HashMap<Character, Double> scores = new HashMap<Character, Double>();

        for (Character c = 0; c < 256; c++) {
            String decrypt = XorCipher.xorCharacter(ciphertext, c).toString();
            decrypts.put(c, decrypt);
            scores.put(c, Metrics.freqScore(Metrics.characterFreqs(decrypt)));
        }

        double maxScore = Double.MAX_VALUE;
        Character maxChar = 0x00;
        for (Character c = 0; c < 256; c++) {
            double score = scores.get(c);
            if (score < maxScore) {
                maxScore = score;
                maxChar = c;
            }
        }

        System.out.println("The decrypt with character '" + maxChar + "':");
        System.out.println(decrypts.get(maxChar));
    }
}
