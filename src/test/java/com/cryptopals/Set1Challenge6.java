package com.cryptopals;

import org.junit.Ignore;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.*;

/**
 * Created by candrews on 10/06/15.
 */
public class Set1Challenge6 {

    @Test
    public void hammingDistance() {
        CryptoBuffer left = new CryptoBuffer("this is a test");
        CryptoBuffer right = new CryptoBuffer("wokka wokka!!!");
        assertEquals(37, left.hammingDistance(right));
    }

    @Test
    public void breakRepeatingXor() throws Exception {
        ArrayList<String> lines = Utils.readFromClasspath("set1challenge6.txt");
        StringBuilder text = new StringBuilder();
        for (String line : lines) {
            text.append(line);
        }
        CryptoBuffer ciphertext = CryptoBuffer.fromBase64(text.toString());

        Map<Double, Integer> keysizes = new HashMap<>();

        for (int keysize = 2; keysize <= 40; keysize++) {
            ArrayList<Double> dists = new ArrayList<>();
            for (int x = 1; x <= 10; x++) {
                for (int y = 0; y <= 10; y++) {
                    if (x == y)
                        break;
                    CryptoBuffer s1 = ciphertext.substr(x * keysize, keysize);
                    CryptoBuffer s2 = ciphertext.substr(y * keysize, keysize);
                    double dist = s1.hammingDistance(s2) / keysize;
                    dists.add(dist);
                }
            }
            double sum = 0;
            for (double dist : dists)
                sum += dist;
            double avg = sum / dists.size();
            keysizes.put(avg, keysize);
        }

        double min = Double.MAX_VALUE;
        for (double avg : keysizes.keySet()) {
            if (avg < min)
                min = avg;
        }

        int keysize = keysizes.get(min);
        System.out.println("keysize: " + keysize);

        ArrayList<CryptoBuffer> blocks = ciphertext.transpose(keysize);
        ArrayList<Character> chars = new ArrayList<>(blocks.size());

        for (CryptoBuffer block : blocks) {
            HashMap<Double, Character> keys = new HashMap<>();

            Character c;
            for (c = 0; c < 256; c++) {
                String plaintext = XorCipher.xorCharacter(block, c).toString();
                keys.put(Metrics.freqScore(Metrics.characterFreqs(plaintext)), c);
            }

            min = Double.MAX_VALUE;
            char blockChar = 0x0;
            for (double score : keys.keySet()) {
                if (score < min) {
                    min = score;
                    blockChar = keys.get(score);
                }
            }

            chars.add(blockChar);
        }

        StringBuilder key = new StringBuilder();
        for (char c : chars)
            key.append(c);
        String plaintext = XorCipher.xorString(ciphertext, key.toString()).toString();

        System.out.println(plaintext);
    }
}
