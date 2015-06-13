package com.cryptopals;

import org.junit.Test;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeSet;

import static org.junit.Assert.assertEquals;

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
        String text = Utils.readFromClasspath("set1challenge6.txt");
        CryptoBuffer ciphertext = CryptoBuffer.fromBase64(text);

        TreeSet<Map.Entry<Integer, Double>> keysizes = new TreeSet<>(new Utils.ScoreComparator<Double>());

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
            keysizes.add(new AbstractMap.SimpleImmutableEntry<>(keysize, avg));
        }

        int keysize = keysizes.first().getKey();
        assertEquals(29, keysize);

        ArrayList<CryptoBuffer> blocks = ciphertext.transpose(keysize);
        ArrayList<Character> chars = new ArrayList<>(blocks.size());

        for (CryptoBuffer block : blocks) {
            chars.add(XorCipher.findXorKey(block));
        }

        StringBuilder key = new StringBuilder();
        for (char c : chars)
            key.append(c);
        String plaintext = XorCipher.xorString(ciphertext, key.toString()).toString();

        //System.out.println(plaintext);
        //assert(plaintext.matches("I'm back and I'm ringin' the bell"));
    }
}
