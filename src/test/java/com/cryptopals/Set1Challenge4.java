package com.cryptopals;

import org.junit.Test;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeSet;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 09/06/15.
 */
public class Set1Challenge4 {

    @Test
    public void findXor() throws Exception {
        ArrayList<String> lines = Utils.readFromClasspath("set1challenge4.txt");

        TreeSet<Map.Entry<Candidate, Double>> scores = new TreeSet<>(new Utils.ScoreComparator<Double>());

        for (String ciphertext : lines) {
            for (Character c = 0; c < 256; c++) {
                CryptoBuffer buf = CryptoBuffer.fromHex(ciphertext);
                String plaintext = XorCipher.xorCharacter(buf, c).toString();
                double score = Metrics.freqScore(Metrics.characterFreqs(plaintext));
                Candidate cand = new Candidate(c, buf);
                scores.add(new AbstractMap.SimpleImmutableEntry<>(cand, score));
            }
        }

        Candidate cand = scores.first().getKey();
        String plaintext = XorCipher.xorCharacter(cand.ciphertext, cand.key).toString();

        assertEquals("Now that the party is jumping\n", plaintext);
        assertEquals('5', cand.key);
    }

    private class Candidate {
        public char key;
        public CryptoBuffer ciphertext;

        public Candidate(char key, CryptoBuffer ciphertext) {
            this.key = key;
            this.ciphertext = ciphertext;
        }
    }
}

