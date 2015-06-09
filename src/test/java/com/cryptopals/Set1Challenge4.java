package com.cryptopals;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by candrews on 09/06/15.
 */
public class Set1Challenge4 {

    @Test
    public void findXor() throws Exception {
        InputStream in = this.getClass().getResourceAsStream("set1challenge4.txt");
        if (in == null)
            fail("no stream");

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(in));
        String line;
        ArrayList<String> lines = new ArrayList<String>();

        while ((line = bufferedReader.readLine()) != null) {
            lines.add(line);
        }

        HashMap<String, String> ciphertexts = new HashMap<String, String>();
        HashMap<String, Character> keys = new HashMap<String, Character>();
        HashMap<String, Double> scores = new HashMap<String, Double>();

        for (String ciphertext : lines) {
            Character c;
            for (c = 0; c < 256; c++) {
                CryptoBuffer buf = CryptoBuffer.fromHex(ciphertext);
                String plaintext = XorCipher.xorCharacter(buf, c).toString();
                double score = Metrics.freqScore(Metrics.characterFreqs(plaintext));
                ciphertexts.put(plaintext, ciphertext);
                keys.put(plaintext, c);
                scores.put(plaintext, score);
            }
        }

        double maxScore = Double.MAX_VALUE;
        String thePlaintext = "";
        for (String plaintext : scores.keySet()) {
            double score = scores.get(plaintext);
            if (score < maxScore) {
                maxScore = score;
                thePlaintext = plaintext;
            }
        }

        assertEquals("Now that the party is jumping\n", thePlaintext);
        assertEquals("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f", ciphertexts.get(thePlaintext));
        assertEquals(new Character('5'), keys.get(thePlaintext));
    }
}

