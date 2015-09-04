package com.cryptopals;

import com.cryptopals.random.MT19937;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.nio.ByteBuffer;
import java.util.Random;


/**
 * Created by candrews on 26/08/15.
 */
public class Set3Challenge24 {

    @Test
    public void testMT19937Encryption() {
        MT19937 prng = new MT19937(1);
        CryptoBuffer plaintext = new CryptoBuffer("and this is the plaintext");

        prng.seed(1);
        CryptoBuffer ciphertext = Modes.prngStream(prng, plaintext);

        prng.seed(1);
        CryptoBuffer plaintext2 = Modes.prngStream(prng, ciphertext);

        assertNotEquals(plaintext, ciphertext);
        assertEquals(plaintext, plaintext2);
    }

    @Test
    public void breakPrngStream() {
        Random r = new Random();
        int seed = r.nextInt(65536);

        MT19937 prng = new MT19937(seed);
        CryptoBuffer plaintext = Utils.randomKey(r.nextInt(5) + 5).append(
                new CryptoBuffer(Utils.stringOfLength('A', 14))
        );
        CryptoBuffer ciphertext = Modes.prngStream(prng, plaintext);

        int adj = 4 - (((ciphertext.length()) - 14) % 4);
        CryptoBuffer knownCiphertext = ciphertext.substr((-14 + adj), 4);

        CryptoBuffer prngBytes = knownCiphertext.xorWith(new CryptoBuffer("AAAA"));
        int prngValue = ByteBuffer.allocate(Integer.SIZE / 8).put(prngBytes.toRawBytes()).getInt(0);

        int foundSeed = 0;
        for (int t = 0; t < 65536; t++) {
            prng.seed(t);
            for (int i = 0; i < 6; i++) {
                int nextInteger = prng.nextInteger();
                byte[] foo = ByteBuffer.allocate(Integer.SIZE / 8).putInt(nextInteger).array();
                if (nextInteger == prngValue) {
                    foundSeed = t;
                }
            }
        }

        assertEquals(seed, foundSeed);
    }

}
