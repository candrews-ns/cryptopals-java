package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.ArrayList;

/**
 * Created by candrews on 19/08/15.
 */
public class Set3Challenge19 {

    private static final CryptoBuffer key = Utils.randomKey(16);
    private static final CryptoBuffer nonce = new CryptoBuffer(new byte[8]);

    @Test
    public void breakCtr() throws Exception {
        ArrayList<String> lines = Utils.readLinesFromClasspath("set3challenge19.txt");
        ArrayList<CryptoBuffer> ciphertexts = new ArrayList<>();

        int length = Integer.MAX_VALUE;
        for (String line : lines) {
            CryptoBuffer plaintext = CryptoBuffer.fromBase64(line);
            CryptoBuffer ciphertext = encryptCtr(plaintext);
            ciphertexts.add(ciphertext);
            if (ciphertext.length() < length) {
                length = ciphertext.length();
            }
        }

        TrigramScore[] scores = new TrigramScore[length];
        CryptoBuffer keystream = new CryptoBuffer();

        for (int i = 0; i < (length - 3); i++) {
            CryptoBuffer triplet = ciphertexts.get(0).substr(i, 3);
            for (CryptoBuffer root : Metrics.allTrigrams()) {
                CryptoBuffer key = root.xorWith(triplet);
                CryptoBuffer buffer = new CryptoBuffer("");
                for (CryptoBuffer ciphertext : ciphertexts) {
                    buffer.append(key.xorWith(ciphertext.substr(i, 3)));
                }
                double score = Metrics.trigramScore(buffer);
                if (scores[i] == null || score > scores[i].getScore()) {
                    for (int j = 0; j < 3; j++) {
                        scores[i+j] = new TrigramScore(score, key.substr(j, 1));
                    }
                }
            }
            keystream.append(scores[i].getCharacter());
        }

        for (CryptoBuffer ciphertext : ciphertexts) {
            CryptoBuffer plaintext = ciphertext.xorWith(keystream);
            System.out.println(plaintext);
        }
    }

    private CryptoBuffer encryptCtr(CryptoBuffer plaintext) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        aes.init(Cipher.ENCRYPT_MODE, skey);
        return Modes.ctr(aes, nonce, plaintext);
    }

    private class TrigramScore {
        private final double score;

        private final CryptoBuffer character;

        public TrigramScore(double score, CryptoBuffer character) {
            this.score = score;
            this.character = character;
        }

        public CryptoBuffer getCharacter() {
            return character;
        }

        public double getScore() {
            return score;
        }

    }
}
