package com.cryptopals;

import org.junit.Test;

import java.util.ArrayList;

/**
 * Created by candrews on 19/08/15.
 */
public class Set3Challenge20 {

    private static final CryptoBuffer key = Utils.randomKey(16);
    private static final CryptoBuffer nonce = new CryptoBuffer(new byte[8]);

    @Test
    public void breakCtrStatistically() throws Exception {
        ArrayList<String> lines = Utils.readLinesFromClasspath("set3challenge20.txt");
        ArrayList<CryptoBuffer> ciphertexts = new ArrayList<>();

        int length = Integer.MAX_VALUE;
        for (String line : lines) {
            CryptoBuffer plaintext = CryptoBuffer.fromBase64(line);
            CryptoBuffer ciphertext = Utils.aesCtrEncryptWithKey(key, nonce, plaintext);
            ciphertexts.add(ciphertext);
            if (ciphertext.length() < length) {
                length = ciphertext.length();
            }
        }

        // this works, but 60 doesn't
        length = 59;

        CryptoBuffer truncated = new CryptoBuffer();
        for (CryptoBuffer ciphertext : ciphertexts) {
            truncated.append(ciphertext.substr(0, length));
        }
        ArrayList<CryptoBuffer> blocks = truncated.transpose(length);

        byte[] chars = new byte[length];
        int i = 0;
        for (CryptoBuffer block : blocks) {
            chars[i] = (byte)XorCipher.findXorKey(block);
            i++;
        }
        CryptoBuffer keystream = new CryptoBuffer(chars);

        for (CryptoBuffer ciphertext : ciphertexts) {
            CryptoBuffer plaintext = ciphertext.xorWith(keystream);
            System.out.println(plaintext);
        }
    }

}
