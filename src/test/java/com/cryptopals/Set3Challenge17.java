package com.cryptopals;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

import com.cryptopals.attacks.cbc.PaddingOracle;

import javax.crypto.BadPaddingException;
import java.util.ArrayList;
import java.util.Random;

/**
 * Created by candrews on 18/08/15.
 */
public class Set3Challenge17 {

    private final static CryptoBuffer key = Utils.randomKey(16);
    private final static Random r = new Random();

    private final static ArrayList<CryptoBuffer> strings = new ArrayList<CryptoBuffer>() {{
        add(CryptoBuffer.fromBase64("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="));
        add(CryptoBuffer.fromBase64("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="));
        add(CryptoBuffer.fromBase64("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="));
        add(CryptoBuffer.fromBase64("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="));
        add(CryptoBuffer.fromBase64("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"));
        add(CryptoBuffer.fromBase64("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="));
        add(CryptoBuffer.fromBase64("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="));
        add(CryptoBuffer.fromBase64("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="));
        add(CryptoBuffer.fromBase64("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="));
        add(CryptoBuffer.fromBase64("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"));
    }};

    @Test
    public void cbcPaddingOracle() {
        PaddingOracle attack = new PaddingOracle(
                key,
                (CryptoBuffer iv, CryptoBuffer ciphertext) -> decryptString(iv, ciphertext)
        );

        ArrayList<CryptoBuffer> decrypts = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            CryptoBuffer decrypt = runAttack(attack);
            assert(decrypt.length() > 0);
            decrypts.add(decrypt);
        }
        assertEquals(100, decrypts.size());
    }

    private CryptoBuffer runAttack(PaddingOracle attack) {
        EncryptResult res = encryptString();
        CryptoBuffer plaintext = attack.cbcPaddingOracle(
                res.getIv(),
                res.getCiphertext()
        );
        return plaintext;
    }

    private EncryptResult encryptString() {
        CryptoBuffer string = strings.get(r.nextInt(strings.size()));
        CryptoBuffer iv = Utils.randomKey(16);
        CryptoBuffer ciphertext = Utils.aesCbcEncryptWithKey(key, iv, string);
        return new EncryptResult(iv, ciphertext);
    }

    private boolean decryptString(CryptoBuffer iv, CryptoBuffer ciphertext) {
        try {
            Utils.aesCbcDecryptWithKey(key, iv, ciphertext);
        }
        catch (BadPaddingException e) {
            return false;
        }
        return true;
    }

    private final class EncryptResult {

        private final CryptoBuffer ciphertext;
        private final CryptoBuffer iv;

        public EncryptResult(CryptoBuffer iv, CryptoBuffer ciphertext) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }

        public CryptoBuffer getCiphertext() {
            return ciphertext;
        }

        public CryptoBuffer getIv() {
            return iv;
        }
    }
}
