package com.cryptopals;

import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 19/08/15.
 */
public class Set3Challenge18 {

    private final static CryptoBuffer string =
            CryptoBuffer.fromBase64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");

    private final static CryptoBuffer key = new CryptoBuffer("YELLOW SUBMARINE");

    @Test
    public void decryptCtr() throws Exception {
        CryptoBuffer nonce = new CryptoBuffer(new byte[8]);

        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        aes.init(Cipher.ENCRYPT_MODE, skey);

        CryptoBuffer plaintext = Modes.ctr(aes, nonce, string);
        assertEquals("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", plaintext.toString());
    }

    @Test
    public void encryptDecryptCtr() throws Exception {
        CryptoBuffer nonce = Utils.randomKey(8);

        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        aes.init(Cipher.ENCRYPT_MODE, skey);

        CryptoBuffer plaintext = new CryptoBuffer("This is at least a couple of blocks, right?");
        CryptoBuffer ciphertext = Modes.ctr(aes, nonce, plaintext);
        CryptoBuffer plaintext2 = Modes.ctr(aes, nonce, ciphertext);

        assertEquals(plaintext, plaintext2);
    }
}
