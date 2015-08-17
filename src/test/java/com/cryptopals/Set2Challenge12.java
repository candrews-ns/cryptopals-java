package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 14/08/15.
 */
public class Set2Challenge12 {

    private final static CryptoBuffer key = Utils.randomKey(16);

    private final static CryptoBuffer target = new CryptoBuffer(
            Encoding.decodeBase64(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                "YnkK"
    ));

    @Test
    public void ecbDecryption() throws Exception {

        int blocksize = Attacks.findBlocksize(
                (CryptoBuffer text) -> this.encryptWithRandomKey(text)
        );
        assertEquals(16, blocksize);

        CryptoBuffer plaintext = Attacks.breakEcb(
                blocksize,
                (CryptoBuffer text) -> this.encryptWithRandomKey(text)
        );
        Pattern p = Pattern.compile("No, I just drove by");
        Matcher m = p.matcher(plaintext.toString());
        assert(m.find());
    }

    private CryptoBuffer encryptWithRandomKey(CryptoBuffer plaintext) {
        plaintext.append(target);

        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        try {
            aes.init(Cipher.ENCRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) { }

        CryptoBuffer ciphertext = new CryptoBuffer();
        try {
            ciphertext = Modes.ecb(aes, plaintext);
        } catch (BadPaddingException | IllegalBlockSizeException ignored) { }

        return ciphertext;
    }
}
