package com.cryptopals;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by candrews on 14/06/15.
 */
public class Set2Challenge10 {

    @Test
    public void cbcEncryptDecrypt() throws Exception {
        CryptoBuffer plaintext = new CryptoBuffer("Some stuff that's really quite a lot longer than 16 bytes.");
        CryptoBuffer key = new CryptoBuffer("YELLOW SUBMARINE");
        CryptoBuffer iv = Utils.randomKey(16);

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKey skey = key.asSecretKey("AES");
        aes.init(Cipher.ENCRYPT_MODE, skey);

        CryptoBuffer ciphertext = Modes.cbcEncrypt(aes, iv, plaintext);

        aes = Cipher.getInstance("AES/ECB/NoPadding");
        skey = key.asSecretKey("AES");
        aes.init(Cipher.DECRYPT_MODE, skey);

        CryptoBuffer plaintext2 = Modes.cbcDecrypt(aes, iv, ciphertext);
        assertEquals(plaintext.toString(), plaintext2.toString());
    }

    @Test
    public void cbcDecrypt() throws Exception {
        CryptoBuffer ciphertext = CryptoBuffer.fromBase64(Utils.readFromClasspath("set2challenge10.txt"));
        CryptoBuffer key = new CryptoBuffer("YELLOW SUBMARINE");
        CryptoBuffer iv = new CryptoBuffer(new byte[16]);

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKey skey = key.asSecretKey("AES");
        aes.init(Cipher.DECRYPT_MODE, skey);

        CryptoBuffer plaintext = Modes.cbcDecrypt(aes, iv, ciphertext);

        Pattern p = Pattern.compile("I'm back and I'm ringin' the bell");
        Matcher m = p.matcher(plaintext.toString());
        assert(m.find());
    }
}
