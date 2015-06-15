package com.cryptopals;

import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by candrews on 14/06/15.
 */
public class Set2Challenge10 {

    @Test
    public void cbcDecrypt() throws Exception {
        CryptoBuffer ciphertext = CryptoBuffer.fromBase64(Utils.readFromClasspath("set2challenge10.txt"));
        CryptoBuffer key = new CryptoBuffer("YELLOW SUBMARINE".getBytes());
        CryptoBuffer iv = new CryptoBuffer(new byte[16]);

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKey skey = key.asSecretKey("AES");
        aes.init(Cipher.DECRYPT_MODE, skey);

        CryptoBuffer plaintext = Modes.cbcDecrypt(aes, ciphertext, iv);
        //System.out.println(plaintext.toString());
    }
}
