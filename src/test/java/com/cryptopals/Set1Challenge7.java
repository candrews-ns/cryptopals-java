package com.cryptopals;

import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by candrews on 13/06/15.
 */
public class Set1Challenge7 {

    @Test
    public void decryptAes() throws Exception {
        CryptoBuffer ciphertext = CryptoBuffer.fromBase64(Utils.readFromClasspath("set1challenge7.txt"));
        CryptoBuffer key = new CryptoBuffer("YELLOW SUBMARINE");

        Cipher aes = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKey skey = key.asSecretKey("AES");
        aes.init(Cipher.DECRYPT_MODE, skey);

        CryptoBuffer plaintext = Modes.ecb(aes, ciphertext);

        Pattern p = Pattern.compile("I'm back and I'm ringin' the bell");
        Matcher m = p.matcher(plaintext.toString());
        assert(m.find());
    }
}
