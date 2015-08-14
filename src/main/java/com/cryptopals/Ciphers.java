package com.cryptopals;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by candrews on 14/08/15.
 */
public class Ciphers {

    public static Cipher aesCipher() {
        Cipher aes = null;
        try {
            aes = Cipher.getInstance("AES/ECB/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ignored) { }
        return aes;
    }
}
