package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.util.HashMap;

/**
 * Created by candrews on 26/08/15.
 */
public class Set4Challenge26 {

    CryptoBuffer key = Utils.randomKey(16);
    CryptoBuffer nonce = new CryptoBuffer(Utils.stringOfLength('\0', 8));

    @Test
    public void ctrBitFlipping() throws Exception {
        CryptoBuffer cookie = createCookie(":admin<true");
        cookie.flipBit(16, 2, 0, 0);
        cookie.flipBit(16, 2, 6, 0);
        assert(checkCookie(cookie));
    }

    private CryptoBuffer createCookie(String userdata) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        String prefix = "comment1=cooking%20MCs;userdata=";
        String suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
        userdata = userdata.replaceAll("(;|=)", "");

        CryptoBuffer plaintext = new CryptoBuffer(prefix + userdata + suffix);
        CryptoBuffer cookie = Utils.aesCtrEncryptWithKey(key, nonce, plaintext);
        return cookie;
    }

    private boolean checkCookie(CryptoBuffer cookie) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        CryptoBuffer plaintext = Utils.aesCtrEncryptWithKey(key, nonce, cookie);
        HashMap<String, String> values = Utils.parseCookieString(plaintext.toString());
        return values.containsKey("admin") && values.get("admin").equals("true");
    }
}
