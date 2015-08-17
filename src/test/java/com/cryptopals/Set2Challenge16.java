package com.cryptopals;

import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by candrews on 17/08/15.
 */
public class Set2Challenge16 {

    private final static CryptoBuffer key = Utils.randomKey(16);
    private final static CryptoBuffer iv = Utils.randomKey(16); //new CryptoBuffer(new byte[16]);

    @Test
    public void bitFlip() {
        String userdata = ":admin<true";
        CryptoBuffer cookie = createCookie(userdata);

        cookie.flipBit(16, 1, 0, 0);
        cookie.flipBit(16, 1, 6, 0);

        assert(checkCookie(cookie));
    }

    private CryptoBuffer createCookie(String userdata) {
        String prefix = "comment1=cooking%20MCs;userdata=";
        String suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
        userdata = userdata.replaceAll("(;|=)", "");

        CryptoBuffer plaintext = new CryptoBuffer(prefix + userdata + suffix);
        CryptoBuffer cookie = Utils.aesCbcEncryptWithKey(key, plaintext, iv);
        return cookie;
    }

    private boolean checkCookie(CryptoBuffer cookie) {
        CryptoBuffer plaintext = Utils.aesCbcDecryptWithKey(key, cookie, iv);
        HashMap<String, String> values = parseCookieString(plaintext.toString());
        return values.containsKey("admin") && values.get("admin").equals("true");
    }

    private HashMap<String, String> parseCookieString(String cookie) {
        HashMap<String, String> c = new HashMap<>();
        String[] chunks = cookie.split(";");
        for (String chunk : chunks) {
            String[] kv = chunk.split("=");
            if (kv.length == 2) {
                c.put(kv[0], kv[1]);
            }
        }

        return c;
    }
}
