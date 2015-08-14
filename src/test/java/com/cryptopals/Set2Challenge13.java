package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 14/08/15.
 */
public class Set2Challenge13 {

    private final static CryptoBuffer key = Utils.randomKey(16);

    @Test
    public void getAdminCookie() {
        CryptoBuffer adminBlock = encryptedProfileFor("xxxxxxxxxxadmin").substr(16, 16);
        CryptoBuffer cookie = encryptedProfileFor("xyzzy@bar.com").substr(0, 32);
        cookie.append(adminBlock);

        HashMap<String, String> c = parseEncryptedCookieString(cookie);
        assertEquals("admin", c.get("role"));
    }

    @Test
    public void testParseCookie() {
        HashMap<String, String> c = parseCookieString("foo=bar&baz=qux&zap=zazzle");
        assertEquals("bar", c.get("foo"));
        assertEquals("qux", c.get("baz"));
        assertEquals("zazzle", c.get("zap"));
        assertEquals(3, c.size());
    }

    @Test
    public void testProfileFor() {
        assertEquals("email=foo@bar.com&uid=10&role=user", profileFor("foo@bar.com").toString());
        assertEquals("email=foo@bar.comroleadmin&uid=10&role=user", profileFor("foo@bar.com&role=admin").toString());
    }

    private CryptoBuffer profileFor(String email) {
        email = email.replaceAll("(&|=)", "");
        return new CryptoBuffer("email=" + email + "&uid=10&role=user");
    }

    private CryptoBuffer encryptedProfileFor(String email) {
        return encrypt(profileFor(email));
    }

    private HashMap<String, String> parseCookieString(String cookie) {
        HashMap<String, String> c = new HashMap<>();
        String[] chunks = cookie.split("&");
        for (String chunk : chunks) {
            String[] kv = chunk.split("=");
            if (kv.length == 2) {
                c.put(kv[0], kv[1]);
            }
        }

        return c;
    }

    private HashMap<String, String> parseEncryptedCookieString(CryptoBuffer cookie) {
        CryptoBuffer plaintext = decrypt(cookie);
        return parseCookieString(plaintext.toString());
    }

    private CryptoBuffer encrypt(CryptoBuffer plaintext) {
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

    private CryptoBuffer decrypt(CryptoBuffer ciphertext) {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        try {
            aes.init(Cipher.DECRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) { }

        CryptoBuffer plaintext = new CryptoBuffer();
        try {
            plaintext = Modes.ecb(aes, ciphertext);
        } catch (BadPaddingException | IllegalBlockSizeException ignored) { }

        return plaintext;
    }
}
