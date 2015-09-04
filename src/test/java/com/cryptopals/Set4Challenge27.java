package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Created by candrews on 26/08/15.
 */
public class Set4Challenge27 {

    private CryptoBuffer key_and_iv = Utils.randomKey(16);

    @Test
    public void recoverCBCKey() throws Exception {
        CryptoBuffer plaintext = new CryptoBuffer("This message is sure to be at least three blocks long.");

        CryptoBuffer ciphertext = encrypt(plaintext);
        CryptoBuffer plaintextcheck = decrypt(ciphertext).pkcs7unPad(16);
        assertEquals(plaintext, plaintextcheck);

        ArrayList<CryptoBuffer> chunks = ciphertext.chunked(16);
        CryptoBuffer c1 = chunks.get(0);
        CryptoBuffer modCiphertext = c1
                .append(new CryptoBuffer(Utils.stringOfLength('\0', 16)))
                .append(c1);
        for (int i = 3; i < chunks.size(); i++) {
            modCiphertext.append(chunks.get(i));
        }

        CryptoBuffer plaintext2 = null;
        try {
            decrypt(modCiphertext);
        }
        catch (Exception e) {
            Pattern p = Pattern.compile("^not ASCII: ([0-9a-f]+)$");
            Matcher m = p.matcher(e.getMessage());
            if (m.matches()) {
                String hex = m.group(1);
                plaintext2 = CryptoBuffer.fromHex(hex);
            }
        }

        if (plaintext2 != null) {
            chunks = plaintext2.chunked(16);
            CryptoBuffer p1 = chunks.get(0);
            CryptoBuffer p3 = chunks.get(2);

            CryptoBuffer key = p1.xorWith(p3);
            assertEquals(key_and_iv, key);
        }
        else {
            fail("didn't recover key");
        }
    }

    private CryptoBuffer decrypt(CryptoBuffer ciphertext) throws Exception {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key_and_iv.asSecretKey("AES");
        try {
            aes.init(Cipher.DECRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) {
        }

        CryptoBuffer plaintext = new CryptoBuffer();
        try {
            plaintext = Modes.cbcDecryptWithoutPaddingCheck(aes, key_and_iv, ciphertext);
        } catch (IllegalBlockSizeException|BadPaddingException ignored) {
        }

        // ASCII check
        for (byte b : plaintext.toRawBytes()) {
            if (b < 0)
                throw new Exception("not ASCII: " + plaintext.toHex());
        }

        return plaintext;
    }

    private CryptoBuffer encrypt(CryptoBuffer plaintext) {
        CryptoBuffer ciphertext = Utils.aesCbcEncryptWithKey(key_and_iv, key_and_iv, plaintext);
        return ciphertext;
    }
}
