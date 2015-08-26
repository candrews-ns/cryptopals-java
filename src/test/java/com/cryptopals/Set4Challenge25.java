package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by candrews on 26/08/15.
 */
public class Set4Challenge25 {

    CryptoBuffer key = Utils.randomKey(16);
    CryptoBuffer nonce = new CryptoBuffer(Utils.stringOfLength('\0', 8));

    @Test
    public void breakRWCtr() throws Exception {
        CryptoBuffer ciphertext = encryptedData();

        int half = ciphertext.length() / 2;
        CryptoBuffer mask = new CryptoBuffer(Utils.stringOfLength('\0', half));
        CryptoBuffer c1 = apiEdit(ciphertext, 0, mask);
        CryptoBuffer c2 = apiEdit(ciphertext, half, mask);
        CryptoBuffer plaintext = c1.xorWith(c2);

        Pattern p = Pattern.compile("I'm back and I'm ringin' the bell");
        Matcher m = p.matcher(plaintext.toString());
        assert(m.find());
    }

    private CryptoBuffer apiEdit(CryptoBuffer ciphertext, int offset, CryptoBuffer newtext) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return edit(ciphertext, key, offset, newtext);
    }

    private CryptoBuffer edit(CryptoBuffer ciphertext, CryptoBuffer key, int offset, CryptoBuffer newtext) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        try {
            aes.init(Cipher.ENCRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) {
        }

        CryptoBuffer plaintext = Modes.ctr(aes, nonce, ciphertext);
        plaintext = plaintext.replaceSubstr(offset, newtext.length(), newtext);
        ciphertext = Modes.ctr(aes, nonce, plaintext);
        return ciphertext;
    }

    private CryptoBuffer encryptedData() throws Exception {
        CryptoBuffer plaintext = new CryptoBuffer(
                Utils.readFromClasspath("set4challenge25.txt")
        );
        return Utils.aesCtrEncryptWithKey(key, nonce, plaintext);
    }
}
