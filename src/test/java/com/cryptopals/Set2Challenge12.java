package com.cryptopals;

import com.cryptopals.attacks.ecb.Decrypt;
import org.junit.Test;

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
        Decrypt.Oracle oracle = (CryptoBuffer text) -> this.encryptWithRandomKey(text);

        int blocksize = Decrypt.findBlocksize(oracle);
        assertEquals(16, blocksize);

        boolean isEcb = Decrypt.findEcb(blocksize, oracle);
        assert(isEcb);

        CryptoBuffer plaintext = Decrypt.breakEcb(blocksize, oracle);
        Pattern p = Pattern.compile("No, I just drove by");
        Matcher m = p.matcher(plaintext.toString());
        assert(m.find());
    }

    private CryptoBuffer encryptWithRandomKey(CryptoBuffer plaintext) {
        plaintext.append(target);
        return Utils.aesEcbEncryptWithKey(key, plaintext);
    }
}
