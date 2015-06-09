package com.cryptopals;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Created by candrews on 09/06/15.
 */
public class Set1Challenge5 {

    @Test
    public void repeatingKeyXor() {

        CryptoBuffer plaintext = new CryptoBuffer("Burning 'em, if you ain't quick and nimble\n" +
                                                  "I go crazy when I hear a cymbal");
        String key = "ICE";

        CryptoBuffer ciphertext = XorCipher.xorString(plaintext, key);

        assertEquals(
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
                "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
                ciphertext.toHex()
        );
    }
}
