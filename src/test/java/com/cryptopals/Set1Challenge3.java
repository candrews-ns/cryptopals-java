package com.cryptopals;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 05/06/15.
 */
public class Set1Challenge3 {

    @Test
    public void decryptXorCipher() throws Exception {

        CryptoBuffer ciphertext = CryptoBuffer.fromHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

        char key = XorCipher.findXorKey(ciphertext);

        assertEquals('X', key);
        assertEquals("Cooking MC's like a pound of bacon", XorCipher.xorCharacter(ciphertext, key).toString());
    }
}
