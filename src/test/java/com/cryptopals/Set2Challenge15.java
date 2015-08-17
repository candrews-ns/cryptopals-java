package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;

/**
 * Created by candrews on 17/08/15.
 */
public class Set2Challenge15 {

    @Test
    public void testUnpadding() throws Exception {
        CryptoBuffer valid = new CryptoBuffer("ICE ICE BABY\u0004\u0004\u0004\u0004");
        CryptoBuffer invalid1 = new CryptoBuffer("ICE ICE BABY\u0005\u0005\u0005\u0005");
        CryptoBuffer invalid2 = new CryptoBuffer("ICE ICE BABY\u0001\u0002\u0003\u0004");

        valid.pkcs7unPad(16);
        assert(invalidPaddingException(invalid1));
        assert(invalidPaddingException(invalid2));
    }

    private boolean invalidPaddingException(CryptoBuffer buf) {
        boolean thrown = false;
        try {
            buf.pkcs7unPad(16);
        }
        catch (BadPaddingException e) {
            thrown = true;
        }
        return thrown;
    }

}
