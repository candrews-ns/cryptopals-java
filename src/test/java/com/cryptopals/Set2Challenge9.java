package com.cryptopals;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 13/06/15.
 */
public class Set2Challenge9 {

    @Test
    public void testPKCS7() {
        CryptoBuffer message = new CryptoBuffer("YELLOW SUBMARINE");
        CryptoBuffer padded = message.pkcs7padTo(20);
        assertEquals("YELLOW SUBMARINE\u0004\u0004\u0004\u0004", padded.toString());
    }
}
