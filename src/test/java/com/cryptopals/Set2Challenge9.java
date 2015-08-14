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

        padded = message.pkcs7padTo(16);
        assertEquals("YELLOW SUBMARINE", padded.toString());

        message = new CryptoBuffer("This is a long message, certainly longer than one block, yeah?");
        padded = message.pkcs7padTo(16);
        assertEquals("This is a long message, certainly longer than one block, yeah?", message.toString());
        assertEquals("This is a long message, certainly longer than one block, yeah?\u0002\u0002", padded.toString());
    }
}
