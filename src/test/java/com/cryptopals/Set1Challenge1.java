package com.cryptopals;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class Set1Challenge1 {

    private static final String the_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    private static final String the_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    @Test
    public void testDecodeBase64() {
        String hex = CryptoBuffer.fromBase64(the_base64).toHex();
        assertEquals(hex, the_hex);
    }

    @Test
    public void testEncodeBase64() throws Exception {
        String base64 = CryptoBuffer.fromHex(the_hex).toBase64();
        assertEquals(base64, the_base64);
    }
}
