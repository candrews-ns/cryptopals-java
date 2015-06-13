package com.cryptopals;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class Set1Challenge2 {

    @Test
    public void testXor() throws Exception {
        String left  = "1c0111001f010100061a024b53535009181c";
        String right = "686974207468652062756c6c277320657965";

        CryptoBuffer output = CryptoBuffer.fromHex(left).xorWith(CryptoBuffer.fromHex(right));
        assertEquals("746865206b696420646f6e277420706c6179", output.toHex());
    }

}
