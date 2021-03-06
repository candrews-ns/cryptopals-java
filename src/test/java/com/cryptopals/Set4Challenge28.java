package com.cryptopals;

import org.junit.Test;

/**
 * Created by candrews on 26/08/15.
 */
public class Set4Challenge28 {

    @Test
    public void macSomeStuff() {
        CryptoBuffer key = Utils.randomKey(16);
        CryptoBuffer text = new CryptoBuffer("this is my message");
        CryptoBuffer mac = text.macSha1(key);

        assert(MACs.authKeyedSha1Mac(key, text, mac));
        assert(!MACs.authKeyedSha1Mac(key, text.append(new CryptoBuffer("yeah")), mac));
    }
}
