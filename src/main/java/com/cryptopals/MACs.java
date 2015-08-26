package com.cryptopals;

/**
 * Created by candrews on 26/08/15.
 */
public class MACs {

    public static CryptoBuffer keyedMac(CryptoBuffer key, CryptoBuffer text) {
        return new CryptoBuffer(SHA1.encode(key.clone().append(text).toString(), true));
    }

    public static boolean authKeyedMac(CryptoBuffer key, CryptoBuffer text, CryptoBuffer mac) {
        CryptoBuffer myMac = new CryptoBuffer(SHA1.encode(key.clone().append(text).toString(), true));
        return myMac.toString().equals(mac.toString());
    }
}
