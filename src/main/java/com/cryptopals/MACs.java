package com.cryptopals;

/**
 * Created by candrews on 26/08/15.
 */
public class MACs {

    interface Digester {
        CryptoBuffer digest(CryptoBuffer message);
    }

    public static CryptoBuffer keyedMac(Digester digester, CryptoBuffer key, CryptoBuffer text) {
        return digester.digest(key.clone().append(text));
    }

    public static boolean authKeyedMac(Digester digester, CryptoBuffer key, CryptoBuffer text, CryptoBuffer mac) {
        CryptoBuffer myMac = digester.digest(key.clone().append(text));
        return myMac.toString().equals(mac.toString());
    }

    public static CryptoBuffer keyedSha1Mac(CryptoBuffer key, CryptoBuffer text) {
        return keyedMac(
                (CryptoBuffer message) -> message.sha1(),
                key,
                text
        );
    }

    public static boolean authKeyedSha1Mac(CryptoBuffer key, CryptoBuffer text, CryptoBuffer mac) {
        CryptoBuffer myMac = keyedSha1Mac(key, text);
        return myMac.toString().equals(mac.toString());
    }

    public static CryptoBuffer keyedMd4Mac(CryptoBuffer key, CryptoBuffer text) {
        return keyedMac(
                (CryptoBuffer message) -> message.md4(),
                key,
                text
        );
    }

    public static boolean authKeyedMd4Mac(CryptoBuffer key, CryptoBuffer text, CryptoBuffer mac) {
        CryptoBuffer myMac = keyedMd4Mac(key, text);
        return myMac.toString().equals(mac.toString());
    }
}
