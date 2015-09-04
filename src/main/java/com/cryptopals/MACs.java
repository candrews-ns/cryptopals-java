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
        return myMac.equals(mac);
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
        return myMac.equals(mac);
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
        return myMac.equals(mac);
    }

    public static CryptoBuffer hmacSha1(CryptoBuffer key, CryptoBuffer message) {
        int blocksize = 64;

        if (key.length() > blocksize) {
            key = SHA1.encode(key); // keys longer than blocksize are shortened
        }
        if (key.length() < blocksize) {
            key.append(new CryptoBuffer(Utils.stringOfLength('\0', blocksize - key.length())));
        }

        CryptoBuffer o_key_pad = new CryptoBuffer(Utils.stringOfLength((char) 0x5C, blocksize)).xorWith(key);
        CryptoBuffer i_key_pad = new CryptoBuffer(Utils.stringOfLength((char) 0x36, blocksize)).xorWith(key);

        return SHA1.encode(o_key_pad.append(SHA1.encode((i_key_pad.append(message)))));
    }
}
