package com.cryptopals;

/**
 * Created by candrews on 04/06/15.
 */
public class XorCipher {

    public static CryptoBuffer xorCharacter(CryptoBuffer buffer, Character c) {
        byte[] chars = new byte[buffer.length()];
        for (int i = 0; i < buffer.length(); i++)
            chars[i] = ((byte) c.charValue());
        return buffer.xorWith(new CryptoBuffer(chars));
    }

    public static CryptoBuffer xorString(CryptoBuffer buffer, String str) {
        int repeats = (int)Math.ceil(buffer.length() / (double)str.length());
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < repeats; i++)
            s.append(str);
        return buffer.xorWith(new CryptoBuffer(s.toString()));
    }
}
