package com.cryptopals;

/**
 * Created by candrews on 04/06/15.
 */
public class XorCipher {

    public static byte[] xorBuffers(byte[] left, byte[] right) {
        byte[] output = new byte[left.length];
        int i = 0;
        for (byte b : left)
            output[i] = (byte) (b ^ right[i++]);
        return output;
    }

    public static byte[] xorCharacter(byte[] buf, Character c) {
        byte[] chars = new byte[buf.length];
        for (int i = 0; i < buf.length; i++)
            chars[i] = ((byte) c.charValue());
        return xorBuffers(buf, chars);
    }
}
