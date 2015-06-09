package com.cryptopals;

import org.apache.commons.codec.DecoderException;

/**
 * Created by candrews on 09/06/15.
 */
public class CryptoBuffer {

    private byte[] buf;

    public CryptoBuffer(byte[] buf) {
        this.buf = buf;
    }

    public CryptoBuffer(String s) {
        this.buf = s.getBytes();
    }

    public int length() {
        return this.buf.length;
    }

    public static CryptoBuffer fromHex(String hex) throws DecoderException {
        return new CryptoBuffer(Encoding.decodeHex(hex));
    }

    public static CryptoBuffer fromBase64(String base64) {
        return new CryptoBuffer(Encoding.decodeBase64(base64));
    }

    public String toHex() {
        return Encoding.encodeHex(this.buf);
    }

    public String toBase64() {
        return Encoding.encodeBase64(this.buf);
    }

    public String toString() {
        return new String(buf);
    }

    public CryptoBuffer xorWith(CryptoBuffer other) {
        byte[] output = new byte[this.buf.length];
        int i = 0;
        for (byte b : this.buf)
            output[i] = (byte) (b ^ other.buf[i++]);
        return new CryptoBuffer(output);
    }
}
