package com.cryptopals;

import org.apache.commons.codec.DecoderException;

import java.util.*;

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

    public int hammingDistance(CryptoBuffer other) {
        CryptoBuffer xored = xorWith(other);
        int dist = 0;
        for (byte a : xored.buf)
            dist += Integer.bitCount(a);
        return dist;
    }

    public CryptoBuffer substr(int offset, int length) {
        return new CryptoBuffer(Arrays.copyOfRange(this.buf, offset, offset + length));
    }

    public ArrayList<CryptoBuffer> chunked(int size) {
        ArrayList<CryptoBuffer> chunks = new ArrayList<>();
        for (int offset = 0; offset < this.buf.length; offset += size)
            chunks.add(this.substr(offset, size));
        return chunks;
    }

    public ArrayList<CryptoBuffer> transpose(int size) {
        ArrayList<CryptoBuffer> chunks = this.chunked(size);
        ArrayList<CryptoBuffer> blocks = new ArrayList<>();

        int count = this.buf.length / size;

        for (int i = 0; i < size; i++) {
            byte[] block = new byte[count];
            for (int j = 0; j < count; j++) {
                block[j] = chunks.get(j).buf[i];
            }
            blocks.add(new CryptoBuffer(block));
        }

        return blocks;
    }
}
