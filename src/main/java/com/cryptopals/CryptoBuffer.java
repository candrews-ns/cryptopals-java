package com.cryptopals;

import org.apache.commons.codec.DecoderException;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Created by candrews on 09/06/15.
 */
public class CryptoBuffer {

    private byte[] buf;

    public CryptoBuffer(byte[] buf) {
        this.buf = buf;
    }

    public CryptoBuffer(byte b) {
        byte[] buf = new byte[1];
        buf[0] = b;
        this.buf = buf;
    }

    public CryptoBuffer(char c) {
        byte[] buf = new byte[1];
        buf[0] = (byte)c;
        this.buf = buf;
    }

    public CryptoBuffer() {
        this.buf = new byte[0];
    }

    public CryptoBuffer(String s) {
        this.buf = s.getBytes();
    }

    public CryptoBuffer(ArrayList<CryptoBuffer> chunks) {
        CryptoBuffer first = null;
        for (CryptoBuffer chunk : chunks) {
            if (first == null) {
                first = chunk;
            } else {
                first.append(chunk);
            }
        }
        this.buf = first.toRawBytes();
    }

    public int length() {
        return this.buf.length;
    }

    public CryptoBuffer clone() {
        return new CryptoBuffer(this.buf.clone());
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

    public byte[] toRawBytes() {
        return this.buf;
    }

    public CryptoBuffer append(CryptoBuffer newChunk) {
        int len = this.buf.length + newChunk.buf.length;
        byte[] newBuf = new byte[len];
        for (int i = 0; i < len; i++)
            newBuf[i] = (i < this.buf.length) ? this.buf[i] : newChunk.buf[i - this.buf.length];
        this.buf = newBuf;
        return this;
    }

    public CryptoBuffer xorWith(CryptoBuffer other) {
        int len = this.buf.length;
        if (len > other.buf.length) {
            len = other.buf.length;
        }
        byte[] output = new byte[len];
        int i = 0;
        for (byte b : this.buf) {
            if (i < len) {
                output[i] = (byte) (b ^ other.buf[i++]);
            }
        }
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
        int start;
        int end;
        if (offset < 0) {
            // perl-style "negative start means backwards from end"
            start = this.buf.length - Math.abs(offset);
            end = start + length;
        }
        else {
            start = offset;
            end = offset + length;
        }
        if (end > this.buf.length) {
            end = this.buf.length;
        }
        return new CryptoBuffer(Arrays.copyOfRange(this.buf, start, end));
    }

    public CryptoBuffer replaceSubstr(int offset, int length, CryptoBuffer newtext) {
        CryptoBuffer out = this.substr(0, offset);
        out.append(newtext);
        out.append(this.substr((offset + length), (this.length() - (offset + length))));
        return out;
    }

    public CryptoBuffer chop() {
        return this.substr(0, (this.length() - 1));
    }

    public CryptoBuffer nullPaddedSubstr(int start, int length) {
        return new CryptoBuffer(Arrays.copyOfRange(this.buf, start, start + length));
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

    public SecretKey asSecretKey (String kind) {
        return new SecretKeySpec(this.buf, 0, this.buf.length, kind);
    }

    public CryptoBuffer pkcs7padTo(int padLength) {
        ArrayList<CryptoBuffer> chunks = this.chunked(padLength);
        CryptoBuffer chunk = chunks.get(chunks.size() - 1);

        int bufLength = chunk.buf.length;
        int pad = padLength - bufLength;
        byte[] padded = new byte[padLength];
        for (int i = 0; i < padLength; i++) {
            if (i < bufLength)
                padded[i] = chunk.buf[i];
            else
                padded[i] = (byte)pad;
        }
        chunk.buf = padded;
        return new CryptoBuffer(chunks);
    }

    public CryptoBuffer pkcs7unPad(int padLength) throws BadPaddingException {
        ArrayList<CryptoBuffer> chunks = this.chunked(padLength);
        CryptoBuffer chunk = chunks.get(chunks.size() - 1);

        int last = padLength - 1;
        int pad = (int)chunk.buf[last];
        if (pad == 0) {
            throw new BadPaddingException();
        }
        for (int pos = last; pos > (last - pad); pos--) {
            if (chunk.buf[pos] != chunk.buf[last]) {
                throw new BadPaddingException();
            }
        }
        this.buf = Arrays.copyOfRange(this.buf, 0, (this.buf.length - pad));
        return this;
    }

    public void flipBit(int blocksize, int block, int byte_offset, int bit_offset) {
        int mask = 0x01 << bit_offset;
        this.buf[(blocksize * block) + byte_offset] ^= mask;
    }

    public void xorByte(int blocksize, int block, int offset, byte b) {
        this.buf[(blocksize * block) + offset] ^= b;
    }

    public CryptoBuffer sha1() {
        return SHA1.encode(this);
    }

    public CryptoBuffer macSha1(CryptoBuffer key) {
        return MACs.keyedSha1Mac(key, this);
    }

    public CryptoBuffer md4() {
        return MD4.encode(this);
    }

    public CryptoBuffer macMd4(CryptoBuffer key) {
        return MACs.keyedMd4Mac(key, this);
    }

    public CryptoBuffer sha256() {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException ignored) { }
        if (md == null) {
            return new CryptoBuffer("");
        }
        return new CryptoBuffer(md.digest(this.buf));
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof CryptoBuffer)) {
            return false;
        }
        CryptoBuffer other = (CryptoBuffer)obj;

        return this.toString().equals(other.toString());
    }

    public int hashCode() {
        return Arrays.hashCode(buf);
    }
}
