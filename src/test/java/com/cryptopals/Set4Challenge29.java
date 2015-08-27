package com.cryptopals;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Random;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 27/08/15.
 */
public class Set4Challenge29 {

    @Test
    public void testSha1() {
        CryptoBuffer message = new CryptoBuffer("Chunky Bacon");
        CryptoBuffer sha1 = SHA1.encode(message);
        assertEquals("51adbd48c02df2fe86a8563bd81d9f019e755286", sha1.toHex());
    }

    @Test
    public void lengthExtension() throws Exception {
        Random r = new Random();
        CryptoBuffer key = Utils.randomKey(r.nextInt(5) + 5);

        CryptoBuffer message = new CryptoBuffer("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
        CryptoBuffer admin = new CryptoBuffer(";admin=true");

        CryptoBuffer mac = message.macSha1(key);
        int[] regs = extractRegisters(mac);

        int foundKeyLen = 0;
        for (int keyLen = 5; keyLen <= 10; keyLen++) {
            CryptoBuffer glue = mdPadding(new CryptoBuffer(Utils.stringOfLength('A', keyLen)).append(message));
            long bitLen = (keyLen + message.length() + glue.length()) * 8;

            CryptoBuffer forged = SHA1.encode(admin, regs, bitLen);
            CryptoBuffer verified = message.clone().append(glue).append(admin).macSha1(key);

            if (forged.toString().equals(verified.toString())) {
                foundKeyLen = keyLen;
                break;
            }
        }
        assert(foundKeyLen != 0);
    }

    private CryptoBuffer mdPadding (CryptoBuffer message) {
        long bitLen = message.length() * 8;

        ArrayList<CryptoBuffer> blocks = message.chunked(64);
        CryptoBuffer last = blocks.get(blocks.size() - 1);
        int len = last.length();

        CryptoBuffer padding = new CryptoBuffer("");
        if (len > 55) {
            padding.append(new CryptoBuffer("\u0080"));
            padding.append(new CryptoBuffer(Utils.stringOfLength('\0', (63 - len))));
            len = 0;
        }

        padding.append(new CryptoBuffer((byte)((padding.length() > 0) ? 0 : 0x80)));
        padding.append(new CryptoBuffer(Utils.stringOfLength('\0', (55 - len))));
        padding.append(longBuffer(bitLen));

        return padding;
    }

    private CryptoBuffer longBuffer(long val) {
        return new CryptoBuffer(ByteBuffer.allocate(Long.SIZE / 8).putLong(val).array());
    }

    private int[] extractRegisters(CryptoBuffer hash) {
        int[] regs = new int[5];
        ArrayList<CryptoBuffer> ints = hash.chunked(4);
        for (int i = 0; i < 5; i++) {
            ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES);
            regs[i] = buf.put(ints.get(i).toRawBytes()).getInt(0);
        }
        return regs;
    }
}
