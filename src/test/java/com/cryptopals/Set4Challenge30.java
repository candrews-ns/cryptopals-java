package com.cryptopals;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Random;

/**
 * Created by candrews on 27/08/15.
 */
public class Set4Challenge30 {

    @Test
    public void testMD4() {
        CryptoBuffer message = new CryptoBuffer("Chunky Bacon");
        CryptoBuffer md4 = MD4.encode(message);
        assertEquals("f8ef7758e8f4b430fad4798a39c6b005", md4.toHex());
    }

    @Test
    public void lengthExtension() throws Exception {
        Random r = new Random();
        CryptoBuffer key = Utils.randomKey(r.nextInt(5) + 5);

        CryptoBuffer message = new CryptoBuffer("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
        CryptoBuffer admin = new CryptoBuffer(";admin=true");

        CryptoBuffer mac = message.macMd4(key);
        int[] regs = extractRegisters(mac);

        int foundKeyLen = 0;
        for (int keyLen = 5; keyLen <= 10; keyLen++) {
            CryptoBuffer glue = mdPadding(new CryptoBuffer(Utils.stringOfLength('A', keyLen)).append(message));
            long byteLen = (keyLen + message.length() + glue.length());

            CryptoBuffer forged = MD4.encode(admin, regs, byteLen);
            CryptoBuffer verified = message.clone().append(glue).append(admin).macMd4(key);

            System.out.println("keylen: " + keyLen + " forged: " + forged.toHex() + " verified: " + verified.toHex());

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

        padding.append(new CryptoBuffer((byte) ((padding.length() > 0) ? 0 : 0x80)));
        padding.append(new CryptoBuffer(Utils.stringOfLength('\0', (55 - len))));
        ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        padding.append(new CryptoBuffer(buf.putInt(0, (int) (bitLen & 0xffffffff)).array()));
        padding.append(new CryptoBuffer(buf.putInt(0, (int) (bitLen >>> 32)).array()));

        return padding;
    }

    private int[] extractRegisters(CryptoBuffer hash) {
        int[] regs = new int[4];
        ArrayList<CryptoBuffer> ints = hash.chunked(4);
        for (int i = 0; i < 4; i++) {
            ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES);
            buf.order(ByteOrder.LITTLE_ENDIAN);
            regs[i] = buf.put(ints.get(i).toRawBytes()).getInt(0);
        }
        return regs;
    }
}
