package com.cryptopals.attacks.cbc;

import com.cryptopals.CryptoBuffer;

import javax.crypto.BadPaddingException;
import java.util.ArrayList;

/**
 * Created by candrews on 18/08/15.
 */
public class PaddingOracle {

    public interface Oracle {
        boolean decrypt(CryptoBuffer iv, CryptoBuffer ciphertext);
    }

    public final CryptoBuffer key;
    public final Oracle oracle;

    public PaddingOracle(CryptoBuffer key, Oracle oracle) {
        this.key = key;
        this.oracle = oracle;
    }

    public CryptoBuffer cbcPaddingOracle(CryptoBuffer iv, CryptoBuffer ciphertext) {
        ArrayList<CryptoBuffer> chunks = ciphertext.chunked(16);
        chunks.add(0, iv);

        CryptoBuffer plaintext = new CryptoBuffer();
        for (int i = 0; i < (chunks.size() - 1); i++) {
            plaintext.append(decryptBlock(chunks.get(i), chunks.get(i+1)));
        }

        try {
            plaintext.pkcs7unPad(16);
        }
        catch (BadPaddingException ignore) { }
        return plaintext;
    }

    private CryptoBuffer decryptBlock(CryptoBuffer block1, CryptoBuffer block2) {
        byte[] chars = new byte[16];

        for (int b = 15; b >= 0; b--) {
            // avoid being fooled by the actual padding on the first byte decrypted
            int start = (b == 15) ? 1 : 0;
            for (int i = start; i < 256; i++) {
                CryptoBuffer edit = block1.clone();

                for (int offset = 15; offset >= b; offset--) {
                    if (offset > b) {
                        int padchar = chars[offset] ^ (16 - b);
                        edit.xorByte(16, 0, offset, (byte)padchar);
                    }
                    else {
                        edit.xorByte(16, 0, offset, (byte)i);
                    }
                }

                if (oracle.decrypt(edit, block2)) {
                    chars[b] = (byte)(i ^ (16 - b));
                    break;
                }
            }
            if (chars[b] == 0) {
                chars[b] = ' ';
            }
        }

        return new CryptoBuffer(chars);
    }
}
