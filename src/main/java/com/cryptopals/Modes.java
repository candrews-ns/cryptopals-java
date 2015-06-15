package com.cryptopals;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by candrews on 14/06/15.
 */
public class Modes {

    public static CryptoBuffer cbcEncrypt(Cipher cipher, CryptoBuffer plaintext, CryptoBuffer iv) {
        CryptoBuffer ciphertext = new CryptoBuffer();
        return ciphertext;
    }

    public static CryptoBuffer cbcDecrypt(Cipher cipher, CryptoBuffer ciphertext, CryptoBuffer iv) throws IllegalBlockSizeException, BadPaddingException {
        CryptoBuffer plaintext = new CryptoBuffer();
        CryptoBuffer state = iv.clone();
        for (CryptoBuffer block : ciphertext.chunked(iv.length())) {
            plaintext.append(state.xorWith(new CryptoBuffer(cipher.doFinal(block.toRawBytes()))));
            state = block;
        }
        return plaintext;
    }
}
