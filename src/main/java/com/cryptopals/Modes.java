package com.cryptopals;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by candrews on 14/06/15.
 */
public class Modes {

    public static CryptoBuffer cbcEncrypt(Cipher cipher, CryptoBuffer plaintext, CryptoBuffer iv) throws BadPaddingException, IllegalBlockSizeException {
        CryptoBuffer ciphertext = new CryptoBuffer();
        CryptoBuffer state = iv.clone();
        for (CryptoBuffer block : plaintext.chunked(iv.length())) {
            state = new CryptoBuffer(cipher.doFinal(state.xorWith(block.pkcs7padTo(16)).toRawBytes()));
            ciphertext.append(state);
        }
        return ciphertext;
    }

    public static CryptoBuffer cbcDecrypt(Cipher cipher, CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException, IllegalBlockSizeException {
        CryptoBuffer plaintext = new CryptoBuffer();
        CryptoBuffer state = iv.clone();
        for (CryptoBuffer block : ciphertext.chunked(iv.length())) {
            plaintext.append(state.xorWith(new CryptoBuffer(cipher.doFinal(block.toRawBytes()))));
            state = block;
        }
        return plaintext.pkcs7unPad(16);
    }
}
