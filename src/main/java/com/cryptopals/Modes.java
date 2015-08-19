package com.cryptopals;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by candrews on 14/06/15.
 */
public class Modes {

    public static CryptoBuffer ecb(Cipher cipher, CryptoBuffer text) throws BadPaddingException, IllegalBlockSizeException {
        return new CryptoBuffer(cipher.doFinal(text.pkcs7padTo(cipher.getBlockSize()).toRawBytes()));
    }

    public static CryptoBuffer cbcEncrypt(Cipher cipher, CryptoBuffer iv, CryptoBuffer plaintext) throws BadPaddingException, IllegalBlockSizeException {
        CryptoBuffer ciphertext = new CryptoBuffer();
        CryptoBuffer state = iv.clone();
        for (CryptoBuffer block : plaintext.chunked(iv.length())) {
            state = new CryptoBuffer(cipher.doFinal(state.xorWith(block.pkcs7padTo(cipher.getBlockSize())).toRawBytes()));
            ciphertext.append(state);
        }
        return ciphertext;
    }

    public static CryptoBuffer cbcDecrypt(Cipher cipher, CryptoBuffer iv, CryptoBuffer ciphertext) throws BadPaddingException, IllegalBlockSizeException {
        CryptoBuffer plaintext = new CryptoBuffer();
        CryptoBuffer state = iv.clone();
        for (CryptoBuffer block : ciphertext.chunked(iv.length())) {
            plaintext.append(state.xorWith(new CryptoBuffer(cipher.doFinal(block.toRawBytes()))));
            state = block;
        }
        return plaintext.pkcs7unPad(cipher.getBlockSize());
    }
}
