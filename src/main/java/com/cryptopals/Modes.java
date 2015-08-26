package com.cryptopals;

import com.cryptopals.random.MT19937;
import org.apache.commons.codec.digest.Crypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

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
        for (CryptoBuffer block : plaintext.chunked(cipher.getBlockSize())) {
            state = new CryptoBuffer(cipher.doFinal(state.xorWith(block.pkcs7padTo(cipher.getBlockSize())).toRawBytes()));
            ciphertext.append(state);
        }
        return ciphertext;
    }

    public static CryptoBuffer cbcDecrypt(Cipher cipher, CryptoBuffer iv, CryptoBuffer ciphertext) throws BadPaddingException, IllegalBlockSizeException {
        CryptoBuffer plaintext = cbcDecryptWithoutPaddingCheck(cipher, iv, ciphertext);
        return plaintext.pkcs7unPad(cipher.getBlockSize());
    }

    public static CryptoBuffer cbcDecryptWithoutPaddingCheck(Cipher cipher, CryptoBuffer iv, CryptoBuffer ciphertext) throws BadPaddingException, IllegalBlockSizeException {
        CryptoBuffer plaintext = new CryptoBuffer();
        CryptoBuffer state = iv.clone();
        for (CryptoBuffer block : ciphertext.chunked(cipher.getBlockSize())) {
            plaintext.append(state.xorWith(new CryptoBuffer(cipher.doFinal(block.toRawBytes()))));
            state = block;
        }
        return plaintext;
    }

    private static ByteBuffer buffer = getBuffer();

    private static ByteBuffer getBuffer() {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        return buffer;
    }

    public static CryptoBuffer ctr(Cipher cipher, CryptoBuffer nonce, CryptoBuffer text) throws BadPaddingException, IllegalBlockSizeException {
        CryptoBuffer out = new CryptoBuffer();
        long counter = 0;
        for (CryptoBuffer block : text.chunked(cipher.getBlockSize())) {
            buffer.putLong(0, counter);
            CryptoBuffer ctrbuf = new CryptoBuffer(buffer.array());
            CryptoBuffer keystream = new CryptoBuffer(
                    cipher.doFinal(nonce.clone().append(ctrbuf).toRawBytes())
            );
            out.append(keystream.xorWith(block));
            counter++;
        }
        return out;
    }

    public static CryptoBuffer prngStream(MT19937 prng, CryptoBuffer text) {
        CryptoBuffer out = new CryptoBuffer();
        for (CryptoBuffer block : text.chunked(Integer.SIZE / 8)) {
            int next = prng.nextInteger();
            CryptoBuffer keystream = new CryptoBuffer(
                    ByteBuffer.allocate(Integer.SIZE / 8).putInt(next).array()
            );
            out.append(keystream.xorWith(block));
        }
        return out;
    }
}
