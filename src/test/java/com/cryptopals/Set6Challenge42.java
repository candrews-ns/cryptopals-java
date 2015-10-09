package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;

public class Set6Challenge42 {

    @Test
    public void testRSASig() {
        RSA.KeyPair k = RSA.generateKeyPair(1024, 3);
        String message = "hi mom";
        CryptoBuffer sig = createSignature(k, message);
        assert(verifySignature(k, message, sig));
    }

    @Test
    public void testBadRSASig() {
        RSA.KeyPair k1 = RSA.generateKeyPair(1024, 3);
        RSA.KeyPair k2 = RSA.generateKeyPair(1024, 3);
        String message = "hi mom";
        CryptoBuffer sig = createSignature(k1, message);
        assert(!verifySignature(k2, message, sig));
    }

    @Test
    public void bleichenbacher() {
        RSA.KeyPair k = RSA.generateKeyPair(1024, 3);
        String message = "hi mom";
        CryptoBuffer sig = forgeSignature(message);
        assert(verifySignature(k, message, sig));
    }

    private CryptoBuffer forgeSignature(String m) {
        CryptoBuffer message = new CryptoBuffer(m);
        CryptoBuffer digest = message.sha256();

        byte[] padding = { 0x00, 0x01, (byte)0xff, 0x00 };
        CryptoBuffer input = new CryptoBuffer(padding);
        input.append(digest);
        input.append(Utils.bufferOfLength((byte)0x00, (128 - input.length())));

        BigInteger c = new BigInteger(input.toHex(), 16);
        return new CryptoBuffer(Utils.cubeRoot(c).add(BigInteger.ONE).toByteArray());
    }

    private CryptoBuffer createSignature(RSA.KeyPair k, String m) {
        CryptoBuffer message = new CryptoBuffer(m);
        CryptoBuffer digest = message.sha256();

        int padlen = 128 - digest.length();
        byte[] padding = new byte[padlen];
        padding[1] = 0x01;
        Arrays.fill(padding, 2, padlen - 1, (byte)0xff);

        CryptoBuffer input = new CryptoBuffer(padding);
        input.append(digest);

        return RSA.decrypt(k, input);
    }

    private boolean verifySignature(RSA.KeyPair k, String m, CryptoBuffer sig) {
        CryptoBuffer message = new CryptoBuffer(m);
        CryptoBuffer digest = message.sha256();

        CryptoBuffer verifier = RSA.encrypt(k, sig);
        byte[] input = verifier.toRawBytes();

        // BAD CODE - fails to correctly check the length of the padding
        if (input[0] != 0x01)
            return false;
        int pos = 0;
        for (int i = 1; i < sig.length(); i++) {
            if (input[i] == (byte)0xff) {
                continue;
            }
            else if (input[i] == (byte)0x00) {
                pos = i + 1;
                break;
            }
            else {
                return false;
            }
        }
        if (pos == 0)
            return false;

        CryptoBuffer sigDigest = new CryptoBuffer(Arrays.copyOfRange(input, pos, pos + digest.length()));
        return digest.equals(sigDigest);
    }
}
