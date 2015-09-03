package com.cryptopals;

import java.math.BigInteger;
import java.util.Random;

/**
 * Created by candrews on 03/09/15.
 */
public class DH {

    public static BigInteger generatePrivateKey(int bits, Random r) {
        return new BigInteger(bits, r);
    }

    public static BigInteger derivePublicKey(BigInteger p, BigInteger g, BigInteger privateKey) {
        return g.modPow(privateKey, p);
    }

    public static BigInteger deriveSessionKey(BigInteger p, BigInteger privateKey, BigInteger publicKey) {
        return publicKey.modPow(privateKey, p);
    }

    public static CryptoBuffer deriveAESKey(BigInteger dhKey, int bytes) {
        return new CryptoBuffer(dhKey.toByteArray()).sha1().substr(0, bytes);
    }

    public static class Params {
        public final BigInteger p;
        public final BigInteger g;

        public Params() {
            this.p = new BigInteger(
                    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                            "fffffffffffff",
                    16
            );
            this.g = new BigInteger("2");
        }
    }

}
