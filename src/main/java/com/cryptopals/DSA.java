package com.cryptopals;

import java.math.BigInteger;
import java.util.Random;

public class DSA {
    public BigInteger p, q, g;
    public int N;

    public DSA(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.N = q.bitLength();
    }

    public Keypair keygen() {
        Random rand = new Random();
        BigInteger x = new BigInteger(N, rand);
        BigInteger y = g.modPow(x, p);
        return new Keypair(x ,y);
    }

    public Signature sign(CryptoBuffer m, Keypair keypair) {
        Random rand = new Random();
        BigInteger r, k, s;
        do {
            do {
                k = new BigInteger(N, rand);
                r = g.modPow(k, p).mod(q);
            } while (r.equals(BigInteger.ZERO));
            BigInteger Hm = new BigInteger(m.sha1().toHex(), 16);
            BigInteger kInv = k.modInverse(q);
            s = kInv.multiply(Hm.add(keypair.x.multiply(r))).mod(q);
        } while (s.equals(BigInteger.ZERO));

        return new Signature(r, s);
    }

    public boolean verify(CryptoBuffer m, Keypair keypair, Signature sig) {
        if (sig.r.compareTo(BigInteger.ZERO) == -1 || sig.r.compareTo(q) == 1)
            return false;
        if (sig.s.compareTo(BigInteger.ZERO) == -1 || sig.s.compareTo(q) == 1)
            return false;

        BigInteger w = sig.s.modInverse(q);
        BigInteger Hm = new BigInteger(m.sha1().toHex(), 16);
        BigInteger u1 = Hm.multiply(w).mod(q);
        BigInteger u2 = sig.r.multiply(w).mod(q);
        BigInteger v = g.modPow(u1, p).multiply(keypair.y.modPow(u2, p)).mod(p).mod(q);
        return v.equals(sig.r);
    }

    public static class Keypair {
        public BigInteger x, y;
        public Keypair(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }

    public static class Signature {
        public BigInteger r, s;
        public Signature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }
    }
}
