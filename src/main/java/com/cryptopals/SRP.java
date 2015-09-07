package com.cryptopals;

import java.math.BigInteger;
import java.util.Random;

public class SRP {
    private final Random r = new Random();
    private final BigInteger N;
    private final BigInteger g;
    private final BigInteger k;

    private CryptoBuffer I;
    private CryptoBuffer P;

    private BigInteger salt, v;

    private final BigInteger privateKey;
    private BigInteger publicKey;

    public SRP() {
        DH.Params params = new DH.Params();
        N = params.p;
        g = params.g;
        k = new BigInteger("3");
        privateKey = new BigInteger(512, r);
    }

    public void setCredentials(String user, String password) {
        this.I = new CryptoBuffer(user);
        this.P = new CryptoBuffer(password);
    }

    // client methods

    public BigInteger clientComputePublicKey() {
        publicKey = g.modPow(privateKey, N);
        return publicKey;
    }

    public CryptoBuffer clientComputeSessionKey(BigInteger serverPublicKey) {
        CryptoBuffer uH = new CryptoBuffer(publicKey.toByteArray()).append(new CryptoBuffer(serverPublicKey.toByteArray())).sha256();
        BigInteger u = new BigInteger(uH.toHex(), 16);
        CryptoBuffer xH = new CryptoBuffer(salt.toByteArray()).append(P).sha256();
        BigInteger x = new BigInteger(xH.toHex(), 16);
        BigInteger S = serverPublicKey.subtract(k.multiply(g.modPow(x, N))).modPow((privateKey.add(u.multiply(x))), N);
        CryptoBuffer K = new CryptoBuffer(S.toByteArray()).sha256();
        return MACs.hmacSha256(K, new CryptoBuffer(salt.toByteArray()));
    }

    // server methods

    public void serverComputeVerifier() {
        salt = new BigInteger(512, r);
        CryptoBuffer xH = new CryptoBuffer(salt.toByteArray()).append(P).sha256();
        BigInteger x = new BigInteger(xH.toHex(), 16);
        v = g.modPow(x, N);
    }

    public BigInteger serverComputePublicKey() {
        publicKey = (k.multiply(v)).add(g.modPow(privateKey, N));
        return publicKey;
    }

    public CryptoBuffer serverComputeSessionKey(BigInteger clientPublicKey) {
        CryptoBuffer uH = new CryptoBuffer(clientPublicKey.toByteArray()).append(new CryptoBuffer(publicKey.toByteArray())).sha256();
        BigInteger u = new BigInteger(uH.toHex(), 16);
        BigInteger S = clientPublicKey.multiply(v.modPow(u, N)).modPow(privateKey, N);
        CryptoBuffer K = new CryptoBuffer(S.toByteArray()).sha256();
        return MACs.hmacSha256(K, new CryptoBuffer(salt.toByteArray()));
    }

    // getters/setters

    public CryptoBuffer getI() {
        return I;
    }

    public void setSalt(BigInteger salt) {
        this.salt = salt;
    }

    public BigInteger getSalt() {
        return salt;
    }

    protected BigInteger getV() {
        return v;
    }

    protected BigInteger getG() {
        return g;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    protected BigInteger getPrivateKey() {
        return privateKey;
    }

    protected CryptoBuffer getP() {
        return P;
    }

    protected BigInteger getN() {
        return N;
    }

    protected Random getR() {
        return r;
    }
}
