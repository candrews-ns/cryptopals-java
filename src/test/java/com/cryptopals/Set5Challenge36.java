package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

public class Set5Challenge36 {

    @Test
    public void testSRP() {
        Client C = new Client("joshua");
        Server S = new Server();

        C.sendPublicKey(S);
        S.sendPublicKeyReply(C);
        C.sendSessionKey(S);
        S.sendSessionKeyReply(C);

        assert(C.isAuthenticated());
        assert(S.isAuthenticated());
    }

    @Test
    public void testSRPBadPassword() {
        Client C = new Client("xyzzy");
        Server S = new Server();

        C.sendPublicKey(S);
        S.sendPublicKeyReply(C);
        C.sendSessionKey(S);
        S.sendSessionKeyReply(C);

        assert(!C.isAuthenticated());
        assert(!S.isAuthenticated());
    }

    public static abstract class Endpoint {
        protected final Random r = new Random();
        protected final BigInteger N;
        protected final BigInteger g;
        protected final BigInteger k;
        protected CryptoBuffer I;
        protected CryptoBuffer P;
        protected CryptoBuffer K;
        protected boolean ok;

        public Endpoint() {
            DH.Params params = new DH.Params();
            N = params.p;
            g = params.g;
            k = new BigInteger("3");
        }

        public boolean isAuthenticated() {
            return ok;
        }
    }

    public static class Client extends Endpoint {
        private final BigInteger a;
        private BigInteger A, B, salt;

        public Client(String password) {
            super();
            a = new BigInteger(512, r);
            I = new CryptoBuffer("falken");
            P = new CryptoBuffer(password);
        }

        public void sendPublicKey(Server other) {
            A = g.modPow(a, N);
            other.receivePublicKey(I, A);
        }

        public void receivePublicKeyReply(BigInteger salt, BigInteger B) {
            this.salt = salt;
            this.B = B;
            CryptoBuffer uH = new CryptoBuffer(A.toByteArray()).append(new CryptoBuffer(B.toByteArray())).sha256();
            BigInteger u = new BigInteger(uH.toHex(), 16);
            CryptoBuffer xH = new CryptoBuffer(salt.toByteArray()).append(P).sha256();
            BigInteger x = new BigInteger(xH.toHex(), 16);
            BigInteger S = B.subtract(k.multiply(g.modPow(x, N))).modPow((a.add(u.multiply(x))), N);
            K = new CryptoBuffer(S.toByteArray()).sha256();
        }

        public void sendSessionKey(Server other) {
            other.receiveSessionKey(MACs.hmacSha256(K, new CryptoBuffer(salt.toByteArray())));
        }

        public void receiveSessionKeyReply(boolean ok) {
            this.ok = ok;
        }
    }

    public static class Server extends Endpoint {
        private final BigInteger salt, v, b;
        private BigInteger A, B;

        public Server() {
            super();
            b = new BigInteger(512, r);
            I = new CryptoBuffer("falken");
            P = new CryptoBuffer("joshua");

            salt = new BigInteger(512, r);
            CryptoBuffer xH = new CryptoBuffer(salt.toByteArray()).append(P).sha256();
            BigInteger x = new BigInteger(xH.toHex(), 16);
            v = g.modPow(x, N);
        }

        public void receivePublicKey(CryptoBuffer I, BigInteger A) {
            this.A = A;
        }

        public void sendPublicKeyReply(Client other) {
            B = (k.multiply(v)).add(g.modPow(b, N));
            other.receivePublicKeyReply(salt, B);
            CryptoBuffer uH = new CryptoBuffer(A.toByteArray()).append(new CryptoBuffer(B.toByteArray())).sha256();
            BigInteger u = new BigInteger(uH.toHex(), 16);
            BigInteger S = A.multiply(v.modPow(u, N)).modPow(b, N);
            K = new CryptoBuffer(S.toByteArray()).sha256();
        }

        public void receiveSessionKey(CryptoBuffer clientKey) {
            CryptoBuffer serverKey = MACs.hmacSha256(K, new CryptoBuffer(salt.toByteArray()));
            ok = serverKey.equals(clientKey);
        }

        public void sendSessionKeyReply(Client other) {
            other.receiveSessionKeyReply(ok);
        }
    }
}
