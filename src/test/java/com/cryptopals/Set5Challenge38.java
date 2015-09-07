package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertEquals;

public class Set5Challenge38 {

    @Test
    public void testSimplifiedSRPStandalone() {
        DH.Params params = new DH.Params();
        BigInteger N = params.p;
        BigInteger g = params.g;

        Random r = new Random();

        //server
        BigInteger salt = new BigInteger(512, r);
        CryptoBuffer xH = new CryptoBuffer(salt.toByteArray()).append(new CryptoBuffer("joshua")).sha256();
        BigInteger x = new BigInteger(xH.toHex(), 16);
        BigInteger v = g.modPow(x, N);

        //client
        BigInteger a = new BigInteger(512, r);
        BigInteger A = g.modPow(a, N);

        //server
        BigInteger b = new BigInteger(512, r);
        BigInteger B = g.modPow(b, N);
        BigInteger u = new BigInteger(128, r);

        //client
        CryptoBuffer client_xH = new CryptoBuffer(salt.toByteArray()).append(new CryptoBuffer("joshua")).sha256();
        BigInteger client_x = new BigInteger(client_xH.toHex(), 16);
        BigInteger client_S = B.modPow((a.add(u.multiply(client_x))), N);

        //server
        BigInteger server_S = A.multiply(v.modPow(u, N)).modPow(b, N);

        assertEquals(client_S, server_S);
    }

    @Test
    public void testSimplifiedSRP() {
        Client C = new Client("falken", "joshua");
        Server S = new Server("falken", "joshua");

        C.sendPublicKey(S);
        S.sendPublicKeyReply(C);
        C.sendSessionKey(S);
        S.sendSessionKeyReply(C);

        assert(C.isAuthenticated());
        assert(S.isAuthenticated());

        Client C2 = new Client("falken", "xyzzy");
        C2.sendPublicKey(S);
        S.sendPublicKeyReply(C2);
        C2.sendSessionKey(S);
        S.sendSessionKeyReply(C2);

        assert(!C2.isAuthenticated());
        assert(!S.isAuthenticated());
    }

    @Test
    public void breakSRPOffline() {
        Client C = new Client("falken", "monkey");
        MITM M = new MITM();

        C.sendPublicKey(M);
        M.sendPublicKeyReply(C);
        C.sendSessionKey(M);
        M.sendSessionKeyReply(C);

        String[] passwords = {
                "123456", "password", "12345", "12345678", "qwerty",
                "123456789", "1234", "baseball", "dragon", "football",
                "1234567", "monkey", "letmein", "abc123", "111111",
                "mustang", "access", "shadow", "master", "michael",
                "superman", "696969", "123123", "batman", "trustno1"
        };
        boolean found = false;
        for (String password : passwords) {
            CryptoBuffer guess = makeGuess(M, password);
            if (guess.equals(M.getClientKey())) {
                found = true;
            }
        }
        assert(found);
    }

    private CryptoBuffer makeGuess(MITM M, String password) {
        CryptoBuffer xH = new CryptoBuffer(M.getSalt().toByteArray()).append(new CryptoBuffer(password)).sha256();
        BigInteger x = new BigInteger(xH.toHex(), 16);
        BigInteger v = M.getG().modPow(x, M.getN());
        BigInteger v_u = v.modPow(M.getU(), M.getN());
        BigInteger S = M.getClientPublicKey().multiply(v_u).modPow(M.getServerPrivateKey(), M.getN());
        CryptoBuffer K = new CryptoBuffer(S.toByteArray()).sha256();
        return MACs.hmacSha256(K, new CryptoBuffer(M.getSalt().toByteArray()));
    }

    public static class MITM extends Server {
        private CryptoBuffer clientKey;
        private final Random r;
        private final BigInteger g;
        private final BigInteger N;
        private BigInteger salt;
        private BigInteger serverPublicKey;
        private BigInteger serverPrivateKey;
        private BigInteger clientPublicKey;
        private BigInteger u;

        public MITM() {
            this.r = new Random();

            DH.Params params = new DH.Params();
            this.g = params.g;
            this.N = params.p;
        }

        public void receivePublicKey(CryptoBuffer I, BigInteger publicKey) {
            clientPublicKey = publicKey;
        }

        public void sendPublicKeyReply(Client other) {
            salt = new BigInteger(512, r);
            serverPrivateKey = new BigInteger(512, r);
            serverPublicKey = g.modPow(serverPrivateKey, N);
            u = new BigInteger(128, r);
            other.receivePublicKeyReply(salt, serverPublicKey, u);
        }

        public void receiveSessionKey(CryptoBuffer clientKey) {
            this.clientKey = clientKey;
        }

        public void sendSessionKeyReply(Client other) {
            other.receiveSessionKeyReply(true);
        }

        public CryptoBuffer getClientKey() {
            return clientKey;
        }

        public BigInteger getSalt() {
            return salt;
        }

        public BigInteger getServerPublicKey() {
            return serverPublicKey;
        }

        public BigInteger getServerPrivateKey() {
            return serverPrivateKey;
        }

        public BigInteger getClientPublicKey() {
            return clientPublicKey;
        }

        public BigInteger getU() {
            return u;
        }

        public BigInteger getG() {
            return g;
        }

        public BigInteger getN() {
            return N;
        }
    }

    public static class SimplifiedSRP {
        private final Random r = new Random();
        private final BigInteger N;
        private final BigInteger g;

        private CryptoBuffer I;
        private CryptoBuffer P;

        private BigInteger salt, v;

        private final BigInteger privateKey;
        private BigInteger publicKey;

        private BigInteger u;

        public SimplifiedSRP() {
            DH.Params params = new DH.Params();
            N = params.p;
            g = params.g;
            privateKey = new BigInteger(512, r);
        }

        public void setCredentials(String user, String password) {
            this.I = new CryptoBuffer(user);
            this.P = new CryptoBuffer(password);
        }

        public void serverComputeVerifier() {
            salt = new BigInteger(512, r);
            CryptoBuffer xH = new CryptoBuffer(salt.toByteArray()).append(P).sha256();
            BigInteger x = new BigInteger(xH.toHex(), 16);
            v = g.modPow(x, N);
        }

        public BigInteger clientComputePublicKey() {
            publicKey = g.modPow(privateKey, N);
            return publicKey;
        }

        public BigInteger serverComputePublicKey() {
            return g.modPow(privateKey, N);
        }

        public CryptoBuffer clientComputeSessionKey(BigInteger serverPublicKey) {
            CryptoBuffer xH = new CryptoBuffer(this.getSalt().toByteArray()).append(this.P).sha256();
            BigInteger x = new BigInteger(xH.toHex(), 16);
            BigInteger S = serverPublicKey.modPow((privateKey.add(u.multiply(x))), N);
            CryptoBuffer K = new CryptoBuffer(S.toByteArray()).sha256();
            return MACs.hmacSha256(K, new CryptoBuffer(this.getSalt().toByteArray()));
        }

        public CryptoBuffer serverComputeSessionKey(BigInteger clientPublicKey) {
            BigInteger S = clientPublicKey.multiply(v.modPow(u, N)).modPow(privateKey, N);
            CryptoBuffer K = new CryptoBuffer(S.toByteArray()).sha256();
            return MACs.hmacSha256(K, new CryptoBuffer(this.getSalt().toByteArray()));
        }

        public void setU(BigInteger u) {
            this.u = u;
        }

        public BigInteger getU() {
            return u;
        }

        public CryptoBuffer getI() {
            return I;
        }

        public void setSalt(BigInteger salt) {
            this.salt = salt;
        }

        public BigInteger getSalt() {
            return salt;
        }

        public Random getR() {
            return r;
        }
    }

    public static abstract class Endpoint {
        protected SimplifiedSRP state;
        protected boolean ok;

        public Endpoint(String user, String password) {
            state = new SimplifiedSRP();
            state.setCredentials(user, password);
        }

        protected Endpoint() {
        }

        public boolean isAuthenticated() {
            return ok;
        }
    }

    public static class Client extends Endpoint {
        private BigInteger serverPublicKey;

        public Client(String user, String password) {
            super(user, password);
        }

        public void sendPublicKey(Server other) {
            other.receivePublicKey(state.getI(), state.clientComputePublicKey());
        }

        public void receivePublicKeyReply(BigInteger salt, BigInteger publicKey, BigInteger u) {
            state.setSalt(salt);
            serverPublicKey = publicKey;
            state.setU(u);
        }

        public void sendSessionKey(Server other) {
            other.receiveSessionKey(state.clientComputeSessionKey(serverPublicKey));
        }

        public void receiveSessionKeyReply(boolean ok) {
            this.ok = ok;
        }
    }

    public static class Server extends Endpoint {
        private BigInteger clientPublicKey;

        public Server(String user, String password) {
            super(user, password);
            state.serverComputeVerifier();
            state.setU(new BigInteger(128, state.getR()));
        }

        public Server() {
        }

        public void receivePublicKey(CryptoBuffer I, BigInteger publicKey) {
            clientPublicKey = publicKey;
        }

        public void sendPublicKeyReply(Client other) {
            other.receivePublicKeyReply(state.getSalt(), state.serverComputePublicKey(), state.getU());
        }

        public void receiveSessionKey(CryptoBuffer clientKey) {
            CryptoBuffer serverKey = state.serverComputeSessionKey(clientPublicKey);
            ok = serverKey.equals(clientKey);
        }

        public void sendSessionKeyReply(Client other) {
            other.receiveSessionKeyReply(ok);
        }
    }

}
