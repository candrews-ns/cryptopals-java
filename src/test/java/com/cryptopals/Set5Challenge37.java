package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;

public class Set5Challenge37 {

    @Test
    public void breakSRPWithFakePublicKeys() {
        DH.Params params = new DH.Params();

        BigInteger[] fakes = new BigInteger[]{
                BigInteger.ZERO,
                params.p,
                params.p.multiply(new BigInteger("2"))
        };

        for (BigInteger fake : fakes) {
            Client C = new Client("falken", "yeahidunno", fake);
            Server S = new Server("falken", "joshua");

            C.sendPublicKey(S);
            S.sendPublicKeyReply(C);
            C.sendSessionKey(S);
            S.sendSessionKeyReply(C);

            assert (C.isAuthenticated());
            assert (S.isAuthenticated());
        }
    }

    public static abstract class Endpoint {
        protected final SRP state;
        protected boolean ok;

        public Endpoint(String user, String password) {
            state = new SRP();
            state.setCredentials(user, password);
        }

        public boolean isAuthenticated() {
            return ok;
        }
    }

    public static class Client extends Endpoint {
        private BigInteger serverPublicKey;
        private BigInteger fakePublicKey;

        public Client(String user, String password, BigInteger fakePublicKey) {
            super(user, password);
            this.fakePublicKey = fakePublicKey;
        }

        public void sendPublicKey(Server other) {
            // don't bother computing a public key, just send zero
            other.receivePublicKey(state.getI(), fakePublicKey);
        }

        public void receivePublicKeyReply(BigInteger salt, BigInteger publicKey) {
            state.setSalt(salt);
            serverPublicKey = publicKey;
        }

        public void sendSessionKey(Server other) {
            // compute a session key using the salt and zero
            CryptoBuffer K = new CryptoBuffer(BigInteger.ZERO.toByteArray()).sha256();
            other.receiveSessionKey(MACs.hmacSha256(K, new CryptoBuffer(state.getSalt().toByteArray())));
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
        }

        public void receivePublicKey(CryptoBuffer I, BigInteger publicKey) {
            clientPublicKey = publicKey;
        }

        public void sendPublicKeyReply(Client other) {
            other.receivePublicKeyReply(state.getSalt(), state.serverComputePublicKey());
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
