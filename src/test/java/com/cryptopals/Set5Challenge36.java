package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;

public class Set5Challenge36 {

    @Test
    public void testSRP() {
        Client C = new Client("falken", "joshua");
        Server S = new Server("falken", "joshua");

        C.sendPublicKey(S);
        S.sendPublicKeyReply(C);
        C.sendSessionKey(S);
        S.sendSessionKeyReply(C);

        assert(C.isAuthenticated());
        assert(S.isAuthenticated());
    }

    @Test
    public void testSRPBadPassword() {
        Client C = new Client("falken", "xyzzy");
        Server S = new Server("falken", "joshua");

        C.sendPublicKey(S);
        S.sendPublicKeyReply(C);
        C.sendSessionKey(S);
        S.sendSessionKeyReply(C);

        assert(!C.isAuthenticated());
        assert(!S.isAuthenticated());
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

        public Client(String user, String password) {
            super(user, password);
        }

        public void sendPublicKey(Server other) {
            other.receivePublicKey(state.getI(), state.clientComputePublicKey());
        }

        public void receivePublicKeyReply(BigInteger salt, BigInteger publicKey) {
            state.setSalt(salt);
            serverPublicKey = publicKey;
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
