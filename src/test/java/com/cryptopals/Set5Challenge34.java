package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 03/09/15.
 */
public class Set5Challenge34 {

    private final static CryptoBuffer MESSAGE = new CryptoBuffer("this is my message, yeah");

    @Test
    public void testEchoBot() throws Exception {
        Client A = new Client();
        Server B = new Server();

        A.sendParams(B);
        B.sendParamsReply(A);
        A.sendMessage(B, MESSAGE);
        B.sendMessageReply(A);

        assertEquals(MESSAGE.toString(), A.getServerReply().toString());
    }

    //@Test
    public void keyFixingAttack() {

    }

    public static class Actor {
        private final Random r = new Random();
        protected final BigInteger privateKey;
        protected BigInteger publicKey;
        protected BigInteger sessionKey;
        protected CryptoBuffer aesKey;

        public Actor() {
            this.privateKey = DH.generatePrivateKey(512, r);
        }
    }

    public static class Client extends Actor {
        private DH.Params params;
        private CryptoBuffer serverReply;

        public void sendParams(Server other) {
            params = new DH.Params();
            publicKey = DH.derivePublicKey(params.p, params.g, privateKey);
            other.receiveParams(params.p, params.g, this.publicKey);
        }

        public void receiveParamsReply(BigInteger serverPublicKey) {
            this.sessionKey = DH.deriveSessionKey(params.p, privateKey, serverPublicKey);
        }

        public void sendMessage(Server other, CryptoBuffer message) throws BadPaddingException {
            aesKey = DH.deriveAESKey(this.sessionKey, 16);
            CryptoBuffer iv = Utils.randomKey(16);
            CryptoBuffer ciphertext = Utils.aesCbcEncryptWithKey(aesKey, iv, message);
            other.receiveMessage(ciphertext, iv);
        }

        public void receiveMessageReply(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            serverReply = Utils.aesCbcDecryptWithKey(aesKey, iv, ciphertext);
        }

        public CryptoBuffer getServerReply() {
            return this.serverReply;
        }
    }

    public static class Server extends Actor {
        private BigInteger p;
        private BigInteger g;
        private CryptoBuffer clientMessage;

        public void receiveParams(BigInteger p, BigInteger g, BigInteger clientPublicKey) {
            this.p = p;
            this.g = g;
            this.publicKey = DH.derivePublicKey(p, g, privateKey);
            this.sessionKey = DH.deriveSessionKey(p, privateKey, clientPublicKey);
        }

        public void sendParamsReply(Client other) {
            other.receiveParamsReply(publicKey);
        }

        public void receiveMessage(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            aesKey = DH.deriveAESKey(this.sessionKey, 16);
            clientMessage = Utils.aesCbcDecryptWithKey(aesKey, iv, ciphertext);
        }

        public void sendMessageReply(Client other) throws BadPaddingException {
            CryptoBuffer iv = Utils.randomKey(16);
            CryptoBuffer message = Utils.aesCbcEncryptWithKey(aesKey, iv, clientMessage);
            other.receiveMessageReply(message, iv);
        }
    }
}
