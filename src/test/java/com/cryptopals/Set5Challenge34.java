package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertEquals;

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

    @Test
    public void keyFixingAttack() throws Exception{
        Client A = new Client();
        Server B = new Server();
        MITM M = new MITM();

        A.sendParams(M);
        M.sendParams(B);
        B.sendParamsReply(M);
        M.sendParamsReply(A);
        A.sendMessage(M, MESSAGE);
        M.sendMessage(B);
        B.sendMessageReply(M);
        M.sendMessageReply(A);

        // are A and B still communicating?
        assertEquals(MESSAGE.toString(), A.getServerReply().toString());

        // did M decrypt the message?
        assertEquals(MESSAGE.toString(), M.getMessage().toString());
    }

    public interface Actor {
        public void sendParams(Actor other);
        public void sendMessage(Actor other, CryptoBuffer message) throws BadPaddingException;
        public void sendParamsReply(Actor other);
        public void sendMessageReply(Actor other) throws BadPaddingException;
        public void receiveParamsReply(BigInteger serverPublicKey);
        public void receiveMessageReply(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException;
        public void receiveParams(BigInteger p, BigInteger g, BigInteger clientPublicKey);
        public void receiveMessage(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException;
    }

    public static abstract class Endpoint implements Actor {
        private final Random r = new Random();
        protected final BigInteger privateKey;
        protected BigInteger publicKey;
        protected BigInteger sessionKey;
        protected CryptoBuffer aesKey;

        public Endpoint() {
            this.privateKey = DH.generatePrivateKey(512, r);
        }
    }

    public static class Client extends Endpoint {
        private DH.Params params;
        private CryptoBuffer serverReply;

        public void sendParams(Actor other) {
            params = new DH.Params();
            publicKey = DH.derivePublicKey(params.p, params.g, privateKey);
            other.receiveParams(params.p, params.g, this.publicKey);
        }

        public void receiveParamsReply(BigInteger serverPublicKey) {
            this.sessionKey = DH.deriveSessionKey(params.p, privateKey, serverPublicKey);
        }

        public void sendMessage(Actor other, CryptoBuffer message) throws BadPaddingException {
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

        @Override
        public void sendParamsReply(Actor other) {
            // noop
        }

        @Override
        public void sendMessageReply(Actor other) {
            // noop
        }

        @Override
        public void receiveParams(BigInteger p, BigInteger g, BigInteger clientPublicKey) {
            // noop
        }

        @Override
        public void receiveMessage(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            // noop
        }
    }

    public static class Server extends Endpoint {
        private CryptoBuffer clientMessage;

        public void receiveParams(BigInteger p, BigInteger g, BigInteger clientPublicKey) {
            this.publicKey = DH.derivePublicKey(p, g, privateKey);
            this.sessionKey = DH.deriveSessionKey(p, privateKey, clientPublicKey);
        }

        public void sendParamsReply(Actor other) {
            other.receiveParamsReply(publicKey);
        }

        public void receiveMessage(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            aesKey = DH.deriveAESKey(this.sessionKey, 16);
            clientMessage = Utils.aesCbcDecryptWithKey(aesKey, iv, ciphertext);
        }

        public void sendMessageReply(Actor other) throws BadPaddingException {
            CryptoBuffer iv = Utils.randomKey(16);
            CryptoBuffer message = Utils.aesCbcEncryptWithKey(aesKey, iv, clientMessage);
            other.receiveMessageReply(message, iv);
        }

        @Override
        public void sendParams(Actor other) {

        }

        @Override
        public void sendMessage(Actor other, CryptoBuffer message) throws BadPaddingException {

        }

        @Override
        public void receiveParamsReply(BigInteger serverPublicKey) {

        }

        @Override
        public void receiveMessageReply(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {

        }
    }

    public static class MITM implements Actor {
        private BigInteger p, g, A, B;
        private CryptoBuffer ciphertext, iv; // the encrypted message in transit

        @Override
        public void receiveParams(BigInteger p, BigInteger g, BigInteger clientPublicKey) {
            this.A = clientPublicKey;
            this.p = p;
            this.g = g;
        }

        @Override
        public void sendParams(Actor other) {
            other.receiveParams(p, g, p);
        }

        @Override
        public void receiveParamsReply(BigInteger serverPublicKey) {
            this.B = serverPublicKey;
        }

        @Override
        public void sendParamsReply(Actor other) {
            other.receiveParamsReply(p);
        }

        @Override
        public void receiveMessage(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }

        @Override
        public void sendMessage(Actor other, CryptoBuffer message) throws BadPaddingException {
            // noop
        }

        public void sendMessage(Actor other) throws BadPaddingException {
            other.receiveMessage(this.ciphertext, this.iv);
        }

        @Override
        public void receiveMessageReply(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }

        @Override
        public void sendMessageReply(Actor other) throws BadPaddingException {
            other.receiveMessageReply(this.ciphertext, this.iv);
        }

        public CryptoBuffer getMessage() throws BadPaddingException {
            BigInteger fixatedSessionKey = BigInteger.ZERO; // !
            CryptoBuffer aesKey = DH.deriveAESKey(fixatedSessionKey, 16);
            return Utils.aesCbcDecryptWithKey(aesKey, this.iv, this.ciphertext);
        }
    }
}
