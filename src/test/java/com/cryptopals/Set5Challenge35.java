package com.cryptopals;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertEquals;

public class Set5Challenge35 {

    private final static CryptoBuffer MESSAGE = new CryptoBuffer("this is my message, yeah");

    @Test
    public void testEchoBot() throws Exception {
        Client A = new Client();
        Server B = new Server();

        A.sendParams(B);
        B.sendParamsReply(A);
        A.sendPublicKey(B);
        B.sendPublicKeyReply(A);
        A.sendMessage(B, MESSAGE);
        B.sendMessageReply(A);

        assertEquals(MESSAGE.toString(), A.getServerReply().toString());
    }

    @Test
    public void negotiatedGroupAttackGIsOne() throws Exception{
        Client A = new Client();
        Server B = new Server();
        MITM M = new MITM(BigInteger.ONE);

        A.sendParams(M);
        M.sendParams(B);
        B.sendParamsReply(M);
        M.sendParamsReply(A);
        A.sendPublicKey(M);
        M.sendPublicKey(B);
        B.sendPublicKeyReply(M);
        M.sendPublicKeyReply(A);
        A.sendMessage(M, MESSAGE);
        M.sendMessage(B);
        B.sendMessageReply(M);
        M.sendMessageReply(A);

        // are A and B still communicating?
        assertEquals(MESSAGE.toString(), A.getServerReply().toString());

        // did M decrypt the message?
        assertEquals(MESSAGE.toString(), M.getMessage(BigInteger.ONE).toString());
    }

    @Test
    public void negotiatedGroupAttackGIsP() throws Exception{
        Client A = new Client();
        Server B = new Server();
        MITM M = new MITM(A.getParams().p);

        A.sendParams(M);
        M.sendParams(B);
        B.sendParamsReply(M);
        M.sendParamsReply(A);
        A.sendPublicKey(M);
        M.sendPublicKey(B);
        B.sendPublicKeyReply(M);
        M.sendPublicKeyReply(A);
        A.sendMessage(M, MESSAGE);
        M.sendMessage(B);
        B.sendMessageReply(M);
        M.sendMessageReply(A);

        // are A and B still communicating?
        assertEquals(MESSAGE.toString(), A.getServerReply().toString());

        // did M decrypt the message?
        assertEquals(MESSAGE.toString(), M.getMessage(BigInteger.ZERO).toString());
    }

    @Test
    public void negotiatedGroupAttackGIsPMinusOne() throws Exception{
        Client A = new Client();
        Server B = new Server();

        BigInteger gMinusOne = A.getParams().p.subtract(BigInteger.ONE);
        MITM M = new MITM(gMinusOne);

        A.sendParams(M);
        M.sendParams(B);
        B.sendParamsReply(M);
        M.sendParamsReply(A);
        A.sendPublicKey(M);
        M.sendPublicKey(B);
        B.sendPublicKeyReply(M);
        M.sendPublicKeyReply(A);
        A.sendMessage(M, MESSAGE);
        M.sendMessage(B);
        B.sendMessageReply(M);
        M.sendMessageReply(A);

        // are A and B still communicating?
        assertEquals(MESSAGE.toString(), A.getServerReply().toString());

        // did M decrypt the message?
        BigInteger fixedSessionKey;
        if (M.getPublicKeyA().equals(BigInteger.ONE) || M.getPublicKeyB().equals(BigInteger.ONE)) {
            fixedSessionKey = BigInteger.ONE;
        }
        else {
            fixedSessionKey = gMinusOne;
        }
        assertEquals(MESSAGE.toString(), M.getMessage(fixedSessionKey).toString());
    }

    public interface Actor {
        public void sendParams(Actor other);
        public void sendPublicKey(Actor other);
        public void sendPublicKeyReply(Actor other);
        public void sendMessage(Actor other, CryptoBuffer message) throws BadPaddingException;
        public void sendParamsReply(Actor other);
        public void sendMessageReply(Actor other) throws BadPaddingException;
        public void receiveParamsReply(BigInteger p, BigInteger g);
        public void receiveMessageReply(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException;
        public void receiveParams(BigInteger p, BigInteger g);
        public void receiveMessage(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException;
        public void receivePublicKey(BigInteger clientPublicKey);
        public void receivePublicKeyReply(BigInteger serverPublicKey);
    }

    public static abstract class Endpoint implements Actor {
        private final Random r = new Random();
        protected final BigInteger privateKey;
        protected BigInteger p, g;
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

        public Client() {
            params = new DH.Params();
        }

        public DH.Params getParams() {
            return params;
        }

        @Override
        public void sendParams(Actor other) {
            other.receiveParams(params.p, params.g);
        }

        @Override
        public void receiveParamsReply(BigInteger p, BigInteger g) {
            this.p = p;
            this.g = g;
            publicKey = DH.derivePublicKey(p, g, privateKey);
        }

        @Override
        public void sendPublicKey(Actor other) {
            other.receivePublicKey(publicKey);
        }

        @Override
        public void receivePublicKeyReply(BigInteger serverPublicKey) {
            this.sessionKey = DH.deriveSessionKey(p, privateKey, serverPublicKey);
        }

        @Override
        public void sendMessage(Actor other, CryptoBuffer message) throws BadPaddingException {
            aesKey = DH.deriveAESKey(this.sessionKey, 16);
            CryptoBuffer iv = Utils.randomKey(16);
            CryptoBuffer ciphertext = Utils.aesCbcEncryptWithKey(aesKey, iv, message);
            other.receiveMessage(ciphertext, iv);
        }

        @Override
        public void receiveMessageReply(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            serverReply = Utils.aesCbcDecryptWithKey(aesKey, iv, ciphertext);
        }

        public CryptoBuffer getServerReply() {
            return this.serverReply;
        }

        @Override
        public void sendPublicKeyReply(Actor other) {
            // noop
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
        public void receiveParams(BigInteger p, BigInteger g) {
            // noop
        }

        @Override
        public void receiveMessage(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            // noop
        }

        @Override
        public void receivePublicKey(BigInteger clientPublicKey) {
            // noop
        }
    }

    public static class Server extends Endpoint {
        private CryptoBuffer clientMessage;

        @Override
        public void receiveParams(BigInteger p, BigInteger g) {
            this.p = p;
            this.g = g;
            this.publicKey = DH.derivePublicKey(p, g, privateKey);
        }

        @Override
        public void sendParamsReply(Actor other) {
            other.receiveParamsReply(p, g);
        }

        @Override
        public void receivePublicKey(BigInteger clientPublicKey) {
            this.sessionKey = DH.deriveSessionKey(p, privateKey, clientPublicKey);
        }

        @Override
        public void sendPublicKeyReply(Actor other) {
            other.receivePublicKeyReply(publicKey);
        }

        @Override
        public void receiveMessage(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            aesKey = DH.deriveAESKey(this.sessionKey, 16);
            clientMessage = Utils.aesCbcDecryptWithKey(aesKey, iv, ciphertext);
        }

        @Override
        public void sendMessageReply(Actor other) throws BadPaddingException {
            CryptoBuffer iv = Utils.randomKey(16);
            CryptoBuffer message = Utils.aesCbcEncryptWithKey(aesKey, iv, clientMessage);
            other.receiveMessageReply(message, iv);
        }

        @Override
        public void receivePublicKeyReply(BigInteger clientPublicKey) {
            // noop
        }

        @Override
        public void sendParams(Actor other) {
            // noop
        }

        @Override
        public void sendPublicKey(Actor other) {
            // noop
        }

        @Override
        public void sendMessage(Actor other, CryptoBuffer message) throws BadPaddingException {
            // noop
        }

        @Override
        public void receiveParamsReply(BigInteger p, BigInteger g) {
            // noop
        }

        @Override
        public void receiveMessageReply(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            // noop
        }
    }

    public static class MITM implements Actor {
        private BigInteger p, g, A, B;
        private CryptoBuffer ciphertext, iv; // the encrypted message in transit
        private BigInteger fixedG;

        public MITM(BigInteger fixedG) {
            this.fixedG = fixedG;
        }

        public BigInteger getPublicKeyA() {
            return A;
        }

        public BigInteger getPublicKeyB() {
            return B;
        }

        @Override
        public void receiveParams(BigInteger p, BigInteger g) {
            this.p = p;
            this.g = g;
        }

        @Override
        public void sendParams(Actor other) {
            other.receiveParams(p, fixedG);
        }

        @Override
        public void sendPublicKey(Actor other) {
            other.receivePublicKey(A);
        }

        @Override
        public void sendPublicKeyReply(Actor other) {
            other.receivePublicKeyReply(B);
        }

        @Override
        public void receiveParamsReply(BigInteger p, BigInteger g) {
            this.p = p;
            this.g = g;
        }

        @Override
        public void sendParamsReply(Actor other) {
            other.receiveParamsReply(p, fixedG);
        }

        @Override
        public void receiveMessage(CryptoBuffer ciphertext, CryptoBuffer iv) throws BadPaddingException {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }

        @Override
        public void receivePublicKey(BigInteger clientPublicKey) {
            A = clientPublicKey;
        }

        @Override
        public void receivePublicKeyReply(BigInteger serverPublicKey) {
            B = serverPublicKey;
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

        public CryptoBuffer getMessage(BigInteger fixatedSessionKey) throws BadPaddingException {
            CryptoBuffer aesKey = DH.deriveAESKey(fixatedSessionKey, 16);
            return Utils.aesCbcDecryptWithKey(aesKey, iv, ciphertext);
        }
    }
}
