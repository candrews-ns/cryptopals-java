package com.cryptopals;

import org.apache.commons.codec.DecoderException;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.junit.Test;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;
import java.util.concurrent.*;

import static org.apache.http.client.fluent.Request.Get;
import static org.junit.Assert.assertEquals;

public class Set4Challenge31 {

    @Test
    public void testHmac() {
        CryptoBuffer message = new CryptoBuffer("this is my message");
        CryptoBuffer key = new CryptoBuffer("YELLOW SUBMARINE");
        CryptoBuffer hmac = MACs.hmacSha1(key, message);
        assertEquals("d633e0eafd62e026262de497e58d956961a2b5c3", hmac.toHex());
    }

    //@Test
    public void breakArtificialTimingLeak() throws Exception {
        LeakyHMAC mac = new LeakyHMAC();
        LeakyServer server = new LeakyServer(mac);

        ThreadFactory serversFactory = new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r);
                t.setName("leaky-servers");
                return t;
            }
        };
        Executor serversExec = Executors.newFixedThreadPool(1, serversFactory);
        Runnable s = () -> server.start();
        serversExec.execute(s);

        Get("http://127.0.0.1:8080/?file=foo&signature=")
                .connectTimeout(1000)
                .socketTimeout(100000)
                .execute();

        CryptoBuffer signature = new CryptoBuffer("");
        for (int i = 0; i < 20; i++) {
            TreeSet<Map.Entry<Byte, Long>> times = new TreeSet<>(new CandidateComparator<Long>());

            ThreadFactory clientsFactory = new ThreadFactory() {
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r);
                    t.setName("leaky-clients");
                    return t;
                }
            };
            Executor clientsExec = Executors.newFixedThreadPool(6, clientsFactory);
            CompletionService<AbstractMap.SimpleImmutableEntry<Byte, Long>> ecs = new ExecutorCompletionService<>(clientsExec);

            ArrayList<Byte> bytes = new ArrayList<>();
            for (byte b = Byte.MIN_VALUE; b < Byte.MAX_VALUE; b++) {
                bytes.add(b);
            }
            for (final Byte b : bytes) {
                ecs.submit(() -> timeGuess(signature, b));
            }
            for (int j = 0, n = bytes.size(); j < n; j++) {
                AbstractMap.SimpleImmutableEntry<Byte, Long> r = ecs.take().get();
                times.add(r);
            }

            System.out.println("items: " + times.size());
            for(Map.Entry<Byte, Long> entry : times) {
                System.out.print(entry.getValue() + " ");
                System.out.println("");
            }

            signature.append(new CryptoBuffer(times.first().getKey()));
            System.out.println("signature: " + signature.toHex());
        }
        String response = Get("http://127.0.0.1:8080/?file=foo&signature=" + signature.toHex())
                .connectTimeout(1000)
                .socketTimeout(100000)
                .execute().returnContent().asString();
        assertEquals("YES", response);
    }

    private AbstractMap.SimpleImmutableEntry<Byte, Long> timeGuess(CryptoBuffer signature, Byte b) {
        CryptoBuffer guess = signature.clone().append(Utils.bufferOfLength(b, (20 - signature.length())));
        long start = System.currentTimeMillis();
        try {
            String response = Get("http://127.0.0.1:8080/?file=foo&signature=" + guess.toHex())
                    .connectTimeout(1000)
                    .socketTimeout(100000)
                    .execute().returnContent().toString();
        } catch (IOException ignored) { }
        long duration = System.currentTimeMillis() - start;
        return new AbstractMap.SimpleImmutableEntry<>(b, duration);
    }

    private static class CandidateComparator<V extends Comparable<V>> implements Comparator<Map.Entry<?, V>> {
        public int compare(Map.Entry<?, V> o1, Map.Entry<?, V> o2) {
            return o2.getValue().compareTo(o1.getValue());
        }
    }

    private static class LeakyHMAC {
        private final CryptoBuffer key;

        public LeakyHMAC() {
            key = new CryptoBuffer("YELLOW SUBMARINE"); //Utils.randomKey(16);
            System.out.println("mac: " + MACs.hmacSha1(key, new CryptoBuffer("foo")).toHex());
        }

        public boolean check(CryptoBuffer file, CryptoBuffer clientMac) {
            CryptoBuffer hmac = MACs.hmacSha1(key, file);
            return insecureCompare(hmac, clientMac);
        }

        private boolean insecureCompare(CryptoBuffer a, CryptoBuffer b) {
            if (a.length() != b.length()) {
                return false;
            }
            for (int i = 0; i < a.length(); i++) {
                if (!a.substr(i, 1).toString().equals(b.substr(i, 1).toString())) {
                    return false;
                }
                try {
                    Thread.sleep(50);
                } catch (InterruptedException ignored) { }
            }
            return true;
        }
    }

    private static class LeakyServer {
        private final Server server;

        public LeakyServer(LeakyHMAC mac) {
            server = new Server(8080);
            server.setHandler(new LeakyHandler(mac));
        }

        public void start() {
            try {
                server.start();
                //server.dumpStdErr();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static class LeakyHandler extends AbstractHandler {
        private final LeakyHMAC mac;

        public LeakyHandler(LeakyHMAC mac) {
            this.mac = mac;
        }

        public void handle(String target,
                           Request baseRequest,
                           HttpServletRequest request,
                           HttpServletResponse response) throws IOException,
                ServletException {

            PrintWriter out = response.getWriter();
            response.setContentType("text/plain; charset=utf-8");

            CryptoBuffer signature = null;
            try {
                signature = CryptoBuffer.fromHex(request.getParameter("signature"));
            } catch (DecoderException e) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                out.print("NO (bad hex)");
            }

            CryptoBuffer file = new CryptoBuffer(request.getParameter("file"));

            if (signature != null) {
                if (mac.check(file, signature)) {
                    out.print("YES");
                } else {
                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    out.print("NO");
                }
            }

            baseRequest.setHandled(true);
        }
    }
}
