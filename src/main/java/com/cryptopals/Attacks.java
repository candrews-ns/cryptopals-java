package com.cryptopals;

import java.util.*;

/**
 * Created by candrews on 17/08/15.
 */
public class Attacks {

    interface Oracle {
        CryptoBuffer test(CryptoBuffer text);
    }

    public static int findBlocksize(Oracle o) {
        TreeSet<Map.Entry<Integer, Double>> keysizes = new TreeSet<>(new Utils.ScoreComparator<Integer, Double>());

        CryptoBuffer ciphertext = o.test(
                new CryptoBuffer(Utils.stringOfLength('Z', 512))
        );

        for (int keysize = 2; keysize <= 31; keysize++) {
            ArrayList<Double> dists = new ArrayList<>();
            for (int x = 1; x <= 10; x++) {
                for (int y = 0; y <= 10; y++) {
                    if (x == y)
                        break;
                    CryptoBuffer s1 = ciphertext.substr(x * keysize, keysize);
                    CryptoBuffer s2 = ciphertext.substr(y * keysize, keysize);
                    double dist = s1.hammingDistance(s2) / keysize;
                    dists.add(dist);
                }
            }
            double sum = 0;
            for (double dist : dists)
                sum += dist;
            double avg = sum / dists.size();
            keysizes.add(new AbstractMap.SimpleImmutableEntry<>(keysize, avg));
        }

        return keysizes.first().getKey();
    }

    public static boolean findEcb(int blocksize, Oracle o) {
        boolean isEcb = false;
        HashMap<String, Boolean> chunks = new HashMap<>();

        CryptoBuffer ciphertext = o.test(
                new CryptoBuffer(Utils.stringOfLength('A', 1024))
        );

        for (CryptoBuffer chunk : ciphertext.chunked(blocksize)) {
            if (chunks.containsKey(chunk.toHex())) {
                isEcb = true;
            }
            else {
                chunks.put(chunk.toHex(), true);
            }
        }
        return isEcb;
    }

    public static CryptoBuffer breakEcb(int blocksize, Oracle o) {

        CryptoBuffer plaintext = new CryptoBuffer();

        for (int i = 0; i < 256; i++) {
            CryptoBuffer prefix = new CryptoBuffer(Utils.stringOfLength('A', (255 - i)));
            HashMap<String, CryptoBuffer> map = new HashMap<>();

            for (int j = 0; j < 127; j++) {
                CryptoBuffer b = new CryptoBuffer((byte)j);
                CryptoBuffer trial = prefix.clone().append(plaintext).append(b);
                CryptoBuffer ciphertext = o.test(trial).substr(0, 256);
                map.put(ciphertext.toString(), b);
            }

            CryptoBuffer ciphertext = o.test(prefix).substr(0, 256);
            CryptoBuffer found = map.get(ciphertext.toString());

            if (found == null) {
                break;
            }

            plaintext.append(found);
        }

        return plaintext;
    }

    public static CryptoBuffer breakEcbWithPrefix(int blocksize, Oracle o) {

        CryptoBuffer plaintext = new CryptoBuffer();
        CryptoBuffer prefix = new CryptoBuffer(
                Utils.stringOfLength('A', 32) + Utils.stringOfLength('B', 32) + Utils.stringOfLength('C', 255)
        );

        for (int i = 0; i < 256; i++) {
            HashMap<String, CryptoBuffer> map = new HashMap<>();

            for (int j = 0; j < 127; j++) {
                CryptoBuffer b = new CryptoBuffer((byte)j);
                CryptoBuffer trial = prefix.clone().append(plaintext).append(b);
                CryptoBuffer ciphertext = encryptUntilFound(blocksize, o, trial);
                map.put(ciphertext.toString(), b);
            }

            CryptoBuffer ciphertext = encryptUntilFound(blocksize, o, prefix.clone());
            CryptoBuffer found = map.get(ciphertext.toString());

            if (found == null) {
                break;
            }

            plaintext.append(found);
            prefix = prefix.chop();
        }

        return plaintext;
    }

    private static CryptoBuffer encryptUntilFound(int blocksize, Oracle o, CryptoBuffer trial) {
        for (;;) {
            CryptoBuffer ciphertext = o.test(trial);

            ArrayList<CryptoBuffer> chunks = ciphertext.chunked(blocksize);
            if ( chunks.get(1).toString().equals(chunks.get(2).toString()) &&
                    chunks.get(3).toString().equals(chunks.get(4).toString()) ) {
                return ciphertext.substr((blocksize * 5), 256);
            }
        }
    }
}
