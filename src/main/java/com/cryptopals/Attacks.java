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
        TreeSet<Map.Entry<Integer, Double>> keysizes = new TreeSet<>(new Utils.ScoreComparator<Double>());

        CryptoBuffer ciphertext = o.test(
                new CryptoBuffer(Utils.stringOfLength('A', 1024))
        );

        for (int keysize = 2; keysize <= 40; keysize++) {
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
}
