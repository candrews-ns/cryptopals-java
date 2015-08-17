package com.cryptopals;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Map;
import java.util.Random;

/**
 * Created by candrews on 12/06/15.
 */
public class Utils {

    public static ArrayList<String> readLinesFromClasspath(String filename) throws Exception {
        InputStream in = Utils.class.getResourceAsStream(filename);
        if (in == null)
            throw new Exception("can't open " + filename);

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(in));
        String line;
        ArrayList<String> lines = new ArrayList<>();

        while ((line = bufferedReader.readLine()) != null) {
            lines.add(line);
        }

        return lines;
    }

    public static String readFromClasspath(String filename) throws Exception {
        ArrayList<String> lines = readLinesFromClasspath(filename);
        StringBuilder text = new StringBuilder();
        for (String line : lines) {
            text.append(line);
        }
        return text.toString();
    }

    public static class ScoreComparator<K extends Comparable<K>, V extends Comparable<V>> implements Comparator<Map.Entry<K, V>> {
        public int compare(Map.Entry<K, V> o1, Map.Entry<K, V> o2) {
            int r = o1.getValue().compareTo(o2.getValue());
            if (r != 0) {
                return r;
            } else {
                return o2.getKey().compareTo(o1.getKey());
            }
        }
    }

    public static CryptoBuffer randomKey(int len) {
        Random r = new Random();
        byte[] bytes = new byte[len];
        r.nextBytes(bytes);
        return new CryptoBuffer(bytes);
    }

    public static String stringOfLength(char c, int len) {
        StringBuilder s = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            s.append(c);
        }
        return s.toString();
    }
}
