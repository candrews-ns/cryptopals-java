package com.cryptopals;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by candrews on 05/06/15.
 */
public class Metrics {

    private static final HashMap<Character, Float> english = new HashMap<Character, Float>();
    static {
        english.put(' ', new Float(20.0));
        english.put('e', new Float(12.702));
        english.put('t', new Float(9.056));
        english.put('a', new Float(8.167));
        english.put('o', new Float(7.507));
        english.put('i', new Float(6.966));
        english.put('n', new Float(6.749));
        english.put('s', new Float(6.327));
        english.put('h', new Float(6.094));
        english.put('r', new Float(5.987));
        english.put('d', new Float(4.253));
        english.put('l', new Float(4.025));
        english.put('c', new Float(2.782));
        english.put('u', new Float(2.758));
        english.put('m', new Float(2.406));
        english.put('w', new Float(2.360));
        english.put('f', new Float(2.228));
        english.put('g', new Float(2.015));
        english.put('y', new Float(1.974));
        english.put('p', new Float(1.929));
        english.put('b', new Float(1.492));
        english.put('v', new Float(0.978));
        english.put('k', new Float(0.772));
        english.put('j', new Float(0.153));
        english.put('x', new Float(0.150));
        english.put('q', new Float(0.095));
        english.put('z', new Float(0.074));
    }

    public static Map<Character, Float> characterFreqs (String input) {
        char[] characters = input.toCharArray();
        HashMap<Character, Float> freqs = new HashMap<Character, Float>();

        for (Character c : characters) {
            if (!freqs.containsKey(c))
                freqs.put(c, new Float(0.0));
            Float freq = freqs.get(c);
            freq++;
            freqs.put(c, freq);
        }

        for (Character c : freqs.keySet()) {
            Float freq = freqs.get(c);
            freq /= characters.length;
            freq *= 100;
            freqs.put(c, freq);
        }

        return freqs;
    }

    public static double freqScore(Map<Character, Float> freqs) {
        // scoring:
        //
        // total of the differences between the sample and english, per
        // letter, plus the total of 10x the percentages of non-letter
        // characters, except space.
        //
        // lower is better.

        double score = 0.0;
        for (Character letter : english.keySet()) {
            double freq = freqs.containsKey(letter) ? freqs.get(letter).doubleValue() : 0.0;
            score += java.lang.Math.abs(freq - english.get(letter).doubleValue());
        }

        for (Character letter : freqs.keySet()) {
            if (!english.containsKey(letter))
                score += 10 * freqs.get(letter);
        }

        return score;
    }
}
