package com.cryptopals;

import com.cryptopals.random.MT19937;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 19/08/15.
 */
public class Set3Challenge21 {

    @Test
    public void getRandomNumbers() {
        MT19937 r = new MT19937(1);
        for (int i = 0; i < 20; i++) {
            System.out.println(r.nextInteger());
        }
    }
}
