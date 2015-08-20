package com.cryptopals;

import com.cryptopals.random.MT19937;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 20/08/15.
 */
public class Set3Challenge23 {

    @Test
    public void cloneState() {
        MT19937 r = new MT19937(1);

        int[] values = new int[624];
        int[] state = new int[624];

        for (int i = 0; i < 624; i++) {
            values[i] = r.nextInteger();
            state[i] = untemper(values[i]);
        }

        MT19937 r2 = new MT19937(1);
        r2.setState(state);

        int differences = 0;
        for (int i = 0; i < 100000; i++) {
            int source = r.nextInteger();
            int target = r2.nextInteger();
            System.out.println(source + " " + target + ((source != target) ? " <===" : ""));
            if (source != target) {
                differences++;
            }
        }
        assertEquals(0, differences);
    }

    private int untemper(int y) {
        y = unshiftxorRight(y, 18);
        y = unshiftxormaskLeft(y, 15, 0xEFC60000);
        y = unshiftxormaskLeft(y, 7, 0x9D2C5680);
        y = unshiftxorRight(y, 11);
        return y;
    }

    private int unshiftxorRight(int value, int shift) {
        int result = 0;

        for (int i = 0; i < 32; i += shift) {
            int mask = 0;
            for (int j = (31 - i); j >=0 && j > (31 - i - shift); j--) {
                mask += (1 << j);
            }
            int part = value & mask;
            value ^= part >>> shift;
            result |= part;
        }

        return result;
    }

    private int unshiftxormaskLeft(int value, int shift, int maskval) {
        int result = 0;

        for (int i = 0; i < 32; i += shift) {
            int mask = 0;
            for (int j = i; j < 32 && j < (i + shift); j++) {
                mask += (1 << j);
            }
            int part = value & mask;
            value ^= ((part << shift) & maskval);
            result |= part;
        }

        return result;
    }
}