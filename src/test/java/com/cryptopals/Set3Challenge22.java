package com.cryptopals;

import com.cryptopals.random.MT19937;
import org.junit.Test;

/**
 * Created by candrews on 20/08/15.
 */
public class Set3Challenge22 {

    @Test
    public void crackSeed() {
        int time_t = (int) (System.currentTimeMillis() / 1000);
        MT19937 r = new MT19937(time_t);

        int rand = r.nextInteger();

        for (int seed = (time_t + 1000); seed > 0; seed--) {
            r.seed(seed);
            if (r.nextInteger() == rand) {
                System.out.println("seed seems to be: " + seed + " (and actually was: " + time_t + ")");
                break;
            }
        }
    }
}
