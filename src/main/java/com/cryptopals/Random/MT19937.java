package com.cryptopals.random;

/**
 * Created by candrews on 19/08/15.
 */
public class MT19937 {

    private int[] mt;
    private int index;

    public MT19937(int seed) {
        this.mt = new int[624];
        this.index = 0;
        seed(seed);
    }

    public void seed(int seed) {
        index = 0;
        mt[0] = seed;
        for (int i = 1; i <= 623; i++) {
            mt[i] = 0xffffffff & (0x6C078965 * (mt[i - 1] ^ (mt[i - 1] >>> 30)) + i);
        }
    }

    public int nextInteger() {
        if (index == 0) {
            generate();
        }

        int y = mt[index];

        y = y ^ (y >>> 11);
        y = y ^ ((y << 7) & 0x9D2C5680);
        y = y ^ ((y << 15) & 0xEFC60000);
        y = y ^ (y >>> 18);

        index = (index + 1) % 624;
        return y;
    }

    public void setState(int[] state) {
        this.mt = state;
    }

    private void generate() {
        for (int i = 1; i <= 623; i++) {
            int y = (mt[i] & 0x80000000) + (mt[(i + 1) % 624] & 0x7fffffff);
            mt[i] = mt[(i + 397) % 624] ^ (y >>> 1);
            if ((y % 2) != 0) {
                mt[i] = mt[i] ^ 0x9908B0DF;
            }
        }
    }
}
