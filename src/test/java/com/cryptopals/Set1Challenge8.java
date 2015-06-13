package com.cryptopals;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by candrews on 13/06/15.
 */
public class Set1Challenge8 {

    @Test
    public void detectEcb() throws Exception {
        ArrayList<String> lines = Utils.readLinesFromClasspath("set1challenge8.txt");
        HashMap<String, String> chunks = new HashMap<>();
        HashMap<String, Integer> ecbs = new HashMap<>();

        for (String line : lines) {
            CryptoBuffer block = CryptoBuffer.fromHex(line);
            for (CryptoBuffer chunk : block.chunked(16)) {
                if (chunks.containsKey(chunk.toHex())) {
                    ecbs.put(line, 1);
                }
                else {
                    chunks.put(chunk.toHex(), line);
                }
            }
        }
        assertEquals(1, ecbs.keySet().size());
        //System.out.println(ecbs.keySet());
    }
}
