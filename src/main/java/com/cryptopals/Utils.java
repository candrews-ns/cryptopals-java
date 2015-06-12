package com.cryptopals;

import java.io.BufferedReader;
import java.io.IOError;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;

import static org.junit.Assert.fail;

/**
 * Created by candrews on 12/06/15.
 */
public class Utils {

    public static ArrayList<String> readFromClasspath(String filename) throws Exception {
        InputStream in = Utils.class.getResourceAsStream(filename);
        if (in == null)
            throw new Exception("can't open " + filename);

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(in));
        String line;
        ArrayList<String> lines = new ArrayList<String>();

        while ((line = bufferedReader.readLine()) != null) {
            lines.add(line);
        }

        return lines;
    }
}
