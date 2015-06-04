package com.cryptopals;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.util.Base64;

/**
 * Created by candrews on 04/06/15.
 */
public class Encoding {

    static byte[] decodeBase64(String base64text) {
        return Base64.getDecoder().decode(base64text);
    }

    static String encodeBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    static byte[] decodeHex(String hextext) throws DecoderException {
        return Hex.decodeHex(hextext.toCharArray());
    }

    static String encodeHex(byte[] data) {
        return Hex.encodeHexString(data);
    }
 }
