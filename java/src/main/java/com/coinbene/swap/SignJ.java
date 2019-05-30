package com.coinbene.swap;

import org.apache.commons.codec.digest.HmacUtils;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.TreeMap;

public class SignJ {

    private final static DateTimeFormatter utcFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

    private String secretKey;
    private String apiKey;

    public SignJ(String apiKey, String secretKey) {
        this.apiKey = apiKey;
        this.secretKey = secretKey;
    }


    private TreeMap<String, String> sign(String method, String requestUrl, String body) {
        String timestamp = utcFormatter.format(ZonedDateTime.now(ZoneOffset.UTC));
        String text = timestamp + method.toUpperCase() + requestUrl + (body==null? "" : body);
        byte[] bytes = HmacUtils.hmacSha256(secretKey, text);
        String encryptText = byteArr2String(bytes);

        TreeMap<String, String> param = new TreeMap<>();
        param.put("ACCESS-KEY", apiKey);
        param.put("ACCESS-SIGN", encryptText);
        param.put("ACCESS-TIMESTAMP", timestamp);

        return param;
    }


    private static String byteArr2String(byte[] bytes) {
        StringBuffer buffer = new StringBuffer();
        for (byte b : bytes) {
            Integer a = (b & 0xff);
            String s = a.toString(16);
            if(s.length() < 2) {
                s = '0'+s;
            }
            buffer.append(s);
        }
        return buffer.toString();
    }
}
