/**
 * Copyright 2022 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.jca;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;

import org.junit.Test;

import static org.junit.Assert.*;

public class AmazonSigningServiceTest {

    @Test
    public void testSignRequestWithoutSessionToken() throws Exception {
        testSign(false);
    }

    @Test
    public void testSignRequestWithSessionToken() throws Exception {
        testSign(true);
    }

    public void testSign(boolean useSessionToken) throws Exception {
        String sessionToken = useSessionToken ? "sessionToken" : null;

        AmazonSigningService service = new AmazonSigningService("eu-west-3", "accessKey|secretKey" + (useSessionToken ? "|sessionToken" : ""), null);

        URL url = new URL("https://kms.eu-west-3.amazonaws.com");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("User-Agent", "Jsign (https://ebourg.github.io/jsign/)");
        conn.setRequestProperty("X-Amz-Target", "TrentService.ListKeys");
        conn.setRequestProperty("Content-Type", "application/x-amz-json-1.1");
        service.sign(conn, "accessKey", "secretKey", sessionToken, "{}".getBytes(), new Date(0));

        assertEquals("X-Amz-Date", "19700101T000000Z", conn.getRequestProperty("X-Amz-Date"));
        assertEquals("X-Amz-Security-Token", sessionToken, conn.getRequestProperty("X-Amz-Security-Token"));
        assertEquals("Authorization", "AWS4-HMAC-SHA256 Credential=accessKey/19700101/eu-west-3/kms/aws4_request, SignedHeaders=content-type;host;user-agent;x-amz-date;x-amz-target, Signature=6247e3c7f2e50e806e32843924b94c860b6a3721fd12f9b99d8d8d140795e4c5", getAuthorizationHeaderValue(conn));
    }

    private String getAuthorizationHeaderValue(HttpURLConnection conn) throws Exception {
        Field delegate = sun.net.www.protocol.https.HttpsURLConnectionImpl.class.getDeclaredField("delegate");
        Field requests = sun.net.www.protocol.http.HttpURLConnection.class.getDeclaredField("requests");
        AccessibleObject.setAccessible(new Field[]{delegate, requests}, true);
        sun.net.www.MessageHeader headers = (sun.net.www.MessageHeader) requests.get(delegate.get(conn));
        return headers.findValue("Authorization");
    }
}
