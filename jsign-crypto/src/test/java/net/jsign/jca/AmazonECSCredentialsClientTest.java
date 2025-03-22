/*
 * Copyright 2025 Alejandro González
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

import java.io.IOException;
import java.net.URL;

import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.closeJadler;
import static net.jadler.Jadler.initJadler;
import static net.jadler.Jadler.onRequest;
import static net.jadler.Jadler.port;

public class AmazonECSCredentialsClientTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    @Test
    public void testUnreachable() throws Exception {
        AmazonECSCredentialsClient client = new AmazonECSCredentialsClient(
                new URL("http://localhost:31457")
        );

        assertThrows(IOException.class, client::getCredentials);
    }

    @Test
    public void testServerError() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/get-credentials")
                .havingQueryStringEqualTo("a=1")
                .respond()
                .withStatus(503);

        AmazonECSCredentialsClient client = new AmazonECSCredentialsClient(
                new URL("http://localhost:" + port() + "/get-credentials?a=1")
        );

        Exception e = assertThrows(IOException.class, client::getCredentials);
        assertTrue("message", e.getMessage().startsWith("Unexpected HTTP response code fetching AWS container credentials: 503"));
    }

    @Test
    public void testGetCredentials() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/get-credentials")
                .havingQueryStringEqualTo("a=1")
                .respond()
                .withStatus(200)
                .withBody("{"
                        + "\"AccessKeyId\" : \"accessKey\", "
                        + "\"SecretAccessKey\" : \"secretKey\", "
                        + "\"Token\" : \"sessionToken\""
                        + "}");

        AmazonECSCredentialsClient client = new AmazonECSCredentialsClient(
                new URL("http://localhost:" + port() + "/get-credentials?a=1")
        );

        AmazonCredentials credentials = client.getCredentials();
        assertNotNull("credentials", credentials);
        assertEquals("access key", "accessKey", credentials.getAccessKey());
        assertEquals("secret key", "secretKey", credentials.getSecretKey());
        assertEquals("session token", "sessionToken", credentials.getSessionToken());
    }
}
