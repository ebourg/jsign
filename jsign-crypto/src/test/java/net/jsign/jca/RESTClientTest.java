/*
 * Copyright 2024 Emmanuel Bourg
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
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class RESTClientTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    @Test
    public void testRetryOnTimeout() throws Exception {
        AtomicInteger attempts = new AtomicInteger(0);
        RESTClient client = new RESTClient("http://localhost:" + port()) {
            @Override
            protected HttpURLConnection openConnection(URL url) throws IOException {
                attempts.incrementAndGet();
                throw new SocketTimeoutException("timeout");
            }

            @Override
            void sleep(long millis) {
                // don't sleep in tests
            }
        };

        assertThrows(SocketTimeoutException.class, () -> client.get("/test"));
        assertEquals("attempts", 3, attempts.get());
    }

    @Test
    public void testRetryEventuallySucceeds() throws Exception {
        AtomicInteger attempts = new AtomicInteger(0);

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/test")
                .respond()
                .withStatus(200)
                .withBody("{\"status\":\"ok\"}");

        RESTClient client = new RESTClient("http://localhost:" + port()) {
            @Override
            protected HttpURLConnection openConnection(URL url) throws IOException {
                if (attempts.incrementAndGet() < 3) {
                    throw new SocketTimeoutException("timeout");
                }
                return super.openConnection(url);
            }

            @Override
            void sleep(long millis) {
                // don't sleep in tests
            }
        };

        Map<String, ?> response = client.get("/test");
        assertEquals("attempts", 3, attempts.get());
        assertEquals("ok", response.get("status"));
    }

    @Test
    public void testNoRetryOnOtherException() throws Exception {
        AtomicInteger attempts = new AtomicInteger(0);
        RESTClient client = new RESTClient("http://localhost:" + port()) {
            @Override
            protected HttpURLConnection openConnection(URL url) throws IOException {
                attempts.incrementAndGet();
                throw new IOException("error");
            }

            @Override
            void sleep(long millis) {
                // don't sleep in tests
            }
        };

        assertThrows(IOException.class, () -> client.get("/test"));
        assertEquals("attempts", 1, attempts.get());
    }
}
