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
import java.net.SocketTimeoutException;
import java.util.Map;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.Assert.*;

public class RESTClientTest {

    private WireMockServer wireMockServer;

    @Before
    public void setUp() {
        wireMockServer = new WireMockServer(wireMockConfig().dynamicPort());
        wireMockServer.start();
    }

    @After
    public void tearDown() {
        wireMockServer.stop();
    }

    @Test
    public void testRetryOnTimeout() {
        wireMockServer.stubFor(get(urlEqualTo("/test"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withFixedDelay(1000)));

        RESTClient client = new RESTClient("http://localhost:" + wireMockServer.port())
                .readTimeout(100)
                .retries(3)
                .retryPause(10);

        assertThrows(SocketTimeoutException.class, () -> client.get("/test"));
        wireMockServer.verify(3, getRequestedFor(urlEqualTo("/test")));
    }

    @Test
    public void testRetryEventuallySucceeds() throws Exception {
        wireMockServer.stubFor(get(urlEqualTo("/test")).inScenario("Retry Scenario")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse()
                        .withStatus(200)
                        .withFixedDelay(500))
                .willSetStateTo("Succeeded"));

        wireMockServer.stubFor(get(urlEqualTo("/test")).inScenario("Retry Scenario")
                .whenScenarioStateIs("Succeeded")
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"status\":\"ok\"}")));

        RESTClient client = new RESTClient("http://localhost:" + wireMockServer.port())
                .readTimeout(200)
                .retries(3)
                .retryPause(400);

        Map<String, ?> response = client.get("/test");
        assertEquals("ok", response.get("status"));
        wireMockServer.verify(2, getRequestedFor(urlEqualTo("/test")));
    }

    @Test
    public void testNoRetryOnOtherException() {
        wireMockServer.stubFor(get(urlEqualTo("/test"))
                .willReturn(aResponse()
                        .withStatus(404)));

        RESTClient client = new RESTClient("http://localhost:" + wireMockServer.port())
                .retries(3)
                .retryPause(10);

        assertThrows(IOException.class, () -> client.get("/test"));
        wireMockServer.verify(1, getRequestedFor(urlEqualTo("/test")));
    }
}
