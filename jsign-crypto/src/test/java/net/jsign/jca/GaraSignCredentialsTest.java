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

import java.io.FileReader;
import java.io.IOException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class GaraSignCredentialsTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    @Test
    public void testGetSessionToken() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .havingParameterEqualTo("api_version", "1.0")
                .havingParameterEqualTo("username", "ebourg")
                .havingParameterEqualTo("password", "123456")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/garasign-authenticate.json"));

        GaraSignCredentials credentials = new GaraSignCredentials("ebourg", "123456", null, null);
        String sessionToken = credentials.getSessionToken("http://localhost:" + port());

        assertEquals("session token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJrdG11c2VyIiwibmJmIjoxNTIyMjgzNzU1LCJleHAiOjE1MjIzNzAxNTUsImVuY3J5cHRlZF9jbGFpbXMiOiJyV1Q1TlljWi83TFV1eTB3YlFnbDR5K08zbXJtS3RrOGFtdjFVSnpOYy8vM0JvaVkrai9RS0lYYTdJSGRicWIxUTVCaWNIQ2VMYWJRQjhzMWQ3ZjJBZDNKeVR6dlliS1gzVGloUThmY3RyZWRyQ21sTFZ2dDZMRFlrZ2IxbURibWVuQ1Z2VFNKbnlXWEplRzRPMGJUUXQwN1RqTHVRdGhPendQR0xXSGFhT0U1cWNSZUUzVjMzb0U0RzJ1R2duR25tSFJNZVFzUTgxQXU3bGp1c2FDR1J6enpwaTFhZmxBdHRCcjNsbThWYmdrV0VWQ3ZDNndjTlNHZXA3YzJnNG0yQzI2MzhzMml2K2hLOTFzPSJ9.kZ7ab16YLhDioc9BE0Xha9QgELXbU2GBze2x7XXALXw", sessionToken);
    }

    @Test
    public void testGetSessionTokenFailed() {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody("{\"requestId\": \"auth\", \"status\": \"FAILED\", \"message\": \"Error authenticating user\"}");

        GaraSignCredentials credentials = new GaraSignCredentials("ebourg", "123456", null, null);

        Exception e = assertThrows(IOException.class, () -> credentials.getSessionToken("http://localhost:" + port()));
        assertEquals("message", "Failed to authenticate with GaraSign: Error authenticating user", e.getMessage());
    }
}
