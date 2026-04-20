/*
 * Copyright 2026 Emmanuel Bourg
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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class CodeSignSecureCredentialsTest {

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
                .havingPathEqualTo("/api/auth/GetLoginToken/")
                .havingHeaderEqualTo("Accept", "*/*")
                .havingBodyEqualTo("{\"user\":\"guest@encryptionconsulting.com\",\"code\":\"secret\",\"identityType\":1}")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-logintoken.json"));

        CodeSignSecureCredentials credentials = new CodeSignSecureCredentials("guest@encryptionconsulting.com", "secret", null, null);
        String token = credentials.getToken("http://localhost:" + port());

        assertEquals("token", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI3MyIsInVzZXJuYW1lIjoiR3Vlc3QtRW1tYW51ZWxAZW5jcnlwdGlvbmNvbnN1bHRpbmcuY29tIiwiZXhwIjoxNzc3NjI2NjQxfQ.C-6KLQCHCqvlEowI6SZOp6Jpk6vdQFHayMBFitdNvY0", token);
    }
}
