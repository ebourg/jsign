/*
 * Copyright 2023 Emmanuel Bourg
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

import java.net.UnknownServiceException;

import org.junit.Test;
import org.mockito.MockedStatic;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class AmazonCredentialsTest {

    @Test
    public void testParseFull() {
        AmazonCredentials credentials = AmazonCredentials.parse("accessKey|secretKey|sessionToken");
        assertEquals("access key", "accessKey", credentials.getAccessKey());
        assertEquals("secret key", "secretKey", credentials.getSecretKey());
        assertEquals("session token", "sessionToken", credentials.getSessionToken());
    }

    @Test
    public void testParsePartial() {
        AmazonCredentials credentials = AmazonCredentials.parse("accessKey|secretKey");
        assertEquals("access key", "accessKey", credentials.getAccessKey());
        assertEquals("secret key", "secretKey", credentials.getSecretKey());
        assertNull("session token", credentials.getSessionToken());
    }

    @Test
    public void testParseIncomplete() {
        assertThrows(IllegalArgumentException.class, () -> AmazonCredentials.parse("accessKey"));
    }

    @Test
    public void testGetDefault() {
        assertThrows(UnknownServiceException.class, AmazonCredentials::getDefault);
    }

    @Test
    public void testGetDefaultFromEnvironment() throws Exception {
        try (MockedStatic<?> mock = mockStatic(AmazonCredentials.class, CALLS_REAL_METHODS)) {
            when(AmazonCredentials.getenv("AWS_ACCESS_KEY_ID")).thenReturn("accessKey");
            when(AmazonCredentials.getenv("AWS_SECRET_KEY")).thenReturn("secretKey");
            when(AmazonCredentials.getenv("AWS_SESSION_TOKEN")).thenReturn("sessionToken");

            AmazonCredentials credentials = AmazonCredentials.getDefault();
            assertNotNull("credentials", credentials);
            assertEquals("access key", "accessKey", credentials.getAccessKey());
            assertEquals("secret key", "secretKey", credentials.getSecretKey());
            assertEquals("session token", "sessionToken", credentials.getSessionToken());
        }

        try (MockedStatic<?> mock = mockStatic(AmazonCredentials.class, CALLS_REAL_METHODS)) {
            when(AmazonCredentials.getenv("AWS_ACCESS_KEY")).thenReturn("accessKey");
            when(AmazonCredentials.getenv("AWS_SECRET_ACCESS_KEY")).thenReturn("secretKey");
            when(AmazonCredentials.getenv("AWS_SESSION_TOKEN")).thenReturn(null);

            AmazonCredentials credentials = AmazonCredentials.getDefault();
            assertNotNull("credentials", credentials);
            assertEquals("access key", "accessKey", credentials.getAccessKey());
            assertEquals("secret key", "secretKey", credentials.getSecretKey());
            assertNull("session token", credentials.getSessionToken());
        }
    }
}
