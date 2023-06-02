/**
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

import org.junit.Test;

import static org.junit.Assert.*;

public class AmazonCredentialsTest {

    @Test
    public void testParseFull() {
        AmazonCredentials credentials = AmazonCredentials.parse("accessKey|secretKey|sessionToken");
        assertEquals("accessKey", credentials.getAccessKey());
        assertEquals("secretKey", credentials.getSecretKey());
        assertEquals("sessionToken", credentials.getSessionToken());
    }

    @Test
    public void testParsePartial() {
        AmazonCredentials credentials = AmazonCredentials.parse("accessKey|secretKey");
        assertEquals("accessKey", credentials.getAccessKey());
        assertEquals("secretKey", credentials.getSecretKey());
        assertNull(credentials.getSessionToken());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseIncomplete() {
        AmazonCredentials.parse("accessKey");
    }
}
