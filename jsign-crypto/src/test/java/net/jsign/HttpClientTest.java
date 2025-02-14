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

package net.jsign;

import java.io.File;
import java.net.URL;

import org.junit.Test;

import static org.junit.Assert.*;

public class HttpClientTest {

    @Test
    public void testGetRequestHash() throws Exception {
        HttpClient client = new HttpClient(null, 0);

        assertEquals("66f8236952f2d7e255569c90c8446f3ea90249a2", client.getRequestHash(new URL("https://github.com/ebourg/jsign")));
        assertEquals("986f7df090d88f756295ac980bcb5c2ef0012155", client.getRequestHash(new URL("https://ebourg.github.io/jsign/")));
    }

    @Test
    public void testCache() throws Exception {
        File cachedir = new File("target/test-classes/cache/");
        File cachefile = new File(cachedir, "986f7df090d88f756295ac980bcb5c2ef0012155.cache");
        cachefile.delete();

        HttpClient client = new HttpClient(cachedir, 1000);

        URL url = new URL("https://ebourg.github.io/jsign/");
        assertFalse(cachefile.exists());
        assertNotNull(client.getInputStream(url));
        assertTrue(cachefile.exists());
        assertNotNull(client.getInputStream(url));
    }
}
