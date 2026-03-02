/*
 * Copyright 2026 Emmanuel Bourg and contributors
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

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.List;

import org.junit.Test;

import static org.junit.Assert.*;

public class JsignProxySelectorTest {

    @Test
    public void testHttpProxy() throws Exception {
        JsignProxySelector selector = new JsignProxySelector("http://example.com:1080");

        List<Proxy> proxies = selector.select(new URI("http://example.com/resource"));
        assertNotNull("null proxies", proxies);
        assertEquals("number of proxies", 1, proxies.size());
        assertEquals("proxy type", Proxy.Type.HTTP, proxies.get(0).type());
        assertEquals("proxy host", "example.com", ((InetSocketAddress) proxies.get(0).address()).getHostName());
        assertEquals("proxy port", 1080, ((InetSocketAddress) proxies.get(0).address()).getPort());
    }

    @Test
    public void testSocksProxy() throws Exception {
        JsignProxySelector selector = new JsignProxySelector("example.com");

        List<Proxy> proxies = selector.select(new URI("socket://example.com/resource"));
        assertNotNull("null proxies", proxies);
        assertEquals("number of proxies", 1, proxies.size());
        assertEquals("proxy type", Proxy.Type.SOCKS, proxies.get(0).type());
        assertEquals("proxy host", "example.com", ((InetSocketAddress) proxies.get(0).address()).getHostName());
        assertEquals("proxy port", 80, ((InetSocketAddress) proxies.get(0).address()).getPort());
    }
}
