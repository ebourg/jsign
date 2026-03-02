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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import static java.net.Proxy.Type.*;

/**
 * Proxy selector for Jsign.
 *
 * @author Emmanuel Bourg
 */
class JsignProxySelector extends ProxySelector {

    private final Logger log = Logger.getLogger(getClass().getName());

    /** The address of the proxy server */
    private final InetSocketAddress address;

    /**
     * Creates a new proxy selector for the specified proxy URL.
     *
     * @param proxyUrl the url of the proxy (either as hostname:port or http[s]://hostname:port)
     */
    public JsignProxySelector(String proxyUrl) {
        if (!proxyUrl.trim().startsWith("http")) {
            proxyUrl = "http://" + proxyUrl.trim();
        }
        URI uri = URI.create(proxyUrl);
        int port = uri.getPort() < 0 ? 80 : uri.getPort();

        address = new InetSocketAddress(uri.getHost(), port);
    }

    @Override
    public List<Proxy> select(URI uri) {
        Proxy proxy = new Proxy(uri.getScheme().equals("socket") ? SOCKS : HTTP, address);

        log.fine("Proxy selected for " + uri + " : " + proxy);
        return Collections.singletonList(proxy);
    }

    @Override
    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
    }
}
