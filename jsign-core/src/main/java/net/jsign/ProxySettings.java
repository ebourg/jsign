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

import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.ProxySelector;

/**
 * Proxy settings.
 *
 * @author Emmanuel Bourg
 * @since 7.5
 */
class ProxySettings {

    /** The url of the proxy (either as hostname:port or http[s]://hostname:port) */
    String url;

    /** The username for the proxy authentication */
    String username;

    /** The password for the proxy authentication */
    String password;

    /**
     * Initializes the proxy.
     */
    public void initializeProxy() {
        // Do nothing if there is no proxy url.
        if (url != null && !url.trim().isEmpty()) {
            ProxySelector.setDefault(new JsignProxySelector(this));

            if (username != null && !username.isEmpty() && password != null) {
                Authenticator.setDefault(new Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password.toCharArray());
                    }
                });
            }
        }
    }
}
