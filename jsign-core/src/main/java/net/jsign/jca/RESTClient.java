/**
 * Copyright 2021 Emmanuel Bourg
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
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Consumer;

import com.cedarsoftware.util.io.JsonReader;
import org.apache.commons.io.IOUtils;

class RESTClient {

    /** Base URL of the REST service for relative resources */
    private final String endpoint;

    /** Callback setting the authentication headers for the request */
    private final Consumer<HttpURLConnection> authenticationHandler;

    RESTClient(String endpoint, Consumer<HttpURLConnection>  authenticationHeaderSupplier) {
        this.endpoint = endpoint;
        this.authenticationHandler = authenticationHeaderSupplier;
    }

    Map<String, ?> get(String resource) throws IOException {
        return query("GET", resource, null);
    }

    Map<String, ?> post(String resource, String body) throws IOException {
        return query("POST", resource, body);
    }

    private Map<String, ?> query(String method, String resource, String body) throws IOException {
        URL url = new URL(resource.startsWith("http") ? resource : endpoint + resource);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("User-Agent", "Jsign (https://ebourg.github.io/jsign/)");
        if (authenticationHandler != null) {
            authenticationHandler.accept(conn);
        }

        if (body != null) {
            byte[] data = body.getBytes(StandardCharsets.UTF_8);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Content-Length", String.valueOf(data.length));
            conn.getOutputStream().write(data);
        }

        int responseCode = conn.getResponseCode();
        String contentType = conn.getHeaderField("Content-Type");
        if (responseCode < 400) {
            String response = IOUtils.toString(conn.getInputStream(), StandardCharsets.UTF_8);

            return JsonReader.jsonToMaps(response);
        } else {
            String error = IOUtils.toString(conn.getErrorStream(), StandardCharsets.UTF_8);
            if (contentType != null && contentType.startsWith("application/json")) {
                throw new IOException(getErrorMessage(JsonReader.jsonToMaps(error)));
            } else {
                throw new IOException("HTTP Error " + responseCode + (conn.getResponseMessage() != null ? " - " + conn.getResponseMessage() : "") + " (" + url + ")");
            }
        }
    }

    private String getErrorMessage(Map<String, ?> response) {
        StringBuilder message = new StringBuilder();

        if (response.get("error") instanceof Map) {
            Map error = (Map) response.get("error");
            if (error.get("code") != null) {
                message.append(error.get("code"));
            }
            if (error.get("status") != null) {
                if (message.length() > 0) {
                    message.append(" - ");
                }
                message.append(error.get("status"));
            }
            if (error.get("message") != null) {
                if (message.length() > 0) {
                    message.append(": ");
                }
                message.append(error.get("message"));
            }
        } else {
            // error message from the CSC API
            String error = (String) response.get("error");
            String description = (String) response.get("error_description");
            message.append(error).append(": ").append(description);
        }
        return message.toString();
    }
}
