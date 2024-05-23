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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import com.cedarsoftware.util.io.JsonReader;
import com.cedarsoftware.util.io.JsonWriter;
import org.apache.commons.io.IOUtils;

class RESTClient {

    /** Base URL of the REST service for relative resources */
    private final String endpoint;

    /** Callback setting the authentication headers for the request */
    private BiConsumer<HttpURLConnection, byte[]> authenticationHandler;

    private boolean debug;

    public RESTClient(String endpoint) {
        this.endpoint = endpoint;
    }

    public RESTClient authentication(Consumer<HttpURLConnection>  authenticationHeaderSupplier) {
        this.authenticationHandler = (conn, data) -> authenticationHeaderSupplier.accept(conn);
        return this;
    }

    public RESTClient authentication(BiConsumer<HttpURLConnection, byte[]>  authenticationHeaderSupplier) {
        this.authenticationHandler = authenticationHeaderSupplier;
        return this;
    }

    public RESTClient debug(boolean debug) {
        this.debug = debug;
        return this;
    }

    public Map<String, ?> get(String resource) throws IOException {
        return query("GET", resource, null, null);
    }

    public Map<String, ?> post(String resource, String body) throws IOException {
        return query("POST", resource, body, null);
    }

    public Map<String, ?> post(String resource, String body, Map<String, String> headers) throws IOException {
        return query("POST", resource, body, headers);
    }

    private Map<String, ?> query(String method, String resource, String body, Map<String, String> headers) throws IOException {
        URL url = new URL(resource.startsWith("http") ? resource : endpoint + resource);
        if (debug) {
            System.out.println(method + " " + url);
        }
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        String userAgent = System.getProperty("http.agent");
        conn.setRequestProperty("User-Agent", "Jsign (https://ebourg.github.io/jsign/)" + (userAgent != null ? " " + userAgent : ""));
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                conn.setRequestProperty(header.getKey(), header.getValue());
            }
        }

        byte[] data = body != null ? body.getBytes(StandardCharsets.UTF_8) : null;
        if (authenticationHandler != null) {
            authenticationHandler.accept(conn, data);
        }
        if (body != null) {
            if (!conn.getRequestProperties().containsKey("Content-Type")) {
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            }
            conn.setRequestProperty("Content-Length", String.valueOf(data.length));
        }

        if (debug) {
            for (String requestHeader : conn.getRequestProperties().keySet()) {
                List<String> values = conn.getRequestProperties().get(requestHeader);
                System.out.println(requestHeader + ": " + (values.size() == 1 ? values.get(0) : values));
            }
        }

        if (body != null) {
            if (debug) {
                System.out.println("Content:\n" + body);
            }
            conn.setDoOutput(true);
            conn.getOutputStream().write(data);
        }
        if (debug) {
            System.out.println();
        }

        int responseCode = conn.getResponseCode();
        String contentType = conn.getHeaderField("Content-Type");
        if (debug) {
            System.out.println("Response Code: " + responseCode);
            System.out.println("Content-Type: " + contentType);
        }

        if (responseCode < 400) {
            byte[] binaryResponse = IOUtils.toByteArray(conn.getInputStream());
            String response = new String(binaryResponse, StandardCharsets.UTF_8);
            if (debug) {
                System.out.println("Content-Length: " + binaryResponse.length);
                System.out.println("Content:\n" + response);
                System.out.println();
            }

            Object value = JsonReader.jsonToJava(response);
            if (value instanceof Map) {
                return (Map) value;
            } else {
                Map<String, Object> map = new HashMap<>();
                map.put("result", value);
                return map;
            }
        } else {
            String error = conn.getErrorStream() != null ? IOUtils.toString(conn.getErrorStream(), StandardCharsets.UTF_8) : "";
            if (debug && conn.getErrorStream() != null) {
                System.out.println("Error:\n" + error);
            }
            if (contentType != null && (contentType.startsWith("application/json") || contentType.startsWith("application/x-amz-json-1.1"))) {
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
        } else if (response.containsKey("__type")) {
            // error from the AWS API
            String error = (String) response.get("__type");
            String description = (String) response.get("message");
            message.append(error).append(": ").append(description);
        } else if (response.containsKey("title") && response.containsKey("errors")) {
            // error from Azure Code Signing API
            String errors = JsonWriter.objectToJson(response.get("errors"));
            message.append(response.get("status")).append(" - ").append(response.get("title")).append(": ").append(errors);
        } else if (response.containsKey("code") && response.containsKey("message")) {
            // error from OCI API
            message.append(response.get("code")).append(": ").append(response.get("message"));
        } else {
            // error message from the CSC API
            String error = (String) response.get("error");
            String description = (String) response.get("error_description");
            message.append(error).append(": ").append(description);
        }
        return message.toString();
    }
}
