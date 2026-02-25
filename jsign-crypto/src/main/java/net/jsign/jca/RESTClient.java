/*
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
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.cedarsoftware.util.io.JsonReader;
import org.apache.commons.io.IOUtils;

class RESTClient {

    private final Logger log = Logger.getLogger(getClass().getName());

    /** Base URL of the REST service for relative resources */
    private final String endpoint;

    /** Callback setting the authentication headers for the request */
    private BiConsumer<HttpURLConnection, byte[]> authenticationHandler;

    /** Callback building an error message from the JSON formatted error response */
    private Function<Map<String, ?>, String> errorHandler;

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

    public RESTClient errorHandler(Function<Map<String, ?>, String> errorHandler) {
        this.errorHandler = errorHandler;
        return this;
    }

    public Map<String, ?> get(String resource) throws IOException {
        return query("GET", resource, null, null);
    }

    public RESTResponse getResponse(String resource) throws IOException {
        return request("GET", resource, null, null);
    }

    public Map<String, ?> post(String resource, String body) throws IOException {
        return query("POST", resource, body, null);
    }

    public Map<String, ?> post(String resource, String body, Map<String, String> headers) throws IOException {
        return query("POST", resource, body, headers);
    }

    public RESTResponse postResponse(String resource, String body) throws IOException {
        return request("POST", resource, body, null);
    }

    public RESTResponse postResponse(String resource, String body, Map<String, String> headers) throws IOException {
        return request("POST", resource, body, headers);
    }

    public Map<String, ?> post(String resource, Map<String, String> params) throws IOException {
        return post(resource, params, false);
    }

    public Map<String, ?> post(String resource, Map<String, ?> params, boolean multipart) throws IOException {
        Map<String, String> headers = new HashMap<>();
        StringBuilder body = new StringBuilder();

        if (multipart) {
            String boundary = "------------------------" + Long.toHexString(new Random().nextLong());
            headers.put("Content-Type", "multipart/form-data; boundary=" + boundary);

            for (String name : params.keySet()) {
                Object value = params.get(name);

                body.append("--" + boundary + "\r\n");
                if (value instanceof byte[]) {
                    body.append("Content-Type: application/octet-stream" + "\r\n");
                    body.append("Content-Disposition: form-data; name=\"" + name + '"' + "; filename=\"" + name + ".data\"\r\n");
                    body.append("\r\n");
                    body.append(new String((byte[]) value, StandardCharsets.UTF_8));
                } else {
                    body.append("Content-Disposition: form-data; name=\"" + name + '"' + "\r\n");
                    body.append("\r\n");
                    body.append(params.get(name));
                }
                body.append("\r\n");
            }

            body.append("--" + boundary + "--");

        } else {
            headers.put("Content-Type", "application/x-www-form-urlencoded");

            for (Map.Entry<String, ?> param : params.entrySet()) {
                if (body.length() > 0) {
                    body.append('&');
                }
                body.append(param.getKey()).append('=').append(URLEncoder.encode(param.getValue().toString(), "UTF-8"));
            }
        }

        return post(resource, body.toString(), headers);
    }

    private Map<String, ?> query(String method, String resource, String body, Map<String, String> headers) throws IOException {
        return request(method, resource, body, headers).getBody();
    }

    private RESTResponse request(String method, String resource, String body, Map<String, String> headers) throws IOException {
        URL url = new URL(resource.startsWith("http") ? resource : endpoint + resource);
        log.finest(method + " " + url);
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

        if (log.isLoggable(Level.FINEST)) {
            for (String requestHeader : conn.getRequestProperties().keySet()) {
                List<String> values = conn.getRequestProperties().get(requestHeader);
                log.finest(requestHeader + ": " + (values.size() == 1 ? values.get(0) : values));
            }
        }

        if (body != null) {
            log.finest("Content:\n" + body);
            conn.setDoOutput(true);
            conn.getOutputStream().write(data);
        }
        log.finest("");

        int responseCode = conn.getResponseCode();
        String contentType = conn.getHeaderField("Content-Type");
        log.finest("Response Code: " + responseCode);
        log.finest("Content-Type: " + contentType);

        if (responseCode < 400) {
            InputStream input = conn.getInputStream();
            byte[] binaryResponse = input != null ? IOUtils.toByteArray(input) : new byte[0];
            String response = new String(binaryResponse, StandardCharsets.UTF_8);
            log.finest("Content-Length: " + binaryResponse.length);
            log.finest("Content:\n" + response);
            log.finest("");

            Map<String, ?> responseBody = Collections.emptyMap();
            if (!response.trim().isEmpty()) {
                Object value = JsonReader.jsonToJava(response);
                if (value instanceof Map) {
                    responseBody = (Map) value;
                } else {
                    Map<String, Object> map = new HashMap<>();
                    map.put("result", value);
                    responseBody = map;
                }
            }

            return new RESTResponse(responseCode, conn.getHeaderFields(), responseBody, binaryResponse);
        } else {
            String error = conn.getErrorStream() != null ? IOUtils.toString(conn.getErrorStream(), StandardCharsets.UTF_8) : "";
            if (conn.getErrorStream() != null) {
                log.finest("Error:\n" + error);
            }
            if (contentType != null && (contentType.startsWith("application/json") || contentType.startsWith("application/x-amz-json-1.1"))) {
                throw new IOException(errorHandler != null ? errorHandler.apply(JsonReader.jsonToMaps(error)) : error);
            } else {
                throw new IOException("HTTP Error " + responseCode + (conn.getResponseMessage() != null ? " - " + conn.getResponseMessage() : "") + " (" + url + ")");
            }
        }
    }

    static class RESTResponse {
        private final int statusCode;
        private final Map<String, List<String>> headers;
        private final Map<String, ?> body;
        private final byte[] rawBody;

        RESTResponse(int statusCode, Map<String, List<String>> headers, Map<String, ?> body, byte[] rawBody) {
            this.statusCode = statusCode;
            this.headers = headers != null ? headers : Collections.emptyMap();
            this.body = body != null ? body : Collections.emptyMap();
            this.rawBody = rawBody != null ? rawBody : new byte[0];
        }

        public int getStatusCode() {
            return statusCode;
        }

        public Map<String, List<String>> getHeaders() {
            return headers;
        }

        public Map<String, ?> getBody() {
            return body;
        }

        public byte[] getRawBody() {
            return rawBody;
        }

        public String getHeader(String name) {
            if (name == null) {
                return null;
            }
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                    List<String> values = entry.getValue();
                    return values != null && !values.isEmpty() ? values.get(0) : null;
                }
            }
            return null;
        }
    }
}
