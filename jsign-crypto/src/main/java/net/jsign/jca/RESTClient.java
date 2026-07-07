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
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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

    /** Number of attempts for a request */
    private int retries = 5;

    /** Pause between retries in milliseconds */
    private int retryWait = 1000;

    /** Connect timeout in milliseconds */
    private int connectTimeout = 30000;

    /** Read timeout in milliseconds */
    private int readTimeout = 30000;

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

    public RESTClient retries(int retries) {
        this.retries = retries;
        return this;
    }

    public RESTClient retryWait(int retryWait) {
        this.retryWait = retryWait;
        return this;
    }

    public RESTClient connectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
        return this;
    }

    public RESTClient readTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
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
        URL url = new URL(resource.startsWith("http") ? resource : endpoint + resource);
        log.finest(method + " " + url);
        HttpURLConnection c = open(url, conn -> {
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);
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
                conn.setRequestProperty("Accept", "*/*");
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
        });

        HttpURLConnection conn = c;
        int responseCode = conn.getResponseCode();
        String contentType = conn.getHeaderField("Content-Type");
        log.finest("Response Code: " + responseCode);
        log.finest("Content-Type: " + contentType);

        if (responseCode < 400) {
            byte[] binaryResponse = IOUtils.toByteArray(conn.getInputStream());
            String response = new String(binaryResponse, StandardCharsets.UTF_8);
            log.finest("Content-Length: " + binaryResponse.length);
            log.finest("Content:\n" + response);
            log.finest("");

            Object value = JsonReader.jsonToJava(response);
            if (value instanceof Map) {
                return (Map) value;
            } else if (value instanceof Object[]) {
                Map<String, Object> map = new HashMap<>();
                map.put("result", value);
                return map;
            } else {
                Map<String, Object> map = new HashMap<>();
                map.put("result", response);
                return map;  
            }
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

    /**
     * Opens a connection to the specified URL and makes several attempts if a timeout occurs.
     * The provided configurator is used to set up the connection before making the request.
     */
    private HttpURLConnection open(URL url, HttpURLConnectionHandler configurator) throws IOException {
        boolean retry = true;
        int attempt = 1;

        HttpURLConnection conn = null;

        while (retry) {
            try {
                conn = (HttpURLConnection) url.openConnection();
                configurator.handle(conn);

                conn.getResponseCode();
                retry = false;
            } catch (SocketTimeoutException e) {
                if (attempt++ < retries) {
                    try {
                        Thread.sleep(retryWait);
                        log.fine("Connection to " + url + " timed out, attempt " + attempt + " of " + retries);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                } else {
                    throw (IOException) new SocketTimeoutException("Unable to connect to " + url + " after " + retries + " attempts").initCause(e);
                }
            }
        }

        return conn;
    }

    private interface HttpURLConnectionHandler {
        void handle(HttpURLConnection conn) throws IOException;
    }
}
