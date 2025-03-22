/*
 * Copyright 2025 Alejandro González
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
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownServiceException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import com.cedarsoftware.util.io.JsonIoException;
import com.cedarsoftware.util.io.JsonReader;

/**
 * Client to query the Elastic Container Service (ECS) credential metadata
 * endpoint for containers running in AWS.
 *
 * @since 7.2
 * @see
 * <a href="https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html">Using
 * the Amazon ECS container credentials provider</a>
 * @see
 * <a href="https://github.com/aws/aws-sdk-java-v2/blob/master/core/auth/src/main/java/software/amazon/awssdk/auth/credentials/ContainerCredentialsProvider.java">ContainerCredentialsProvider</a>
 */
class AmazonECSCredentialsClient {

    private static final URL DEFAULT_AWS_CONTAINER_SERVICE_ENDPOINT;

    private final URL endpoint;

    static {
        try {
            DEFAULT_AWS_CONTAINER_SERVICE_ENDPOINT = new URL("http://169.254.170.2");
        } catch (MalformedURLException e) {
            throw new AssertionError("Invalid default URI for AWS container credential metadata endpoint", e);
        }
    }

    /**
     * Creates a new client to query the ECS credential metadata endpoint, using
     * the endpoint URL provided by the environment variables
     * {@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI} or
     * {@code AWS_CONTAINER_CREDENTIALS_FULL_URI}.
     *
     * @throws UnknownServiceException If no valid ECS endpoint URL is
     * available.
     */
    AmazonECSCredentialsClient() throws UnknownServiceException {
        this(defaultCredentialsUrl());
    }

    /**
     * Creates a new client to query the ECS credential metadata endpoint, using
     * the specified endpoint URL.
     *
     * @param endpoint The URL of the ECS credential metadata endpoint.
     * @throws IllegalArgumentException If the endpoint URL is null or has an
     * unexpected protocol.
     */
    AmazonECSCredentialsClient(URL endpoint) {
        if (endpoint == null || (!"http".equals(endpoint.getProtocol()) && !"https".equals(endpoint.getProtocol()))) {
            throw new IllegalArgumentException(
                    "Null endpoint or unexpected protocol for AWS container credential metadata endpoint: " + endpoint
            );
        }

        this.endpoint = endpoint;
    }

    /**
     * Queries the ECS credential metadata endpoint to obtain the credentials
     * for the container.
     */
    public AmazonCredentials getCredentials() throws IOException {
        HttpURLConnection connection = (HttpURLConnection) this.endpoint.openConnection();
        connection.setConnectTimeout(3000);
        connection.setReadTimeout(3000);

        String authToken = System.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN");
        if (authToken == null) {
            String authTokenFile = System.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
            if (authTokenFile != null) {
                authToken = new String(Files.readAllBytes(Paths.get(authTokenFile)), StandardCharsets.UTF_8);
            }
        }
        if (authToken != null) {
            connection.addRequestProperty("Authorization", authToken);
        }

        int responseCode = connection.getResponseCode();
        if (responseCode != 200) {
            String responseMessage = connection.getResponseMessage();
            throw new IOException(String.format(
                    "Unexpected HTTP response code fetching AWS container credentials: %d (%s)",
                    responseCode, responseMessage == null ? "No message" : responseMessage
            ));
        }

        try {
            Map<String, String> json = JsonReader.jsonToMaps(connection.getInputStream(), new HashMap<>());
            return new AmazonCredentials(json.get("AccessKeyId"), json.get("SecretAccessKey"), json.get("Token"));
        } catch (JsonIoException e) {
            throw new IOException("Error parsing JSON response from AWS container credentials endpoint", e);
        }
    }

    /**
     * Returns the URL of the ECS credential metadata endpoint, using the
     * environment variables {@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI} or
     * {@code AWS_CONTAINER_CREDENTIALS_FULL_URI}.
     *
     * @throws UnknownServiceException If no valid ECS endpoint URL is
     * available.
     */
    private static URL defaultCredentialsUrl() throws UnknownServiceException {
        String relativeUri, fullUri;
        URL endpoint;

        if ((relativeUri = System.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")) != null) {
            try {
                endpoint = new URL(DEFAULT_AWS_CONTAINER_SERVICE_ENDPOINT, relativeUri);
            } catch (MalformedURLException e) {
                throw new UnknownServiceException("Invalid relative URI for AWS container credential metadata endpoint: " + relativeUri);
            }
        } else if ((fullUri = System.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")) != null) {
            try {
                endpoint = new URL(fullUri);
            } catch (MalformedURLException e) {
                throw new UnknownServiceException("Invalid full URI for AWS container credential metadata endpoint: " + fullUri);
            }
        } else {
            throw new UnknownServiceException("No AWS container credential metadata endpoint URIs available");
        }

        return endpoint;
    }
}
