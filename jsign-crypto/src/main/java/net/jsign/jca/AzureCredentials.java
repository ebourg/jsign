/*
 * Copyright 2026 Emmanuel Bourg
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Azure API credentials
 *
 * @since 8.0
 */
public class AzureCredentials {

    private String endpoint = "https://login.microsoftonline.com";

    /** The Microsoft Entra tenant ID */
    private String tenantId;

    /** The application ID registered in the tenant */
    private String clientId;

    /** The secret of the application */
    private String clientSecret;

    /** The access token */
    private String token;

    /**
     * Creates the Azure credentials from either an Azure API access token, for example one obtained with
     * the Azure CLI (<tt>az account get-access-token --resource https://vault.azure.net</tt>), or the
     * concatenated parameters (<tt>tenantId|clientId|clientSecret</tt>).
     *
     * @param credentials the Azure API access token, or <tt>tenantId|clientId|clientSecret</tt>
     * @throws IllegalArgumentException if the credentials are malformed
     */
    public AzureCredentials(String credentials) {
        String[] elements = credentials.split("\\|", 3);
        if (elements.length == 1) {
            token = credentials;
        } else if (elements.length == 3) {
            tenantId = elements[0];
            clientId = elements[1];
            clientSecret = elements[2];
        } else {
            throw new IllegalArgumentException("Invalid Azure credentials, <tenantId>|<clientId>|<clientSecret> expected");
        }
    }

    /**
     * Creates the Azure credentials from the specified parameters.
     *
     * @param tenantId     The Microsoft Entra tenant ID (<tt>AZURE_TENANT_ID</tt>)
     * @param clientId     The application ID registered in the tenant (<tt>AZURE_CLIENT_ID</tt>)
     * @param clientSecret The secret of the application (<tt>AZURE_CLIENT_SECRET</tt>)
     */
    public AzureCredentials(String tenantId, String clientId, String clientSecret) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    String getTenantId() {
        return tenantId;
    }

    String getClientId() {
        return clientId;
    }

    String getClientSecret() {
        return clientSecret;
    }

    /**
     * Returns the access token for the specified resource.
     *
     * @param resource the resource the access token is requested for (for example <tt>https://vault.azure.net</tt>)
     */
    public String getAccessToken(String resource) throws IOException {
        if (token == null) {
            Map<String, String> request = new LinkedHashMap<>();
            request.put("grant_type", "client_credentials");
            request.put("client_id", clientId);
            request.put("client_secret", clientSecret);
            request.put("scope", resource + "/.default");

            RESTClient client = new RESTClient(endpoint + "/" + tenantId)
                    .errorHandler(response -> response.get("error") + ": " + response.get("error_description"));
            Map<String, ?> response = client.post("/oauth2/v2.0/token", request);

            token = (String) response.get("access_token");
        }

        return token;
    }

    /**
     * Returns the credentials defined by the environment variables <tt>AZURE_TENANT_ID</tt>,
     * <tt>AZURE_CLIENT_ID</tt> and <tt>AZURE_CLIENT_SECRET</tt>.
     *
     * @throws IllegalArgumentException if one of the required variables is missing
     * @see <a href="https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential">EnvironmentCredential Class</a>
     */
    public static AzureCredentials getDefault() {
        List<String> missing = new ArrayList<>(Arrays.asList("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"));
        missing.removeIf(variable -> getenv(variable) != null);
        if (!missing.isEmpty()) {
            throw new IllegalArgumentException("Azure credentials are missing from the environment variables: " + String.join(", ", missing));
        }

        return new AzureCredentials(getenv("AZURE_TENANT_ID"), getenv("AZURE_CLIENT_ID"), getenv("AZURE_CLIENT_SECRET"));
    }

    static String getenv(String name) {
        return System.getenv(name);
    }
}
