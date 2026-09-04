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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class AzureCredentialsTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    private AzureCredentials getCredentials() {
        AzureCredentials credentials = new AzureCredentials("00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000001", "secret");
        credentials.setEndpoint("http://localhost:" + port());
        return credentials;
    }

    @Test
    public void testGetAccessToken() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token")
                .havingHeaderEqualTo("Content-Type", "application/x-www-form-urlencoded")
                .havingBodyEqualTo("grant_type=client_credentials"
                        + "&client_id=00000000-0000-0000-0000-000000000001"
                        + "&client_secret=secret"
                        + "&scope=https%3A%2F%2Fvault.azure.net%2F.default")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody("{\"token_type\":\"Bearer\",\"expires_in\":3599,\"access_token\":\"token\"}");

        AzureCredentials credentials = getCredentials();

        String token = credentials.getAccessToken("https://vault.azure.net");
        assertEquals("access token", "token", token);

        token = credentials.getAccessToken("https://vault.azure.net");

        assertEquals("access token", "token", token);

        verifyThatRequest().havingMethodEqualTo("POST").receivedTimes(1);
    }

    @Test
    public void testGetAccessTokenError() {
        onRequest()
                .havingMethodEqualTo("POST")
                .respond()
                .withStatus(401)
                .withContentType("application/json")
                .withBody("{\"error\":\"invalid_client\",\"error_description\":\"AADSTS7000215: Invalid client secret provided.\"}");

        Exception e = assertThrows(IOException.class, () -> getCredentials().getAccessToken("https://vault.azure.net"));
        assertEquals("message", "invalid_client: AADSTS7000215: Invalid client secret provided.", e.getMessage());
    }

    @Test
    public void testGetAccessTokenFromConstructor() throws Exception {
        AzureCredentials credentials = new AzureCredentials("token");
        assertEquals("access token", "token", credentials.getAccessToken("https://vault.azure.net"));
        assertNull("tenant id", credentials.getTenantId());
        assertNull("client id", credentials.getClientId());
        assertNull("client secret", credentials.getClientSecret());
    }

    @Test
    public void testParseCredentials() {
        AzureCredentials credentials = new AzureCredentials("tenant|client|secret");
        assertEquals("tenant id", "tenant", credentials.getTenantId());
        assertEquals("client id", "client", credentials.getClientId());
        assertEquals("client secret", "secret", credentials.getClientSecret());
    }

    @Test
    public void testParseIncompleteCredentials() {
        Exception e = assertThrows(IllegalArgumentException.class, () -> new AzureCredentials("tenant|client"));
        assertEquals("message", "Invalid Azure credentials, <tenantId>|<clientId>|<clientSecret> expected", e.getMessage());
    }

    @Test
    public void testGetDefault() {
        try (MockedStatic<?> mock = mockStatic(AzureCredentials.class, CALLS_REAL_METHODS)) {
            when(AzureCredentials.getenv("AZURE_TENANT_ID")).thenReturn("tenant");
            when(AzureCredentials.getenv("AZURE_CLIENT_ID")).thenReturn("client");
            when(AzureCredentials.getenv("AZURE_CLIENT_SECRET")).thenReturn("secret");

            AzureCredentials credentials = AzureCredentials.getDefault();
            assertEquals("tenant id", "tenant", credentials.getTenantId());
            assertEquals("client id", "client", credentials.getClientId());
            assertEquals("client secret", "secret", credentials.getClientSecret());
        }
    }

    @Test
    public void testGetDefaultWithMissingVariables() {
        try (MockedStatic<?> mock = mockStatic(AzureCredentials.class, CALLS_REAL_METHODS)) {
            when(AzureCredentials.getenv("AZURE_TENANT_ID")).thenReturn("tenant");

            Exception e = assertThrows(IllegalArgumentException.class, AzureCredentials::getDefault);
            assertEquals("message", "Azure credentials are missing from the environment variables: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET", e.getMessage());
        }
    }
}
