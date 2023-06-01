/**
 * Copyright 2023 Vincent Malmedy
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

import org.apache.commons.io.IOUtils;

import com.cedarsoftware.util.io.JsonReader;

/**
 * Client to query the Instance MetaData Service (IMDS) v2 from AWS EC2 instances.
 * 
 * @since 5.0
 * @see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html">Retrieve instance metadata</a>
 * @see <a href="https://github.com/aws/aws-sdk-java-v2/blob/master/core/auth/src/main/java/software/amazon/awssdk/auth/credentials/InstanceProfileCredentialsProvider.java">InstanceProfileCredentialsProvider</a>
 */
class IMDS2Client {

    private static final String ROLE_PATTERN = "[-\\w+=,.@]{1,64}";
    private static final String IMDS_ENDPOINT = "http://169.254.169.254";
    private static final int TOKEN_TTL_SECONDS = 21600; // 6h (default & max value)

    private String apiToken = null;

    private IMDS2Client() {
    }

    public static IMDS2Client create() {
        return new IMDS2Client();
    }

    /**
     * Get the currently associated role / instance profile for this EC2 instance.
     * 
     * @return The name of the role (technically, instance profile) associated with
     *         the EC2 instance from which this code is run; null if not associated.
     */
    public String getInstanceProfileName() throws IOException {
        String response = getMetaData("iam/security-credentials", 404);
        if (response == null) {
            return null;
        }
        String[] roles = response.trim().split("\n");
        if (roles.length == 0 || !roles[0].matches(ROLE_PATTERN)) {
            throw new RuntimeException("Unable to read the instance profile name");
        }
        return roles[0];
    }

    /**
     * Query IMDSv2 to obtain credentials to access other AWS services, using the
     * currently associated role in the instance profile.
     * 
     * @return Credentials in the form [accessKeyId, secretAccessKey, token].
     */
    public String[] getCredentials() throws IOException {
        String role = getInstanceProfileName();
        if (role == null) {
            throw new RuntimeException("This EC2 instance seems not to be associated with an instance profile");
        }
        return getCredentials(role);
    }

    /**
     * Query IMDSv2 to obtain credentials to access other AWS services, using the
     * specified role.
     * 
     * @param role The role / instance profile providing the credentials.
     * @return Credentials in the form [accessKeyId, secretAccessKey, token].
     */
    public String[] getCredentials(String role) throws IOException {
        String response = getMetaData("iam/security-credentials/" + role);
        Map<String, ?> credentials = JsonReader.jsonToMaps(response);
        return new String[] {
                (String) credentials.get("AccessKeyId"),
                (String) credentials.get("SecretAccessKey"),
                (String) credentials.get("Token")
        };
    }

    /**
     * Obtain a token to authorize queries to IMDSv2.
     */
    private String getApiToken() throws IOException {
        if (apiToken != null) { // TODO: check token TTL if long-lived client
            return apiToken;
        }
        URL url = new URL(IMDS_ENDPOINT + "/latest/api/token");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(3000 /* milliseconds */);
        conn.setRequestMethod("PUT");
        conn.setRequestProperty("X-aws-ec2-metadata-token-ttl-seconds", String.valueOf(TOKEN_TTL_SECONDS));
        int responseCode = conn.getResponseCode();
        if (responseCode >= 400) {
            throw handleError(conn); // TODO: check meaning of the error codes
        }
        apiToken = IOUtils.toString(conn.getInputStream(), StandardCharsets.UTF_8);
        if (apiToken == null) {
            throw new RuntimeException("Unable to obtain an API token to query the IMDS v2 service");
        }
        return apiToken;
    }

    /**
     * Fetch some metadata from IMDS v2 service.
     * 
     * @param path             The metadata path to query.
     * @param noThrowErrorCode Prefer null as a return value (rather than throw) if the HTTP request returns this error code.
     * @return The resulting metadata, or null if the HTTP request returns with code noThrowErrorCode.
     */
    private String getMetaData(String path, int noThrowErrorCode) throws IOException {
        URL url = new URL(IMDS_ENDPOINT + "/latest/meta-data/" + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(10000 /* milliseconds */);
        conn.setRequestProperty("X-aws-ec2-metadata-token", getApiToken());
        int responseCode = conn.getResponseCode();
        if (responseCode >= 400) {
            // TODO: implement finer error management; see https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html#instance-metadata-returns
            if (noThrowErrorCode > 0 && responseCode == noThrowErrorCode) {
                return null;
            } else {
                throw handleError(conn);
            }
        }
        return IOUtils.toString(conn.getInputStream(), StandardCharsets.UTF_8);
    }

    /**
     * Fetch some metadata from IMDS v2 service.
     * 
     * @param path The metadata path to query.
     * @return The resulting metadata.
     */
    private String getMetaData(String path) throws IOException {
        return getMetaData(path, -1);
    }

    private IOException handleError(HttpURLConnection conn) throws IOException {
        return new IOException("HTTP Error " + conn.getResponseCode()
                + (conn.getResponseMessage() != null ? " - " + conn.getResponseMessage() : "") + " (" + conn.getURL()
                + ")");
    }
}
