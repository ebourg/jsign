/*
 * Copyright 2023 Emmanuel Bourg
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

/**
 * AWS credentials
 *
 * @since 5.0
 */
public class AmazonCredentials {

    private final String accessKey;
    private final String secretKey;
    private final String sessionToken;

    public AmazonCredentials(String accessKey, String secretKey, String sessionToken) {
        this.accessKey = accessKey;
        this.secretKey = secretKey;
        this.sessionToken = sessionToken;
    }

    public String getAccessKey() {
        return accessKey;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    /**
     * Parses the concatenated AWS credentials
     *
     * @param credentials <tt>accessKey|secretKey|sessionToken</tt> (the session token is optional)
     */
    public static AmazonCredentials parse(String credentials) throws IllegalArgumentException {
        // parse the credentials
        String[] elements = credentials.split("\\|", 3);
        if (elements.length < 2) {
            throw new IllegalArgumentException("Invalid AWS credentials: " + credentials);
        }
        String accessKey = elements[0];
        String secretKey = elements[1];
        String sessionToken = elements.length > 2 ? elements[2] : null;

        return new AmazonCredentials(accessKey, secretKey, sessionToken);   
    }

    /**
     * Returns the default AWS credentials, fetched from the following sources in order:
     * <ul>
     *   <li>The environment variables <tt>AWS_ACCESS_KEY_ID</tt> (or <tt>AWS_ACCESS_KEY</tt>),
     *       <tt>AWS_SECRET_KEY</tt> (or <tt>AWS_SECRET_ACCESS_KEY</tt>) and <tt>AWS_SESSION_TOKEN</tt></li>
     *   <li>The ECS container credentials service (ECS, EKS, Greengrass, Fargate)</li>
     *   <li>The EC2 instance metadata service (IMDSv2)</li>
     * </ul>
     */
    public static AmazonCredentials getDefault() throws IOException {
        if (getenv("AWS_ACCESS_KEY_ID") != null || getenv("AWS_ACCESS_KEY") != null) {
            String accessKey = getenv("AWS_ACCESS_KEY_ID");
            if (accessKey == null) {
                accessKey = getenv("AWS_ACCESS_KEY");
            }
            String secretKey = getenv("AWS_SECRET_KEY");
            if (secretKey == null) {
                secretKey = getenv("AWS_SECRET_ACCESS_KEY");
            }
            String sessionToken = getenv("AWS_SESSION_TOKEN");

            return new AmazonCredentials(accessKey, secretKey, sessionToken);
        } else {
            try {
                return new AmazonECSCredentialsClient().getCredentials();
            } catch (IOException ecsException) {
                try {
                    return new AmazonIMDS2Client().getCredentials();
                } catch (IOException imds2Exception) {
                    ecsException.addSuppressed(imds2Exception);
                    throw ecsException;
                }
            }
        }
    }

    static String getenv(String name) {
        return System.getenv(name);
    }
}
