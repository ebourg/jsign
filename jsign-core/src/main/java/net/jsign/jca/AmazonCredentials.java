/**
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
}
