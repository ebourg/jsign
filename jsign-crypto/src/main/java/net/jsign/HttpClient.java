/**
 * Copyright 2024 Emmanuel Bourg
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

package net.jsign;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.security.MessageDigest;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Hex;

/**
 * Simple HTTP client with resource caching.
 *
 * @since 6.1
 */
class HttpClient {

    /** The directory where the cached files are stored */
    private final File cacheDir;

    /** The expiration time for the cached files */
    private final long expirationTime;

    public HttpClient(File cacheDir, long expirationTime) {
        this.cacheDir = cacheDir;
        this.expirationTime = expirationTime;
    }

    public InputStream getInputStream(URL url) throws IOException {
        File cacheFile = new File(cacheDir, getRequestHash(url) + ".cache");
        if (cacheFile.exists() && (System.currentTimeMillis() - cacheFile.lastModified()) < expirationTime) {
            return new FileInputStream(cacheFile);
        } else {
            HttpURLConnection conn = connect(url);
            if (conn.getResponseCode() >= 400) {
                throw new IOException("Unable to read " + url + " : " + conn.getResponseCode() + " - " + conn.getResponseMessage());
            }

            InputStream in = conn.getInputStream();
            byte[] response = IOUtils.toByteArray(in);
            in.close();

            conn.disconnect();

            // put the response in the cache
            cacheFile.getParentFile().mkdirs();
            Files.write(cacheFile.toPath(), response);

            return new ByteArrayInputStream(response);
        }
    }

    /**
     * Connect to the specified URL and follow the redirections (including http -> https).
     */
    private HttpURLConnection connect(URL url) throws IOException {
        int redirections = 0;

        while (redirections++ < 10) {
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            String userAgent = System.getProperty("http.agent");
            conn.setRequestProperty("User-Agent", "Jsign (https://ebourg.github.io/jsign/)" + (userAgent != null ? " " + userAgent : ""));
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setInstanceFollowRedirects(false);

            switch (conn.getResponseCode()) {
                case HttpURLConnection.HTTP_MOVED_PERM:
                case HttpURLConnection.HTTP_MOVED_TEMP:
                    url = new URL(url, conn.getHeaderField("Location"));
                    continue;
            }

            return conn;
        }

        throw new IOException("Too many redirections for " + url);
    }

    String getRequestHash(URL url) {
        MessageDigest digest = DigestAlgorithm.SHA1.getMessageDigest();
        digest.update(url.toString().getBytes());

        return Hex.toHexString(digest.digest());
    }
}
