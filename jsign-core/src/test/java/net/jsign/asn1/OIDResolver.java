/**
 * Copyright 2012 Emmanuel Bourg
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

package net.jsign.asn1;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Utility class for fetching human readable descriptions of object identifiers (OID).
 * The resolved OIDs are cached in a <code>oid.txt</code> file in the local directory.
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class OIDResolver {
    
    private final File file = new File("oid.txt");
    
    private final Properties cache = new Properties();

    public OIDResolver() {
        if (file.exists()) {
            try (InputStream in = new FileInputStream(file)) {
                cache.load(in);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public String lookup(ASN1ObjectIdentifier oid) throws IOException {
        if (!cache.containsKey(oid.getId())) {

            URL url = new URL("http://www.oid-info.com/cgi-bin/display?oid=" + oid.getId() + "&action=display");

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.ISO_8859_1));

            String description = null;
            String ligne;
            while ((ligne = in.readLine()) != null && description == null) {
                if (ligne.contains("<b>Description</b>")) {
                    in.readLine();
                    in.readLine();

                    description = in.readLine();
                    description = description.substring(description.indexOf("<br>") + 4).trim();
                }
            }

            conn.disconnect();

            if (description != null) {
                cache.put(oid.getId(), description);
                FileOutputStream out = new FileOutputStream(file);
                cache.store(out, null);
                out.flush();
                out.close();
            }
        }
        
        return cache.getProperty(oid.getId()) + " (" + oid.getId() + ")";
    }
}
