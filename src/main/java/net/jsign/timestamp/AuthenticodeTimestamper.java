/**
 * Copyright 2014 Emmanuel Bourg
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

package net.jsign.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;

import net.jsign.DigestAlgorithm;
import net.jsign.ProxySettings;
import net.jsign.asn1.authenticode.AuthenticodeTimeStampRequest;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Base64;

/**
 * Legacy Authenticode timestamping.
 *
 * @author Emmanuel Bourg
 * @since 1.3
 */
public class AuthenticodeTimestamper extends Timestamper {

    public AuthenticodeTimestamper() {
        setURL("http://timestamp.comodoca.com/authenticode");
    }

    protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest, ProxySettings proxy) throws IOException, TimestampingException {
        AuthenticodeTimeStampRequest timestampRequest = new AuthenticodeTimeStampRequest(encryptedDigest);

        byte[] request = Base64.encode(timestampRequest.getEncoded("DER"));

        HttpURLConnection conn = proxy.openConnection(tsaurl);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-type", "application/octet-stream");
        conn.setRequestProperty("Content-length", String.valueOf(request.length));
        conn.setRequestProperty("Accept", "application/octet-stream");
        conn.setRequestProperty("User-Agent", "Transport");

        conn.getOutputStream().write(request);
        conn.getOutputStream().flush();

        if (conn.getResponseCode() >= 400) {
            throw new IOException("Unable to complete the timestamping due to HTTP error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
        }

        try {
            byte[] response = Base64.decode(toBytes(conn.getInputStream()));
            return new CMSSignedData(response);
        } catch (CMSException e) {
            throw new TimestampingException("Unable to complete the timestamping", e);
        }
    }

    private byte[] toBytes(InputStream in) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) != -1) {
            bout.write(buffer, 0, n);
        }
        
        return bout.toByteArray();
    }
}
