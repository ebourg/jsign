/**
 * Copyright 2014 Florent Daigniere
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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.jsign.HashAlgo;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

/**
 * RFC 3161 timestamping.
 *
 * @see <a href="https://www.ietf.org/rfc/rfc3161.txt">Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)</a>
 * @author Florent Daigniere
 * @since 1.3
 */
public class RFC3161Timestamper extends Timestamper {

    public RFC3161Timestamper() {
        setURL("http://timestamp.comodoca.com/rfc3161");
    }

    protected CMSSignedData timestamp(HashAlgo algo, byte[] encryptedDigest) throws IOException, TimestampingException {
        OutputStream out = null;

        try {
            MessageDigest md = MessageDigest.getInstance(algo.id);
            TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
            TimeStampRequest req = reqgen.generate(algo.oid, md.digest(encryptedDigest));
            byte request[] = req.getEncoded();

            HttpURLConnection con = (HttpURLConnection) tsaurl.openConnection();
            con.setConnectTimeout(10000);
            con.setReadTimeout(10000);
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setUseCaches(false);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/timestamp-query");
            con.setRequestProperty("Content-length", String.valueOf(request.length));
            con.setRequestProperty("Accept", "application/timestamp-query");
            con.setRequestProperty("User-Agent", "Transport");
            out = con.getOutputStream();
            out.write(request);
            out.flush();

            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
            }
            InputStream in = con.getInputStream();
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(req);
            if (response.getStatus() != 0) {
                throw new IOException("Received an invalid timestamp (status=" + response.getStatusString() + ")");
            }

            return response.getTimeStampToken().toCMSSignedData();
        } catch (NoSuchAlgorithmException e) {
            // This should never happen
            throw new TimestampingException(e);
        } catch (TSPException e) {
            throw new TimestampingException(e);
        }
    }
}
