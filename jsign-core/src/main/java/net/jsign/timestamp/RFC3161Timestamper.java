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
import java.net.HttpURLConnection;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;

/**
 * RFC 3161 timestamping.
 *
 * @author Florent Daigniere
 * @see <a href="https://www.ietf.org/rfc/rfc3161.txt">Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)</a>
 * @since 1.3
 */
public class RFC3161Timestamper extends Timestamper {

    public RFC3161Timestamper() {
        setURL("http://timestamp.sectigo.com");
    }

    protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
        TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
        reqgen.setCertReq(true);
        TimeStampRequest req = reqgen.generate(algo.oid, algo.getMessageDigest().digest(encryptedDigest));
        byte[] request = req.getEncoded();

        HttpURLConnection conn = (HttpURLConnection) tsaurl.openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-type", "application/timestamp-query");
        conn.setRequestProperty("Content-length", String.valueOf(request.length));
        conn.setRequestProperty("Accept", "application/timestamp-reply");
        conn.setRequestProperty("User-Agent", "Transport");
        
        conn.getOutputStream().write(request);
        conn.getOutputStream().flush();

        if (conn.getResponseCode() >= 400) {
            throw new IOException("Unable to complete the timestamping due to HTTP error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
        }

        try {
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(conn.getInputStream()).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(req);
            if (response.getStatus() != 0) {
                throw new IOException("Unable to complete the timestamping due to an invalid response (" + response.getStatusString() + ")");
            }

            return response.getTimeStampToken().toCMSSignedData();

        } catch (Exception e) {
            throw new TimestampingException("Unable to complete the timestamping", e);
        }
    }

    @Override
    protected AttributeTable getUnsignedAttributes(CMSSignedData token) {
        Attribute rfc3161CounterSignature = new Attribute(AuthenticodeObjectIdentifiers.SPC_RFC3161_OBJID, new DERSet(token.toASN1Structure()));
        return new AttributeTable(rfc3161CounterSignature);
    }
}
