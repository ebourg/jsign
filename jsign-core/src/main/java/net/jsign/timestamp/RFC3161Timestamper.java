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
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import net.jsign.DigestAlgorithm;

import static net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers.*;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.*;

/**
 * RFC 3161 timestamping.
 *
 * @author Florent Daigniere
 * @see <a href="https://www.ietf.org/rfc/rfc3161.txt">Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)</a>
 * @since 1.3
 */
public class RFC3161Timestamper extends Timestamper {

    /**
     * Tells if the timestamp should use the standard Signature Time-stamp attribute
     * defined in RFC 3161 or the Authenticode specific attribute SPC_RFC3161_OBJID.
     */
    private boolean standardAttribute = false;

    public RFC3161Timestamper() {
        setURL("http://timestamp.sectigo.com");
    }

    @Override
    public CMSSignedData timestamp(DigestAlgorithm algo, CMSSignedData sigData) throws TimestampingException, IOException, CMSException {
        standardAttribute = !isAuthenticode(sigData.getSignedContentTypeOID());
        return super.timestamp(algo, sigData);
    }

    protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
        TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
        reqgen.setCertReq(true);
        TimeStampRequest req = reqgen.generate(algo.oid, algo.getMessageDigest().digest(encryptedDigest));
        byte[] request = req.getEncoded();

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/timestamp-query");
        headers.put("Accept", "application/timestamp-reply");
        byte[] response = post(tsaurl, request, headers);

        try {
            TimeStampResponse resp = new TimeStampResponse(response);
            resp.validate(req);
            if (resp.getStatus() != 0) {
                throw new IOException("Unable to complete the timestamping due to an invalid response (" + resp.getStatusString() + ")");
            }

            return resp.getTimeStampToken().toCMSSignedData();

        } catch (Exception e) {
            throw new TimestampingException("Unable to complete the timestamping", e);
        }
    }

    @Override
    protected Attribute getCounterSignature(CMSSignedData token) {
        return new Attribute(standardAttribute ? id_aa_signatureTimeStampToken : SPC_RFC3161_OBJID, new DERSet(token.toASN1Structure()));
    }
}
