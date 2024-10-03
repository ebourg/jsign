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

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.encoders.Base64;

import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeTimeStampRequest;

/**
 * Legacy Authenticode timestamping.
 *
 * @author Emmanuel Bourg
 * @since 1.3
 */
public class AuthenticodeTimestamper extends Timestamper {

    public AuthenticodeTimestamper() {
        setURL("http://timestamp.sectigo.com");
    }

    protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
        AuthenticodeTimeStampRequest timestampRequest = new AuthenticodeTimeStampRequest(encryptedDigest);

        byte[] request = Base64.encode(timestampRequest.getEncoded("DER"));
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/octet-stream");
        headers.put("Accept", "application/octet-stream");
        byte[] response = post(tsaurl, request, headers);

        try {
            return new CMSSignedData(Base64.decode(response));
        } catch (Exception e) {
            throw new TimestampingException("Unable to complete the timestamping", e);
        }
    }

    @Override
    protected Collection<X509CertificateHolder> getExtraCertificates(CMSSignedData token) {
        return token.getCertificates().getMatches(null);
    }

    @Override
    protected Attribute getCounterSignature(CMSSignedData token) {
        SignerInformation timestampSignerInformation = token.getSignerInfos().getSigners().iterator().next();
        return new Attribute(CMSAttributes.counterSignature, new DERSet(timestampSignerInformation.toASN1Structure()));
    }
}
