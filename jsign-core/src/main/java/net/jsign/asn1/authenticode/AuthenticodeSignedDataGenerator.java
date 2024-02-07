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

package net.jsign.asn1.authenticode;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.PKCS7ProcessableObject;
import org.bouncycastle.cms.SignerInformation;

/**
 * CMSSignedDataGenerator suitable for Authenticode signing (generates SignedData v1 structures and preserves
 * the sequence structure of the SpcIndirectDataContent object instead of turning it into an octet string).
 *
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class AuthenticodeSignedDataGenerator extends CMSSignedDataGenerator {

    @Override
    public CMSSignedData generate(CMSTypedData content, boolean encapsulate) throws CMSException {
        digests.clear();
        
        if (!(content instanceof PKCS7ProcessableObject))
        	return super.generate(content, encapsulate);

        SignerInfo signerInfo = getSignerInfo(content);
        ContentInfo encInfo = new ContentInfo(content.getContentType(), (ASN1Encodable) content.getContent());
        DERSet certificates = new DERSet((ASN1Encodable[]) certs.toArray(new ASN1Encodable[0]));
        ASN1Encodable signedData = new AuthenticodeSignedData(signerInfo.getDigestAlgorithm(), encInfo, certificates, signerInfo);
        ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.signedData, signedData);

        return new CMSSignedData(content, contentInfo);
    }

    private SignerInfo getSignerInfo(CMSTypedData content) throws CMSException {
        if (!_signers.isEmpty()) {
            return ((SignerInformation) _signers.get(0)).toASN1Structure();
        } else {
            CMSSignedData sigData = super.generate(content, true);
            return sigData.getSignerInfos().iterator().next().toASN1Structure();
        }
    }
}
