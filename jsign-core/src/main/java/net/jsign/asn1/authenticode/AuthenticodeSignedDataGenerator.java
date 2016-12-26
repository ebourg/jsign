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

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;

/**
 * Simplified SignedDataGenerator suitable for Authenticode signing.
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class AuthenticodeSignedDataGenerator extends CMSSignedDataGenerator {
    
    public CMSSignedData generate(ASN1ObjectIdentifier contentTypeOID, ASN1Encodable content) throws CMSException, IOException {
        digests.clear();
        
        SignerInfo signerInfo;
        
        if (!_signers.isEmpty()) {
            signerInfo = ((SignerInformation) _signers.get(0)).toASN1Structure();
        } else {
            SignerInfoGenerator signerInfoGenerator = (SignerInfoGenerator) signerGens.get(0);
            
            byte[] signedContent = content.toASN1Primitive().getEncoded("DER");
            
            OutputStream out = signerInfoGenerator.getCalculatingOutputStream();
            out.write(signedContent, 2, signedContent.length - 2); // skip the first 2 bytes as specified
            out.flush();
            out.close();
            
            signerInfo = signerInfoGenerator.generate(contentTypeOID);
            
            byte[] calculatedDigest = signerInfoGenerator.getCalculatedDigest();
            digests.put(signerInfoGenerator.getDigestAlgorithm().getAlgorithm().getId(), calculatedDigest);
        }       

        ContentInfo encInfo = new ContentInfo(contentTypeOID, content);
        ASN1Set certificates = new DERSet((ASN1Encodable[]) certs.toArray(new ASN1Encodable[0]));

        ASN1Encodable signedData = new AuthenticodeSignedData(signerInfo.getDigestAlgorithm(), encInfo, certificates, signerInfo);

        ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.signedData, signedData);

        return new CMSSignedData(new CMSProcessableByteArray(contentTypeOID, content.toASN1Primitive().getEncoded("DER")), contentInfo);
    }
}
