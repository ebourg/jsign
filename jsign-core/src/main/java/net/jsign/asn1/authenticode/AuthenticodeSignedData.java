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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Simplified version of the SignedData structure as used by Authenticode.
 */
public class AuthenticodeSignedData extends ASN1Object {

    private final AlgorithmIdentifier digestAlgorithm;
    private final ContentInfo contentInfo;
    private final ASN1Set certificates;
    private final SignerInfo signerInformation;

    public AuthenticodeSignedData(AlgorithmIdentifier digestAlgorithm, ContentInfo contentInfo, ASN1Set certificates, SignerInfo signerInformation) {
        this.digestAlgorithm = digestAlgorithm;
        this.contentInfo = contentInfo;
        this.certificates = certificates;
        this.signerInformation = signerInformation;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(1));
        v.add(new DERSet(digestAlgorithm));
        v.add(contentInfo);

        if (certificates != null) {
            v.add(new DERTaggedObject(false, 0, certificates));
        }

        v.add(new DERSet(signerInformation));

        return new BERSequence(v);
    }
}
