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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * <pre>
 * TimeStampRequest ::= SEQUENCE {
 *   countersignatureType OBJECT IDENTIFIER,
 *   attributes Attributes OPTIONAL, 
 *   content  ContentInfo
 * }
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class AuthenticodeTimeStampRequest extends ASN1Object {
    
    private final ContentInfo contenInfo;

    public AuthenticodeTimeStampRequest(byte[] digest) {
        contenInfo = new ContentInfo(PKCSObjectIdentifiers.data, new BEROctetString(digest));
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(AuthenticodeObjectIdentifiers.SPC_TIME_STAMP_REQUEST_OBJID);
        v.add(contenInfo);
        return new DERSequence(v);
    }
}
