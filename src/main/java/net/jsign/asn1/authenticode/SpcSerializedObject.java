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

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * SpcSerializedObject ::= SEQUENCE {
 *     classId             SpcUuid,
 *     serializedData      OCTETSTRING
 * }
 * 
 * SpcUuid ::= OCTETSTRING  
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcSerializedObject extends ASN1Object {

    private DEROctetString classId = new DEROctetString(new BigInteger("a6b586d5b4a12466ae05a217da8e60d6", 16).toByteArray());

    /**
     * The serializedData field contains a binary structure. When present in an
     * Authenticode signature generated in Windows Vista, serializedData
     * contains a binary structure that contains page hashes.
     */
    private DEROctetString serializedData;

    public SpcSerializedObject(byte[] serializedData) {
        this.serializedData = new DEROctetString(serializedData);
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(classId);
        v.add(serializedData);
        
        return new DERSequence(v);
    }
}
