/*
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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * SpcSerializedObject ::= SEQUENCE {
 *     classId             SpcUuid,
 *     serializedData      OCTETSTRING
 * }
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcSerializedObject extends ASN1Object {

    private final SpcUuid classId;

    /**
     * The serializedData field contains a binary structure. When present in an
     * Authenticode signature generated in Windows Vista, serializedData
     * contains a binary structure that contains page hashes.
     */
    private final byte[] serializedData;

    public SpcSerializedObject(byte[] serializedData) {
        this(new SpcUuid("A6B586D5-B4A1-2466-AE05-A217DA8E60D6"), serializedData);
    }

    public SpcSerializedObject(SpcUuid classId, byte[] serializedData) {
        this.classId = classId;
        this.serializedData = serializedData;
    }

    public SpcUuid getClassId() {
        return classId;
    }

    public byte[] getSerializedData() {
        return serializedData;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[] { classId, new DEROctetString(serializedData) });
    }

    public static SpcSerializedObject parse(ASN1Encodable encodable) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(encodable);
        SpcUuid classId = new SpcUuid(((ASN1OctetString) sequence.getObjectAt(0)).getOctets());
        DEROctetString serializedData = (DEROctetString) sequence.getObjectAt(1);
        return new SpcSerializedObject(classId, serializedData.getOctets());
    }
}
