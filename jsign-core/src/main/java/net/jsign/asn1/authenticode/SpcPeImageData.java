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

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 * SpcPeImageData ::= SEQUENCE {
 *    flags                   SpcPeImageFlags DEFAULT { includeResources },
 *    file                    SpcLink
 * } --#public--
 *
 * SpcPeImageFlags ::= BIT STRING {
 *    includeResources            (0),
 *    includeDebugInfo            (1),
 *    includeImportAddressTable   (2)
 * }
 * </pre>
 *
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcPeImageData extends ASN1Object {

    /**
     * This field specifies which portions of the Windows PE file are hashed.
     * It is a 2-bit value that is set to one of the SpcPeImageData flags.
     * Although flags is always present, it is ignored when calculating the
     * file hash for both signing and verification purposes.
     */
    private ASN1BitString flags = new DERBitString(new byte[0]);

    /**
     * This field is always set to an SPCLink structure, even though the ASN.1
     * definitions designate file as optional. SPCLink originally contained
     * information that describes the software publisher.
     */
    private SpcLink file = new SpcLink();

    public ASN1BitString getFlags() {
        return flags;
    }

    public SpcLink getFile() {
        return file;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(flags);
        v.add(new DERTaggedObject(0, file)); // contrary to the specification this is tagged (as observed in actual signed executables)

        return new BERSequence(v);
    }

    public static SpcPeImageData parse(ASN1Encodable encodable) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(encodable);
        SpcPeImageData data = new SpcPeImageData();
        data.flags = ASN1BitString.getInstance(sequence.getObjectAt(0));
        data.file = SpcLink.parse(ASN1TaggedObject.getInstance(DERTaggedObject.getInstance(sequence.getObjectAt(1)).getBaseObject()));
        return data;
    }
}
