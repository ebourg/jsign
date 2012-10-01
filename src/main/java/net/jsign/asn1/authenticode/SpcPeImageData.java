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
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 * SpcPeImageData ::= SEQUENCE {
 *    flags                   SpcPeImageFlags DEFAULT { includeResources },
 *    file                    SpcLink
 * } --#public--
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
    private DERBitString flags = new DERBitString(new byte[0]);

    /**
     * This field is always set to an SPCLink structure, even though the ASN.1
     * definitions designate file as optional. SPCLink originally contained
     * information that describes the software publisher.
     */
    private SpcLink file = new SpcLink();

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(flags);
        v.add(new DERTaggedObject(0, file)); // contrary to the specification this is tagged (as observed in actual signed executables)

        return new BERSequence(v);
    }
}
