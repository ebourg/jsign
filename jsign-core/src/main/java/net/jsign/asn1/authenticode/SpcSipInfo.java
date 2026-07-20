/*
 * Copyright 2019 Emmanuel Bourg
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
import org.bouncycastle.asn1.BERSequence;

/**
 * Subject Interface Package (SIP) information.
 * 
 * <pre>
 * SpcSipInfo ::= {
 *     version                 INTEGER,
 *     uuid                    SpcUuid,
 *     reserved1               INTEGER,
 *     reserved2               INTEGER,
 *     reserved3               INTEGER,
 *     reserved4               INTEGER,
 *     reserved5               INTEGER
 * }
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 3.0
 */
public class SpcSipInfo extends ASN1Object {

    /** A value specific to the type of object signed (1 for MSI, VBScript and JScript, 65536 for PowerShell) */
    private final int version;

    /** The GUID of the object signed */
    private final SpcUuid uuid;

    public SpcSipInfo(int version, SpcUuid uuid) {
        this.version = version;
        this.uuid = uuid;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(version));
        v.add(uuid);
        v.add(new ASN1Integer(0)); // reserved1
        v.add(new ASN1Integer(0)); // reserved2
        v.add(new ASN1Integer(0)); // reserved3
        v.add(new ASN1Integer(0)); // reserved4
        v.add(new ASN1Integer(0)); // reserved5
        return new BERSequence(v);
    }
}
