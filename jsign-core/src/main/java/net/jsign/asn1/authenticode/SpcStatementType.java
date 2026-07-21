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

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * SpcStatementType ::= SEQUENCE of OBJECT IDENTIFIER
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcStatementType extends ASN1Object {

    private final List<ASN1ObjectIdentifier> identifiers =  new ArrayList<>();

    public SpcStatementType() {
    }

    public SpcStatementType(ASN1ObjectIdentifier identifier) {
        checkIdentifier(identifier);
        this.identifiers.add(identifier);
    }

    private void checkIdentifier(ASN1ObjectIdentifier identifier) {
        if (!AuthenticodeObjectIdentifiers.SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID.equals(identifier)
                && !AuthenticodeObjectIdentifiers.SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID.equals(identifier)) {
            throw new IllegalArgumentException("Invalid id for SpcStatementType: " + identifier);
        }
    }

    public List<ASN1ObjectIdentifier> getIdentifiers() {
        return identifiers;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(identifiers.toArray(new ASN1Encodable[0]));
    }

    public static SpcStatementType parse(ASN1Encodable encodable) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(encodable);
        SpcStatementType statementType = new SpcStatementType();
        for (ASN1Encodable element : sequence) {
            statementType.identifiers.add(ASN1ObjectIdentifier.getInstance(element));
        }
        return statementType;
    }
}
