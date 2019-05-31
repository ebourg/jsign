/**
 * Copyright 2019 PrimeKey Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.jsign;

import java.util.Collection;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;

/**
 * Implementation of a signed CMS attribute table generator with the ability to
 * exclude a collection of attributes.
 *
 * @author Marcus Lundblad
 * @author Markus Kilas
 */
public class FilteredSignedAttributeTableGenerator extends
        DefaultSignedAttributeTableGenerator {

    private final Collection<ASN1ObjectIdentifier> attributesToRemove;

    public FilteredSignedAttributeTableGenerator(Collection<ASN1ObjectIdentifier> attributesToRemove, AttributeTable attributeTable) {
        super(attributeTable);
        this.attributesToRemove = attributesToRemove;
    }

    @Override
    public AttributeTable getAttributes(Map parameters) {
        AttributeTable attrs = super.getAttributes(parameters);

        for (ASN1ObjectIdentifier oid : attributesToRemove) {
            attrs = attrs.remove(oid);
        }

        return attrs;
    }
}
