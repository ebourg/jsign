/**
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

import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;

/**
 * AttributeTable generator able to remove attributes from the table returned by another AttributeTable generator.
 * 
 * @author Emmanuel Bourg
 * @since 3.0
 */
public class FilteredAttributeTableGenerator implements CMSAttributeTableGenerator {

    private final CMSAttributeTableGenerator delegate;
    private final ASN1ObjectIdentifier[] removedAttributes;

    public FilteredAttributeTableGenerator(CMSAttributeTableGenerator delegate, ASN1ObjectIdentifier... removedAttributes) {
        this.delegate = delegate;
        this.removedAttributes = removedAttributes;
    }

    @Override
    public AttributeTable getAttributes(Map parameters) throws CMSAttributeTableGenerationException {
        AttributeTable attributes = delegate.getAttributes(parameters);

        for (ASN1ObjectIdentifier identifier : removedAttributes) {
            attributes = attributes.remove(identifier);
        }
        
        return attributes;
    }
}
