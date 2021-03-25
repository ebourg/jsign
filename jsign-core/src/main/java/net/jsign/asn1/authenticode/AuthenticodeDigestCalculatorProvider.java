/**
 * Copyright 2017 Emmanuel Bourg
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * DigestCalculator skipping the ASN.1 sequence header (typically 2 or 3 bytes) of the SpcIndirectData structure.
 * 
 * @author Emmanuel Bourg
 * @since 2.1
 */
public class AuthenticodeDigestCalculatorProvider implements DigestCalculatorProvider {

    @Override
    public DigestCalculator get(final AlgorithmIdentifier digestAlgorithmIdentifier) throws OperatorCreationException {
        final DigestCalculator delegate = new JcaDigestCalculatorProviderBuilder().build().get(digestAlgorithmIdentifier);

        return new DigestCalculator() {
            private final ByteArrayOutputStream out = new ByteArrayOutputStream();

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return digestAlgorithmIdentifier;
            }

            @Override
            public OutputStream getOutputStream() {
                return out;
            }

            @Override
            public byte[] getDigest() {
                try {
                    ASN1InputStream in = new ASN1InputStream(out.toByteArray());
                    ASN1Sequence sequence = (ASN1Sequence) in.readObject();
                    for (ASN1Encodable element : sequence) {
                        delegate.getOutputStream().write(element.toASN1Primitive().getEncoded());
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                return delegate.getDigest();
            }
        };
    }
}
