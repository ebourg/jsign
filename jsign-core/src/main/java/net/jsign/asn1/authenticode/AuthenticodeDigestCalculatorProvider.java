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

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * DigestCalculator skipping the first two bytes of the signed data (why?).
 * 
 * @author Emmanuel Bourg
 * @since 2.1
 */
public class AuthenticodeDigestCalculatorProvider implements DigestCalculatorProvider {

    @Override
    public DigestCalculator get(final AlgorithmIdentifier digestAlgorithmIdentifier) throws OperatorCreationException {
        final DigestCalculator delegate = new JcaDigestCalculatorProviderBuilder().build().get(digestAlgorithmIdentifier);

        return new DigestCalculator() {
            private ByteArrayOutputStream out = new ByteArrayOutputStream();

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
                    delegate.getOutputStream().write(out.toByteArray(), 2, out.size() - 2);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                return delegate.getDigest();
            }
        };
    }
}
