/*
 * Copyright 2021 Emmanuel Bourg
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

package net.jsign.jca;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SignatureException;

class SigningServiceSignature extends AbstractSignatureSpi {

    private SigningServicePrivateKey privateKey;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public SigningServiceSignature(String signingAlgorithm) {
        super(signingAlgorithm);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) {
        this.privateKey = (SigningServicePrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            return privateKey.getService().sign(privateKey, signingAlgorithm, buffer.toByteArray());
        } catch (GeneralSecurityException e) {
            throw new SignatureException(e);
        }
    }
}
