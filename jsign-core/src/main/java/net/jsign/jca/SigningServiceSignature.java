/**
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

import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

class SigningServiceSignature extends SignatureSpi {

    private final SigningService service;
    private final String signingAlgorithm;
    private SigningServicePrivateKey privateKey;
    private byte[] data;

    public SigningServiceSignature(SigningService service, String signingAlgorithm) {
        this.service = service;
        this.signingAlgorithm = signingAlgorithm;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) {
        this.privateKey = (SigningServicePrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(byte b) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        data = new byte[len];
        System.arraycopy(b, off, data, 0, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            return service.sign(privateKey, signingAlgorithm, data);
        } catch (GeneralSecurityException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }
}
