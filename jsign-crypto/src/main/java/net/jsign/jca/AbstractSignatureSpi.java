/*
 * Copyright 2023 Emmanuel Bourg
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

import java.security.InvalidParameterException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Base class for JCA signature implementations.
 *
 * @since 6.0
 */
abstract class AbstractSignatureSpi extends SignatureSpi {

    protected final String signingAlgorithm;

    public AbstractSignatureSpi(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[]{b}, 0, 1);
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
