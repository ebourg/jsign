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

import java.security.PrivateKey;

/**
 * Private key held by the signing service.
 */
class SigningServicePrivateKey implements PrivateKey {

    private final String id;

    /** The algorithm of the key (for example RSA or ECDSA) */
    private final String algorithm;

    public SigningServicePrivateKey(String id, String algorithm) {
        this.id = id;
        this.algorithm = algorithm;
    }

    public String getId() {
        return id;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException();
    }
}
