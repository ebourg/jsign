/**
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

import java.security.Provider;
import java.util.Collections;
import java.util.function.Supplier;

/**
 * Provider.Service implementation using a lambda expression to create the service instances.
 *
 * @since 6.0
 */
class ProviderService extends Provider.Service {

    private final Supplier<Object> constructor;

    public ProviderService(Provider provider, String type, String algorithm, String className, Supplier<Object> constructor) {
        super(provider, type, algorithm, className, Collections.emptyList(), null);
        this.constructor = constructor;
    }

    @Override
    public Object newInstance(Object constructorParameter) {
        return constructor.get();
    }
}
