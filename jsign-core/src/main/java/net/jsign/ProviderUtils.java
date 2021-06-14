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

package net.jsign;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;

/**
 * Helper class for working with security providers.
 *
 * @since 4.0
 */
class ProviderUtils {

    /**
     * Creates a SunPKCS11 provider with the specified configuration.
     *
     * @param configuration Either the SunPKCS11 configuration file, or the inline SunPKCS11
     *                      configuration (starting with <code>--</code>)
     * @since 4.0
     */
    static Provider createSunPKCS11Provider(String configuration) {
        try {
            try {
                // Java 9 and later, using the Provider.configure() method
                Method providerConfigureMethod = Provider.class.getMethod("configure", String.class);
                Provider provider = Security.getProvider("SunPKCS11");
                return (Provider) providerConfigureMethod.invoke(provider, configuration);
            } catch (NoSuchMethodException e) {
                // prior to Java 9, direct instantiation of the SunPKCS11 class
                Constructor<?> sunpkcs11Constructor = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(String.class);
                return (Provider) sunpkcs11Constructor.newInstance(configuration);
            }
        } catch (Exception e) {
            throw new ProviderException("Failed to create a SunPKCS11 provider from the configuration " + configuration, e);
        }
    }
}
