/*
 * Copyright 2024 Björn Kautler
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

import net.jsign.jca.OracleCloudCredentials;
import net.jsign.jca.OracleCloudSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import org.kohsuke.MetaInfServices;

import java.io.File;
import java.io.IOException;
import java.security.Provider;

import static net.jsign.JsignKeyStore.getCertificateStore;

/**
 * Oracle Cloud Infrastructure Key Management Service. This keystore requires the <a href="https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm">configuration file</a>
 * or the <a href="https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clienvironmentvariables.htm">environment
 * variables</a> used by the OCI CLI. The storepass parameter specifies the path to the configuration file
 * (<code>~/.oci/config</code> by default). If the configuration file contains multiple profiles, the name of the
 * non-default profile to use is appended to the storepass (for example <code>~/.oci/config|PROFILE</code>).
 * The keypass parameter may be used to specify the passphrase of the key file used for signing the requests to
 * the OCI API if it isn't set in the configuration file.
 *
 * <p>The certificate must be provided separately using the certfile parameter. The alias specifies the OCID
 * of the key.</p>
 */
@MetaInfServices(JsignKeyStore.class)
public class OracleCloudKeyStore extends AbstractJsignKeyStore {
    @Override
    public String getType() {
        return "ORACLECLOUD";
    }

    @Override
    public void validate(KeyStoreBuilder params) throws IllegalArgumentException {
        if (params.certfile() == null) {
            throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
        }
    }

    @Override
    public Provider getProvider(KeyStoreBuilder params) {
        OracleCloudCredentials credentials = new OracleCloudCredentials();
        try {
            File config = null;
            String profile = null;
            if (params.storepass() != null) {
                String[] elements = params.storepass().split("\\|", 2);
                config = new File(elements[0]);
                if (elements.length > 1) {
                    profile = elements[1];
                }
            }
            credentials.load(config, profile);
            credentials.loadFromEnvironment();
            if (params.keypass() != null) {
                credentials.setPassphrase(params.keypass());
            }
        } catch (IOException e) {
            throw new RuntimeException("An error occurred while fetching the Oracle Cloud credentials", e);
        }
        return new SigningServiceJcaProvider(new OracleCloudSigningService(credentials, getCertificateStore(params)));
    }
}
