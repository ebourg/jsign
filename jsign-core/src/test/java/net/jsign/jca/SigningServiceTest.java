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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import net.jsign.AuthenticodeSigner;
import net.jsign.SignatureAssert;
import net.jsign.pe.PEFile;

import static net.jsign.DigestAlgorithm.*;

public class SigningServiceTest {

    public void testCustomProvider(Provider signingProvider, KeyStore keystore, String alias, String keypass) throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signing-service-" + signingProvider.getName().toLowerCase() + ".exe");

        FileUtils.copyFile(sourceFile, targetFile);

        PEFile peFile = null;
        try {
            peFile = new PEFile(targetFile);

            AuthenticodeSigner signer = new AuthenticodeSigner(keystore, alias, keypass)
                    .withSignatureProvider(signingProvider)
                    .withTimestamping(false)
                    .withDigestAlgorithm(SHA256);

            signer.sign(peFile);

            peFile = new PEFile(targetFile);

            SignatureAssert.assertSigned(peFile, SHA256);
        } finally {
            if (peFile != null) {
                peFile.close();
            }
        }
    }

    @Test
    public void testLocalProvider() throws Exception {
        Provider provider = new SigningServiceJcaProvider(new LocalKeyStoreSigningService("target/test-classes/keystores/keystore.jks", "password", "password"));

        KeyStore keystore = KeyStore.getInstance("LOCALKEYSTORE", provider);
        keystore.load(null, "secret".toCharArray());

        testCustomProvider(provider, keystore, "test", "password");
    }

    @Test
    public void testAzureProvider() throws Exception {
        Provider provider = new SigningServiceJcaProvider(new AzureKeyVaultSigningService("jsigntestkeyvault", Azure.getAccessToken()));
        KeyStore keystore = KeyStore.getInstance("AZUREKEYVAULT", provider);
        keystore.load(null, "".toCharArray());

        testCustomProvider(provider, keystore, "jsign", "");
    }

    @Test
    public void testGoogleCloudProvider() throws Exception {
        Provider provider = new SigningServiceJcaProvider(new GoogleCloudSigningService("projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring", GoogleCloud.getAccessToken(), alias -> {
            try {
                try (FileInputStream in = new FileInputStream("src/test/resources/keystores/jsign-test-certificate-full-chain-reversed.pem")) {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
                    return certificates.toArray(new Certificate[0]);
                }
            } catch (IOException | CertificateException e) {
                throw new RuntimeException(e);
            }
        }));
        KeyStore keystore = KeyStore.getInstance("GOOGLECLOUD", provider);
        keystore.load(null, "".toCharArray());

        testCustomProvider(provider, keystore, "test", "");
    }

    @Test
    public void testDigiCertProvider() throws Exception {
        String apikey = DigiCertONE.getApiKey();
        String keystoreFile = DigiCertONE.getClientCertificateFile();

        Provider provider = new SigningServiceJcaProvider(new DigiCertOneSigningService(apikey, new File(keystoreFile), DigiCertONE.getClientCertificatePassword()));
        KeyStore keystore = KeyStore.getInstance("DIGICERTONE", provider);
        keystore.load(null, "".toCharArray());

        testCustomProvider(provider, keystore, "0a50eb72-68d0-4730-96cb-fe648d2c2fd2", "");
    }

    @Test
    public void testESignerProvider() throws Exception {
        ESignerSigningService service = new ESignerSigningService("https://cs-try.ssl.com", "esigner_demo", "esignerDemo#1");
        Provider provider = new SigningServiceJcaProvider(service);
        KeyStore keystore = KeyStore.getInstance("ESIGNER", provider);
        keystore.load(null, "".toCharArray());
        String alias = keystore.aliases().nextElement();

        testCustomProvider(provider, keystore, alias, "RDXYgV9qju+6/7GnMf1vCbKexXVJmUVr+86Wq/8aIGg=");
    }
}
