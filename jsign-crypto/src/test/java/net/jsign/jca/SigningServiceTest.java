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
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;

import org.junit.Assume;
import org.junit.Test;

import static org.junit.Assert.*;

public class SigningServiceTest {

    public void testCustomProvider(Provider signingProvider, KeyStore keystore, String alias, String keypass) throws Exception {
        Certificate[] chain = keystore.getCertificateChain(alias);
        assertNotNull("Certificate chain not found", chain);
        assertNotEquals("Empty certificate chain", 0, chain.length);

        Key key = keystore.getKey(alias, keypass.toCharArray());
        assertNotNull("Private key not found", key);

        Signature signature = Signature.getInstance("SHA256withRSA", signingProvider);
        signature.initSign((PrivateKey) key);
        signature.update("Hello World".getBytes());
        byte[] s1 = signature.sign();

        assertNotNull("signature null", s1);

        // test with multiple updates
        signature = Signature.getInstance("SHA256withRSA", signingProvider);
        signature.initSign((PrivateKey) key);
        signature.update("Hello".getBytes());
        signature.update(" ".getBytes());
        signature.update("World".getBytes());
        byte[] s2 = signature.sign();

        assertArrayEquals("signature", s1, s2);
    }

    @Test
    public void testLocalProvider() throws Exception {
        Provider provider = new SigningServiceJcaProvider(new LocalKeyStoreSigningService("target/test-classes/keystores/keystore.jks", "password", "password"));

        KeyStore keystore = KeyStore.getInstance("LOCALKEYSTORE", provider);
        keystore.load(null, "secret".toCharArray());

        testCustomProvider(provider, keystore, "test", "password");
    }

    @Test
    public void testOpenPGPCardProvider() throws Exception {
        OpenPGPCardTest.assumeCardPresent();
        Provider provider = new SigningServiceJcaProvider(new OpenPGPCardSigningService(null, "123456", alias -> {
            try {
                try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate-full-chain-reversed.pem")) {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
                    return certificates.toArray(new Certificate[0]);
                }
            } catch (IOException | CertificateException e) {
                throw new RuntimeException(e);
            }
        }));

        KeyStore keystore = KeyStore.getInstance("OPENPGP", provider);
        keystore.load(null, "123456".toCharArray());

        testCustomProvider(provider, keystore, "AUTHENTICATION", "123456");
    }

    @Test
    public void testPIVCardProvider() throws Exception {
        PIVCardTest.assumeCardPresent();
        Provider provider = new SigningServiceJcaProvider(new PIVCardSigningService(null, "123456", alias -> {
            try {
                try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate-full-chain-reversed.pem")) {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
                    return certificates.toArray(new Certificate[0]);
                }
            } catch (IOException | CertificateException e) {
                throw new RuntimeException(e);
            }
        }));

        KeyStore keystore = KeyStore.getInstance("PIV", provider);
        keystore.load(null, "123456".toCharArray());

        testCustomProvider(provider, keystore, "SIGNATURE", "123456");
    }

    @Test
    public void testAmazonProvider() throws Exception {
        AmazonCredentials credentials = new AmazonCredentials(AWS.getAccessKey(), AWS.getSecretKey(), null);
        Provider provider = new SigningServiceJcaProvider(new AmazonSigningService("eu-west-3", credentials, alias -> {
            try {
                try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate-full-chain-reversed.pem")) {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
                    return certificates.toArray(new Certificate[0]);
                }
            } catch (IOException | CertificateException e) {
                throw new RuntimeException(e);
            }
        }));
        KeyStore keystore = KeyStore.getInstance("AWS", provider);
        keystore.load(null, "".toCharArray());

        testCustomProvider(provider, keystore, "test", "");
    }

    @Test
    public void testAzureProvider() throws Exception {
        Provider provider = new SigningServiceJcaProvider(new AzureKeyVaultSigningService("jsignvault", Azure.getAccessToken()));
        KeyStore keystore = KeyStore.getInstance("AZUREKEYVAULT", provider);
        keystore.load(null, "".toCharArray());

        testCustomProvider(provider, keystore, "jsign", "");
    }

    @Test
    public void testGoogleCloudProvider() throws Exception {
        Provider provider = new SigningServiceJcaProvider(new GoogleCloudSigningService("projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring", GoogleCloud.getAccessToken(), alias -> {
            try {
                try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate-full-chain.pem")) {
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

        testCustomProvider(provider, keystore, "353d4f18-5325-4b78-b17c-f92375cf40ec", "");
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

    @Test
    public void testOracleCloudProvider() throws Exception {
        Assume.assumeTrue("OCI configuration not found", OracleCloudCredentials.getConfigFile().exists());

        OracleCloudCredentials credentials = OracleCloudCredentials.getDefault();
        Provider provider = new SigningServiceJcaProvider(new OracleCloudSigningService(credentials, alias -> {
            try {
                try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate-full-chain.pem")) {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
                    return certificates.toArray(new Certificate[0]);
                }
            } catch (IOException | CertificateException e) {
                throw new RuntimeException(e);
            }
        }));
        KeyStore keystore = KeyStore.getInstance("ORACLECLOUD", provider);
        keystore.load(null, "".toCharArray());

        testCustomProvider(provider, keystore, "ocid1.key.oc1.eu-paris-1.h5tafwboaahxq.abrwiljrwkhgllb5zfqchmvdkmqnzutqeq5pz7yo6z7yhl2zyn2yncwzxiza", "");
    }

    @Test
    public void testTrustedSigningProvider() throws Exception {
        String token = Azure.getAccessToken("https://codesigning.azure.net");
        Provider provider = new SigningServiceJcaProvider(new AzureTrustedSigningService("https://weu.codesigning.azure.net", token));
        KeyStore keystore = KeyStore.getInstance("TRUSTEDSIGNING", provider);
        keystore.load(null, "".toCharArray());

        testCustomProvider(provider, keystore, "MyAccount/MyProfile", "");
    }

    @Test
    public void testGaraSignProvider() throws Exception {
        GaraSignCredentials credentials = new GaraSignCredentials("demo_user", "password", "target/test-classes/keystores/keystore.p12", "password");
        Provider provider = new SigningServiceJcaProvider(new GaraSignSigningService(null, credentials));
        KeyStore keystore = KeyStore.getInstance("GARASIGN", provider);
        keystore.load(null, "".toCharArray());

        try {
            testCustomProvider(provider, keystore, "windows_codesign", "");
            fail("Exception not thrown");
        } catch (Exception e) {
            assertEquals("message", "Failed to authenticate with GaraSign: Error authenticating user", e.getCause().getMessage());
        }
    }
}
