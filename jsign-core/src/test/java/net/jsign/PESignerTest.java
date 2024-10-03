/**
 * Copyright 2012 Emmanuel Bourg
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.HashSet;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.JavaVersion;
import org.apache.commons.lang3.SystemUtils;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assume;
import org.junit.Test;

import net.jsign.pe.PEFile;
import net.jsign.timestamp.AuthenticodeTimestamper;
import net.jsign.timestamp.TimestampingException;
import net.jsign.timestamp.TimestampingMode;

import static net.jsign.DigestAlgorithm.*;
import static net.jsign.KeyStoreType.*;
import static org.junit.Assert.*;

public class PESignerTest {

    private static final String PRIVATE_KEY_PASSWORD = "password";
    private static final String ALIAS = "test";

    private KeyStore getKeyStore() throws Exception {
        return new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
    }

    @Test
    public void testSign() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");
        
        FileUtils.copyFile(sourceFile, targetFile);

        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(false)
                .withProgramName("WinEyes")
                .withProgramURL("http://www.steelblue.com/WinEyes");

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);

            CMSSignedData signature = peFile.getSignatures().get(0);

            assertNotNull("signature", signature);
            assertNull("signingTime attribute found", signature.getSignerInfos().iterator().next().getSignedAttributes().get(CMSAttributes.signingTime));
        }
    }

    @Test
    public void testSignWithUnknownKeyStoreEntry() throws Exception {
        try {
            new PESigner(getKeyStore(), "unknown", PRIVATE_KEY_PASSWORD);
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "No certificate found in the keystore with the alias 'unknown'", e.getMessage());
        }
    }

    @Test
    public void testSigningWithKeyAndChain() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-key-chain.exe");
        
        FileUtils.copyFile(sourceFile, targetFile);

        Certificate[] chain;
        try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate-full-chain.spc")) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
            chain = certificates.toArray(new Certificate[0]);
        }

        PrivateKey key = PrivateKeyUtils.load(new File("target/test-classes/keystores/privatekey-encrypted.pvk"), "password");

        PESigner signer = new PESigner(chain, key)
                .withTimestamping(false)
                .withProgramName("WinEyes")
                .withProgramURL("http://www.steelblue.com/WinEyes");

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);

            CMSSignedData signature = peFile.getSignatures().get(0);

            assertNotNull("signature", signature);

            // check the signer id
            SignerId signerId = signature.getSignerInfos().iterator().next().getSID();
            X509CertificateHolder certificate = (X509CertificateHolder) signature.getCertificates().getMatches(signerId).iterator().next();
            String commonName = certificate.getSubject().getRDNs(X509ObjectIdentifiers.commonName)[0].getFirst().getValue().toString();
            assertEquals("signer", "Jsign Code Signing Test Certificate 2024 (RSA)", commonName);
        }
    }

    @Test
    public void testSigningWithYubikey() throws Exception {
        Assume.assumeTrue("No Yubikey detected", YubiKey.isPresent());

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-yubikey.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        KeyStore keystore = new KeyStoreBuilder().storetype(YUBIKEY).storepass("123456")
                .certfile("target/test-classes/keystores/jsign-test-certificate-full-chain.spc").build();
        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "X.509 Certificate for Digital Signature", null);

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEmptyChain() throws Exception {
        PrivateKey key = PrivateKeyUtils.load(new File("target/test-classes/keystores/privatekey-encrypted.pvk"), "password");
        new PESigner(new Certificate[0], key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullChain() throws Exception {
        PrivateKey key = PrivateKeyUtils.load(new File("target/test-classes/keystores/privatekey-encrypted.pvk"), "password");
        new PESigner(null, key);
    }

    @Test
    public void testSigningWithMismatchingKeyAndCertificate() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-mismatching-key-certificate.exe");
        
        FileUtils.copyFile(sourceFile, targetFile);

        Certificate[] chain;
        try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-root-ca.pem")) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
            chain = certificates.toArray(new Certificate[0]);
        }

        PrivateKey key = PrivateKeyUtils.load(new File("target/test-classes/keystores/privatekey-encrypted.pvk"), "password");

        PESigner signer = new PESigner(chain, key)
                .withTimestamping(false)
                .withProgramName("WinEyes")
                .withProgramURL("http://www.steelblue.com/WinEyes");

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);
            fail("Exception not thrown"); // todo investigate why no exception is thrown when the mismatched keys have the same length
        } catch (Exception e) {
            // expected
        }
    }

    @Test
    public void testTimestampAuthenticode() throws Exception {
        testTimestamp(TimestampingMode.AUTHENTICODE, SHA1);
    }

    @Test
    public void testTimestampRFC3161() throws Exception {
        testTimestamp(TimestampingMode.RFC3161, SHA256);
    }

    public void testTimestamp(TimestampingMode mode, DigestAlgorithm alg) throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamped-" + mode.name().toLowerCase() + ".exe");
        
        FileUtils.copyFile(sourceFile, targetFile);

        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(alg);
        signer.withTimestamping(true);
        signer.withTimestampingMode(mode);

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, alg);
            SignatureAssert.assertTimestamped("Invalid timestamp", peFile.getSignatures().get(0));
        }
    }

    /**
     * Tests that a custom Timestamper implementation can be provided.
     */
    @Test
    public void testWithTimestamper() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamped-custom.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        final HashSet<Boolean> called = new HashSet<>();

        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(SHA1);
        signer.withTimestamping(true);
        signer.withTimestamper(new AuthenticodeTimestamper() {
            
            @Override
            protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
                called.add(true);
                return super.timestamp(algo, encryptedDigest);
            }

        });

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            assertTrue("expecting our Timestamper to be used", called.contains(true));

            SignatureAssert.assertSigned(peFile, SHA1);
            SignatureAssert.assertTimestamped("Invalid timestamp", peFile.getSignatures().get(0));
        }
    }

    @Test
    public void testSignTwice() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-twice.exe");
        
        FileUtils.copyFile(sourceFile, targetFile);

        try (PEFile peFile = new PEFile(targetFile)) {
            PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA1)
                    .withTimestamping(true)
                    .withProgramName("WinEyes")
                    .withProgramURL("http://www.steelblue.com/WinEyes");

            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA1);
            SignatureAssert.assertTimestamped("Invalid timestamp", peFile.getSignatures().get(0));

            // second signature
            signer.withDigestAlgorithm(SHA256);
            signer.withTimestamping(false);
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA1, SHA256);
            SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", peFile.getSignatures().get(0));
        }
    }

    @Test
    public void testSignThreeTimes() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-three-times.exe");
        
        FileUtils.copyFile(sourceFile, targetFile);

        try (PEFile peFile = new PEFile(targetFile)) {

            PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA1)
                    .withTimestamping(true)
                    .withProgramName("WinEyes")
                    .withProgramURL("http://www.steelblue.com/WinEyes");
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA1);
            SignatureAssert.assertTimestamped("Invalid timestamp", peFile.getSignatures().get(0));

            // second signature
            signer.withDigestAlgorithm(SHA256);
            signer.withTimestamping(false);
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA1, SHA256);
            SignatureAssert.assertTimestamped("Timestamp corrupted after adding the second signature", peFile.getSignatures().get(0));

            // third signature
            signer.withDigestAlgorithm(SHA512);
            signer.withTimestamping(false);
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA1, SHA256, SHA512);
            SignatureAssert.assertTimestamped("Timestamp corrupted after adding the third signature", peFile.getSignatures().get(0));
        }
    }

    @Test
    public void testReplaceSignature() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-re-signed.exe");
        
        FileUtils.copyFile(sourceFile, targetFile);

        try (PEFile peFile = new PEFile(targetFile)) {
            PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withDigestAlgorithm(SHA1)
                    .withProgramName("WinEyes")
                    .withProgramURL("http://www.steelblue.com/WinEyes");

            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA1);

            // second signature
            signer.withDigestAlgorithm(SHA256);
            signer.withTimestamping(false);
            signer.withSignaturesReplaced(true);
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testInvalidAuthenticodeTimestampingAuthority() throws Exception {
        testInvalidTimestampingAuthority(TimestampingMode.AUTHENTICODE);
    }

    @Test
    public void testInvalidRFC3161TimestampingAuthority() throws Exception {
        testInvalidTimestampingAuthority(TimestampingMode.RFC3161);
    }

    public void testInvalidTimestampingAuthority(TimestampingMode mode) throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamped-unavailable-" + mode.name().toLowerCase() + ".exe");
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(SHA1);
        signer.withTimestamping(true);
        signer.withTimestampingMode(mode);
        signer.withTimestampingAuthority("http://www.google.com/" + mode.name().toLowerCase());
        signer.withTimestampingRetries(1);
        
        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);
            fail("TimestampingException not thrown");
        } catch (TimestampingException e) {
            assertTrue("Missing suppressed IOException", e.getSuppressed() != null && e.getSuppressed().length > 0 && e.getSuppressed()[0].getClass().equals(IOException.class));
            // expected
        }

        SignatureAssert.assertNotSigned(new PEFile(targetFile));
    }

    @Test
    public void testBrokenAuthenticodeTimestampingAuthority() throws Exception {
        testBrokenTimestampingAuthority(TimestampingMode.AUTHENTICODE);
    }

    @Test
    public void testBrokenRFC3161TimestampingAuthority() throws Exception {
        testBrokenTimestampingAuthority(TimestampingMode.RFC3161);
    }

    public void testBrokenTimestampingAuthority(TimestampingMode mode) throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamped-broken-" + mode.name().toLowerCase() + ".exe");
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(SHA1);
        signer.withTimestamping(true);
        signer.withTimestampingMode(mode);
        signer.withTimestampingAuthority("http://github.com");
        signer.withTimestampingRetries(1);
        
        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);
            fail("TimestampingException not thrown");
        } catch (TimestampingException e) {
            // expected
        }

        SignatureAssert.assertNotSigned(new PEFile(targetFile));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidTimestampingURL() throws Exception {
        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(SHA1);
        signer.withTimestamping(true);
        signer.withTimestampingMode(TimestampingMode.RFC3161);
        signer.withTimestampingAuthority("example://example.com");
        signer.withTimestampingRetries(1);

        try (PEFile peFile = new PEFile(new File("target/test-classes/wineyes.exe"))) {
            signer.sign(peFile);
        }
    }

    @Test
    public void testAuthenticodeTimestampingFailover() throws Exception {
        testTimestampingFailover(TimestampingMode.AUTHENTICODE, "http://timestamp.sectigo.com");
    }

    @Test
    public void testRFC3161TimestampingFailover() throws Exception {
        testTimestampingFailover(TimestampingMode.RFC3161, "http://timestamp.sectigo.com");
    }

    public void testTimestampingFailover(TimestampingMode mode, String validURL) throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamped-failover-" + mode.name().toLowerCase() + ".exe");
        
        FileUtils.copyFile(sourceFile, targetFile);

        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD);
        signer.withDigestAlgorithm(SHA256);
        signer.withTimestamping(true);
        signer.withTimestampingMode(mode);
        signer.withTimestampingRetryWait(1);
        signer.withTimestampingAuthority("http://www.google.com/" + mode.name().toLowerCase(), "http://github.com", validURL);

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);
            SignatureAssert.assertTimestamped("Invalid timestamp", peFile.getSignatures().get(0));
        }
    }

    /**
     * Tests that it is possible to specify a signature algorithm.
     */
    @Test
    public void testWithSignatureAlgorithmSHA1withRSA() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        try (PEFile peFile = new PEFile(targetFile)) {
            PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withTimestamping(false)
                    .withDigestAlgorithm(SHA256)
                    .withSignatureAlgorithm("SHA1withRSA");

            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA1);

            // Check the signature algorithm
            CMSSignedData signedData = peFile.getSignatures().get(0);
            SignerInformation si = signedData.getSignerInfos().getSigners().iterator().next();
            assertEquals("Digest algorithm", SHA1.oid, si.getDigestAlgorithmID().getAlgorithm());
            assertEquals("Encryption algorithm", PKCSObjectIdentifiers.rsaEncryption.getId(), si.getEncryptionAlgOID());
        }
    }

    /**
     * Tests that it is possible to specify a signature algorithm who's name is
     * not simply a concatenation of a digest algorithm and the key algorithm.
     *
     * This test also sets the signature provider as a provider supporting
     * the RSASSA-PSS algorithms might not be installed.
     */
    @Test
    public void testWithSignatureAlgorithmSHA256withRSAandMGF1() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        try (PEFile peFile = new PEFile(targetFile)) {
            PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                    .withTimestamping(false)
                    .withDigestAlgorithm(SHA1)
                    .withSignatureAlgorithm("SHA256withRSAandMGF1", "BC");

            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);

            CMSSignedData signedData = peFile.getSignatures().get(0);
            assertNotNull("signature", signedData);

            // Check the signature algorithm
            SignerInformation si = signedData.getSignerInfos().getSigners().iterator().next();
            assertEquals("Digest algorithm", NISTObjectIdentifiers.id_sha256, si.getDigestAlgorithmID().getAlgorithm());
            assertEquals("Encryption algorithm", PKCSObjectIdentifiers.id_RSASSA_PSS.getId(), si.getEncryptionAlgOID());
        }
    }

    @Test
    public void testSignWithECKey() throws Exception {
        KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore-ec.p12").storepass("password").build();

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-ec.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(false)
                .withProgramName("WinEyes")
                .withProgramURL("http://www.steelblue.com/WinEyes");

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSignWithEd25519Key() throws Exception {
        Assume.assumeTrue("EdDSA requires Java 15 or higher", SystemUtils.isJavaVersionAtLeast(JavaVersion.JAVA_15));

        KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore-ed25519.p12").storepass("password").build();

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-ed25519.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSignWithEd448Key() throws Exception {
        Assume.assumeTrue("EdDSA requires Java 15 or higher", SystemUtils.isJavaVersionAtLeast(JavaVersion.JAVA_15));

        KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore-ed448.p12").storepass("password").build();

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-ed448.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, ALIAS, PRIVATE_KEY_PASSWORD).withTimestamping(false);

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testContentDigestAlgorithmIdentifier() throws Exception {
        // ensure the algorithm identifier has a DER NULL optional parameters field to match the signtool output
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        AuthenticodeSigner signer = new AuthenticodeSigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(false)
                .withDigestAlgorithm(SHA256);

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);

            CMSSignedData signature = peFile.getSignatures().get(0);
            AlgorithmIdentifier ai = signature.getDigestAlgorithmIDs().iterator().next();
            assertEquals("Algorithm identifier", signer.digestAlgorithm.oid, ai.getAlgorithm());
            assertEquals("Algorithm parameters", DERNull.INSTANCE, ai.getParameters());
        }
    }

    @Test
    public void testSignWithIncompleteChain() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-completed-chain.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        PESigner signer = new PESigner(getKeyStore(), ALIAS, PRIVATE_KEY_PASSWORD)
                .withTimestamping(false);

        try (PEFile peFile = new PEFile(targetFile)) {
            signer.sign(peFile);

            SignatureAssert.assertSigned(peFile, SHA256);

            CMSSignedData signature = peFile.getSignatures().get(0);

            Collection<X509CertificateHolder> certificates = signature.getCertificates().getMatches(null);
            assertEquals("Number of certificates", 2, certificates.size());
            for (X509CertificateHolder certificate : certificates) {
                if (certificate.getSubject().toString().equals(certificate.getIssuer().toString())) {
                    fail("Root certificate found: " + certificate.getSubject());
                }
            }
        }
    }
}
