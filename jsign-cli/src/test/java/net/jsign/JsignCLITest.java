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
import java.io.FileOutputStream;
import java.net.ProxySelector;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidParameterException;
import java.security.Permission;
import java.security.ProviderException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import io.netty.handler.codec.http.HttpRequest;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.ByteOrderMark;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.littleshoot.proxy.HttpFilters;
import org.littleshoot.proxy.HttpFiltersSourceAdapter;
import org.littleshoot.proxy.HttpProxyServer;
import org.littleshoot.proxy.ProxyAuthenticator;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;

import net.jsign.msi.MSIFile;
import net.jsign.pe.PEFile;
import net.jsign.script.PowerShellScript;

import static net.jsign.DigestAlgorithm.*;
import static org.junit.Assert.*;

public class JsignCLITest {

    private JsignCLI cli;
    private File sourceFile = new File("target/test-classes/wineyes.exe");
    private File targetFile = new File("target/test-classes/wineyes-signed-with-cli.exe");

    private String keystore = "keystore.jks";
    private String alias    = "test";
    private String keypass  = "password";

    private static final long SOURCE_FILE_CRC32 = 0xA6A363D8L;

    @Before
    public void setUp() throws Exception {
        cli = new JsignCLI();

        // remove the files signed previously
        if (targetFile.exists()) {
            assertTrue("Unable to remove the previously signed file", targetFile.delete());
        }

        assertEquals("Source file CRC32", SOURCE_FILE_CRC32, FileUtils.checksumCRC32(sourceFile));
        Thread.sleep(100);
        FileUtils.copyFile(sourceFile, targetFile);
    }

    @After
    public void tearDown() {
        // reset the proxy configuration
        ProxySelector.setDefault(null);
    }

    @Test
    public void testPrintHelp() {
        JsignCLI.main("--help");
    }

    @Test
    public void testMissingKeyStore() {
        assertThrows(SignerException.class, () -> cli.execute("sign", "" + targetFile));
    }

    @Test
    public void testUnsupportedKeyStoreType() {
        assertThrows(IllegalArgumentException.class, () -> cli.execute("--keystore=keystore.jks", "--storetype=ABC", "" + targetFile));
    }

    @Test
    public void testKeyStoreNotFound() {
        assertThrows(SignerException.class, () -> cli.execute("--keystore=keystore2.jks", "" + targetFile));
    }

    @Test
    public void testCorruptedKeyStore() {
        assertThrows(SignerException.class, () -> cli.execute("--keystore=" + targetFile, "" + targetFile));
    }

    @Test
    public void testEmptyKeystore()  {
        Exception e = assertThrows(SignerException.class, () -> cli.execute("--keystore=target/test-classes/keystores/keystore-empty.p12", "--alias=unknown", "" + targetFile));
        assertTrue(e.getMessage().startsWith("No certificate found in the keystore"));
    }

    @Test
    public void testMissingAlias() {
        assertThrows(SignerException.class, () -> cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "" + targetFile));
    }

    @Test
    public void testAliasNotFound() throws Exception  {
        try {
            cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "--alias=unknown", "" + targetFile);
        } catch (SignerException e) {
            assertEquals("message", "No certificate found under the alias 'unknown' in the keystore target/test-classes/keystores/keystore.jks (available aliases: test)", e.getMessage().replace('\\', '/'));
        }
    }

    @Test
    public void testMultipleAliases() {
        Exception e = assertThrows(SignerException.class, () -> cli.execute("--keystore=target/test-classes/keystores/keystore-two-entries.p12", "" + targetFile));
        assertEquals("message", "alias option must be set to select a certificate (available aliases: test, test2)", e.getMessage());
    }

    @Test
    public void testCertificateNotFound() {
        assertThrows(SignerException.class, () -> cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "--alias=foo", "" + targetFile));
    }

    @Test
    public void testMissingFile() {
        assertThrows(SignerException.class, () -> cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "--alias=test", "--keypass=password"));
    }

    @Test
    public void testFileNotFound() {
        assertThrows(SignerException.class, () -> cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "--alias=test", "--keypass=password", "wineyes-foo.exe"));
    }

    @Test
    public void testCorruptedFile() {
        assertThrows(SignerException.class, () -> cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "--alias=test", "--keypass=password", "target/test-classes/keystore.jks"));
    }

    @Test
    public void testConflictingAttributes() {
        assertThrows(SignerException.class, () -> cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "--alias=test", "--keypass=password", "--keyfile=privatekey.pvk", "--certfile=jsign-test-certificate-full-chain.spc", "" + targetFile));
    }

    @Test
    public void testMissingCertFile() {
        assertThrows(SignerException.class, () -> cli.execute("--keyfile=target/test-classes/keystores/privatekey.pvk", "" + targetFile));
    }

    @Test
    public void testMissingKeyFile() {
        assertThrows(SignerException.class, () -> cli.execute("--certfile=target/test-classes/keystores/jsign-test-certificate-full-chain.spc", "" + targetFile));
    }

    @Test
    public void testCertFileNotFound() {
        assertThrows(SignerException.class, () -> cli.execute("--certfile=target/test-classes/keystores/certificate2.spc", "--keyfile=target/test-classes/privatekey.pvk", "" + targetFile));
    }

    @Test
    public void testKeyFileNotFound() {
        assertThrows(SignerException.class, () -> cli.execute("--certfile=target/test-classes/keystores/jsign-test-certificate-full-chain.spc", "--keyfile=target/test-classes/privatekey2.pvk", "" + targetFile));
    }

    @Test
    public void testCorruptedCertFile() {
        assertThrows(SignerException.class, () -> cli.execute("--certfile=target/test-classes/keystores/privatekey.pvk", "--keyfile=target/test-classes/privatekey.pvk", "" + targetFile));
    }

    @Test
    public void testCorruptedKeyFile() {
        assertThrows(SignerException.class, () -> cli.execute("--certfile=target/test-classes/keystores/jsign-test-certificate-full-chain.spc", "--keyfile=target/test-classes/jsign-test-certificate-full-chain.spc", "" + targetFile));
    }

    @Test
    public void testUnsupportedDigestAlgorithm() {
        assertThrows(SignerException.class, () -> cli.execute("--alg=SHA-123", "--keystore=target/test-classes/keystores/keystore.jks", "--alias=test", "--keypass=password", "" + targetFile));
    }

    @Test
    public void testSigning() throws Exception {
        cli.execute("--name=WinEyes", "--url=http://www.steelblue.com/WinEyes", "--alg=SHA-1", "--keystore=target/test-classes/keystores/" + keystore, "--keypass=" + keypass, "" + targetFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA1);
        }
    }

    @Test
    public void testSigningMultipleFiles() throws Exception {
        cli.execute("--name=WinEyes", "--url=http://www.steelblue.com/WinEyes", "--alg=SHA-1", "--keystore=target/test-classes/keystores/" + keystore, "--keypass=" + keypass, "" + targetFile, "" + targetFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA1, SHA1);
        }
    }

    @Test
    public void testSigningMultipleFilesWithListFile() throws Exception {
        File listFile = new File("target/test-classes/files.txt");
        Files.write(listFile.toPath(), Arrays.asList("# first file", '"' + targetFile.getPath() + '"', " ", "# second file", targetFile.getAbsolutePath()));

        cli.execute("--name=WinEyes", "--url=http://www.steelblue.com/WinEyes", "--alg=SHA-1", "--keystore=target/test-classes/keystores/" + keystore, "--keypass=" + keypass, "@" + listFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA1, SHA1);
        }
    }

    @Test
    public void testSigningMultipleFilesWithListFileUTF16() throws Exception {
        File listFile = new File("target/test-classes/files-utf16.txt");
        try (FileOutputStream out = new FileOutputStream(listFile)) {
            out.write(ByteOrderMark.UTF_16LE.getBytes());
            IOUtils.writeLines(Arrays.asList(targetFile.getAbsolutePath(), targetFile.getAbsolutePath()), "\r\n", out, StandardCharsets.UTF_16LE);
        }

        cli.execute("--name=WinEyes", "--url=http://www.steelblue.com/WinEyes", "--alg=SHA-1", "--keystore=target/test-classes/keystores/" + keystore, "--keypass=" + keypass, "@" + listFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA1, SHA1);
        }
    }

    @Test
    public void testSigningMultipleFilesWithPattern() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile1 = new File("target/test-classes/wineyes-pattern1.exe");
        targetFile1.delete();
        File targetFile2 = new File("target/test-classes/wineyes-pattern2.exe");
        targetFile2.delete();
        FileUtils.copyFile(sourceFile, targetFile1);
        FileUtils.copyFile(sourceFile, targetFile2);

        cli.execute("--keystore=target/test-classes/keystores/" + keystore, "--keypass=" + keypass, "target/**/*-pattern*.exe");

        try (PEFile peFile = new PEFile(targetFile1)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
        try (PEFile peFile = new PEFile(targetFile2)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSigningPowerShell() throws Exception {
        File sourceFile = new File("target/test-classes/hello-world.ps1");
        File targetFile = new File("target/test-classes/hello-world-signed-with-cli.ps1");
        FileUtils.copyFile(sourceFile, targetFile);

        cli.execute("--alg=SHA-1", "--replace", "--encoding=ISO-8859-1", "--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "" + targetFile);

        PowerShellScript script = new PowerShellScript(targetFile);

        SignatureAssert.assertSigned(script, SHA1);
    }

    @Test
    public void testSigningPowerShellWithDefaultEncoding() throws Exception {
        File sourceFile = new File("target/test-classes/hello-world.ps1");
        File targetFile = new File("target/test-classes/hello-world-signed-with-cli.ps1");
        FileUtils.copyFile(sourceFile, targetFile);

        cli.execute("--alg=SHA-1", "--replace", "--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "" + targetFile);

        PowerShellScript script = new PowerShellScript(targetFile);

        SignatureAssert.assertSigned(script, SHA1);
    }

    @Test
    public void testSigningMSI() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msi");
        File targetFile = new File("target/test-classes/minimal-signed-with-cli.msi");
        FileUtils.copyFile(sourceFile, targetFile);

        cli.execute("--alg=SHA-1", "--replace", "--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "" + targetFile);

        try (MSIFile file = new MSIFile(targetFile)) {
            SignatureAssert.assertSigned(file, SHA1);
        }
    }

    @Test
    public void testSigningPKCS12() throws Exception {
        cli.execute("--name=WinEyes", "--url=http://www.steelblue.com/WinEyes", "--alg=SHA-256", "--keystore=target/test-classes/keystores/keystore.p12", "--alias=test", "--storepass=password", "" + targetFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSigningJCEKS() throws Exception {
        cli.execute("--name=WinEyes", "--url=http://www.steelblue.com/WinEyes", "--alg=SHA-256", "--keystore=target/test-classes/keystores/keystore.jceks", "--alias=test", "--storepass=password", "" + targetFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSigningJKS() throws Exception {
        cli.execute("--name=WinEyes", "--url=http://www.steelblue.com/WinEyes", "--alg=SHA-256", "--keystore=target/test-classes/keystores/keystore.jks", "--alias=test", "--storepass=password", "" + targetFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSigningPVKSPC() throws Exception {
        cli.execute("--url=http://www.steelblue.com/WinEyes", "--certfile=target/test-classes/keystores/jsign-test-certificate-full-chain.spc", "--keyfile=target/test-classes/keystores/privatekey-encrypted.pvk", "--storepass=password", "" + targetFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSigningPEM() throws Exception {
        cli.execute("--certfile=target/test-classes/keystores/jsign-test-certificate.pem", "--keyfile=target/test-classes/keystores/privatekey.pkcs8.pem", "--keypass=password", "" + targetFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSigningEncryptedPEM() throws Exception {
        cli.execute("--certfile=target/test-classes/keystores/jsign-test-certificate.pem", "--keyfile=target/test-classes/keystores/privatekey-encrypted.pkcs1.pem", "--keypass=password", "" + targetFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSigningWithYubikey() throws Exception {
        Assume.assumeTrue("No Yubikey detected", YubiKeyKeyStore.isPresent());

        cli.execute("--storetype=YUBIKEY", "--certfile=target/test-classes/keystores/jsign-test-certificate-full-chain.spc", "--storepass=123456", "--alias=X.509 Certificate for Digital Signature", "" + targetFile, "" + targetFile);
    }

    @Test
    public void testTimestampingAuthenticode() throws Exception {
        File targetFile2 = new File("target/test-classes/wineyes-timestamped-with-cli-authenticode.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        cli.execute("--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "--tsaurl=http://timestamp.sectigo.com", "--tsmode=authenticode", "" + targetFile2);

        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));

        try (PEFile peFile = new PEFile(targetFile2)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testTimestampingRFC3161() throws Exception {
        File targetFile2 = new File("target/test-classes/wineyes-timestamped-with-cli-rfc3161.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        cli.execute("--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "--tsaurl=http://timestamp.sectigo.com", "--tsmode=rfc3161", "" + targetFile2);

        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));

        try (PEFile peFile = new PEFile(targetFile2)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testTimestampingWithProxyUnauthenticated() throws Exception {
        final AtomicBoolean proxyUsed = new AtomicBoolean(false);
        HttpProxyServer proxy = DefaultHttpProxyServer.bootstrap().withPort(12543)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest originalRequest) {
                        proxyUsed.set(true);
                        return super.filterRequest(originalRequest);
                    }
                })
                .start();

        try {
            File targetFile2 = new File("target/test-classes/wineyes-timestamped-with-cli-rfc3161-proxy-unauthenticated.exe");
            FileUtils.copyFile(sourceFile, targetFile2);
            cli.execute("--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass,
                        "--tsaurl=http://timestamp.sectigo.com", "--tsmode=rfc3161", "--tsretries=1", "--tsretrywait=1",
                        "--proxyUrl=localhost:" + proxy.getListenAddress().getPort(),
                        "" + targetFile2);

            assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));
            assertTrue("The proxy wasn't used", proxyUsed.get());

            try (PEFile peFile = new PEFile(targetFile2)) {
                SignatureAssert.assertSigned(peFile, SHA256);
            }
        } finally {
            proxy.stop();
        }
    }

    @Test
    public void testTimestampingWithProxyAuthenticated() throws Exception {
        final AtomicBoolean proxyUsed = new AtomicBoolean(false);
        HttpProxyServer proxy = DefaultHttpProxyServer.bootstrap().withPort(12544)
                .withFiltersSource(new HttpFiltersSourceAdapter() {
                    @Override
                    public HttpFilters filterRequest(HttpRequest originalRequest) {
                        proxyUsed.set(true);
                        return super.filterRequest(originalRequest);
                    }
                })
                .withProxyAuthenticator(new ProxyAuthenticator() {
                    @Override
                    public boolean authenticate(String username, String password) {
                        return "jsign".equals(username) && "jsign".equals(password);
                    }

                    @Override
                    public String getRealm() {
                        return "Jsign Tests";
                    }
                })
                .start();

        try {
            File targetFile2 = new File("target/test-classes/wineyes-timestamped-with-cli-rfc3161-proxy-authenticated.exe");
            FileUtils.copyFile(sourceFile, targetFile2);
            cli.execute("--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass,
                        "--tsaurl=http://timestamp.sectigo.com", "--tsmode=rfc3161", "--tsretries=1", "--tsretrywait=1",
                        "--proxyUrl=http://localhost:" + proxy.getListenAddress().getPort(),
                        "--proxyUser=jsign",
                        "--proxyPass=jsign",
                        "" + targetFile2);

            assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));
            assertTrue("The proxy wasn't used", proxyUsed.get());

            try (PEFile peFile = new PEFile(targetFile2)) {
                SignatureAssert.assertSigned(peFile, SHA256);
            }
        } finally {
            proxy.stop();
        }
    }

    @Test
    public void testReplaceSignature() throws Exception {
        File targetFile2 = new File("target/test-classes/wineyes-re-signed.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        cli.execute("--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "" + targetFile2);

        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));

        cli.execute("--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "--alg=SHA-512", "--replace", "" + targetFile2);

        try (PEFile peFile = new PEFile(targetFile2)) {
            SignatureAssert.assertSigned(peFile, SHA512);
        }
    }

    @Test
    public void testDetachedSignature() throws Exception {
        File targetFile2 = new File("target/test-classes/wineyes-signed-detached.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        cli.execute("--keystore=target/test-classes/keystores/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "--detached", "" + targetFile2);

        assertTrue("Signature wasn't detached", new File("target/test-classes/wineyes-signed-detached.exe.sig").exists());
    }

    @Test
    public void testExitOnError() {
        NoExitSecurityManager manager = new NoExitSecurityManager();
        System.setSecurityManager(manager);

        try {
            assertThrows("VM not terminated", SecurityException.class, () -> JsignCLI.main("foo.exe"));
            assertEquals("Exit code", Integer.valueOf(1), manager.getStatus());
        } finally {
            System.setSecurityManager(null);
        }
    }

    private static class NoExitSecurityManager extends SecurityManager {
        private Integer status;

        public Integer getStatus() {
            return status;
        }

        public void checkPermission(Permission perm) { }

        public void checkPermission(Permission perm, Object context) { }

        public void checkExit(int status) {
            this.status = status;
            throw new SecurityException("Exit disabled");
        }
    }

    @Test
    public void testUnknownOption() {
        assertThrows(ParseException.class, () -> cli.execute("--jsign"));
    }

    @Test
    public void testUnknownPKCS11Provider() {
        Exception e = assertThrows(SignerException.class, () -> cli.execute("--storetype=PKCS11", "--keystore=SunPKCS11-jsigntest", "--keypass=password", "" + targetFile));
        assertEquals("message", "Security provider SunPKCS11-jsigntest not found", e.getMessage());}

    @Test
    public void testMissingPKCS11Configuration() {
        Exception e = assertThrows(SignerException.class, () -> cli.execute("--storetype=PKCS11", "--keystore=jsigntest.cfg", "--keypass=password", "" + targetFile));
        assertEquals("message", "keystore option should either refer to the SunPKCS11 configuration file or to the name of the provider configured in jre/lib/security/java.security", e.getMessage());
    }

    @Test
    public void testBrokenPKCS11Configuration() {
        Exception e = assertThrows(SignerException.class, () -> cli.execute("--storetype=PKCS11", "--keystore=pom.xml", "--keypass=password", "" + targetFile));
        assertTrue(e.getCause() instanceof ProviderException // JDK < 9
                || e.getCause().getCause() instanceof InvalidParameterException); // JDK 9+
    }

    @Test
    public void testOverrideKeyStoreCertificate() throws Exception {
        cli.execute("--keystore=target/test-classes/keystores/keystore-2022.p12", "--alias=test", "--storepass=password", "--certfile=target/test-classes/keystores/jsign-test-certificate-full-chain.spc", "" + targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            SignatureAssert.assertSigned(signable, SHA256);
            CMSSignedData signature = signable.getSignatures().get(0);
            assertEquals("issuer", "CN=Jsign Code Signing CA 2024", signature.getSignerInfos().iterator().next().getSID().getIssuer().toString());
        }
    }

    @Test
    public void testUnknownCommand() {
        Exception e = assertThrows(ParseException.class, () -> cli.execute("unsign", "" + targetFile));
        assertEquals("message", "Unknown command 'unsign'", e.getMessage());
    }

    @Test
    public void testExtract() {
        Exception e = assertThrows(SignerException.class, () -> cli.execute("extract", "" + targetFile));
        assertEquals("message", "No signature found in " + targetFile.getPath(), e.getMessage());
    }

    @Test
    public void testRemove() {
        Exception e = assertThrows(SignerException.class, () -> cli.execute("remove", "xeyes.exe"));
        assertEquals("message", "Couldn't find xeyes.exe", e.getMessage());
    }

    @Test
    public void testTag() {
        Exception e = assertThrows(SignerException.class, () -> cli.execute("tag", "--value", "userid:1234-ABCD-5678-EFGH", "" + targetFile));
        assertEquals("message", "No signature found in " + targetFile.getPath(), e.getMessage());
    }

    @Test
    public void testTimestamp() {
        Exception e = assertThrows(SignerException.class, () -> cli.execute("timestamp", "" + targetFile));
        assertEquals("message", "No signature found in " + targetFile.getPath(), e.getMessage());
    }
}
