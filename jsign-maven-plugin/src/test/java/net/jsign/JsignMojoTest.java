/**
 * Copyright 2017 Emmanuel Bourg
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
import java.util.Collections;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.testing.AbstractMojoTestCase;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.apache.maven.shared.model.fileset.FileSet;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import static org.junit.Assert.*;

public class JsignMojoTest extends AbstractMojoTestCase {

    private JsignMojo getMojo() throws Exception {
        File pom = getTestFile("target/test-classes/test-pom.xml");
        assertNotNull("null pom", pom);
        assertTrue("pom not found", pom.exists());

        JsignMojo mojo = lookupMojo("sign", pom);
        assertNotNull("plugin not found", mojo);

        MavenProject project = new MavenProject();
        project.setFile(pom);
        setVariableValueToObject(mojo, "project", project);

        return mojo;
    }

    public void testMojo() throws Exception {
        JsignMojo mojo = getMojo();

        Exception e = assertThrows(MojoFailureException.class, mojo::execute);
        assertEquals("Either keystore, or keyfile and certfile, or storetype elements must be set", e.getCause().getMessage());
    }

    public void testFileSet() throws Exception {
        FileSet fileset = new FileSet();
        fileset.setDirectory("target/test-classes/");
        fileset.addInclude("*.exe");

        JsignMojo mojo = getMojo();
        setVariableValueToObject(mojo, "file", null);
        setVariableValueToObject(mojo, "fileset", fileset);

        Exception e = assertThrows(MojoFailureException.class, mojo::execute);
        assertEquals("Either keystore, or keyfile and certfile, or storetype elements must be set", e.getCause().getMessage());
    }

    public void testMissingFileAndFileSet() throws Exception {
        JsignMojo mojo = getMojo();
        setVariableValueToObject(mojo, "file", null);
        setVariableValueToObject(mojo, "fileset", null);

        Exception e = assertThrows(MojoExecutionException.class, mojo::execute);
        assertEquals("file or fileset must be set", e.getMessage());
    }

    public void testInvalidProxyId() throws Exception {
        JsignMojo mojo = getMojo();

        Proxy proxy = new Proxy();
        proxy.setHost("example.com");
        proxy.setPort(1080);
        proxy.setUsername("johndoe");
        proxy.setPassword("secret");

        Settings settings = new Settings();
        settings.setProxies(Collections.singletonList(proxy));

        setVariableValueToObject(mojo, "settings", settings);
        setVariableValueToObject(mojo, "proxyId", "proxima");

        Exception e = assertThrows(MojoExecutionException.class, mojo::execute);
        assertEquals("Configured proxy with id=proxima not found", e.getMessage());
    }

    public void testValidProxyId() throws Exception {
        JsignMojo mojo = getMojo();

        Proxy proxy = new Proxy();
        proxy.setId("proxima");
        proxy.setHost("example.com");
        proxy.setPort(1080);
        proxy.setUsername("johndoe");
        proxy.setPassword("secret");

        Settings settings = new Settings();
        settings.setProxies(Collections.singletonList(proxy));

        setVariableValueToObject(mojo, "settings", settings);

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");
        setVariableValueToObject(mojo, "tsmode", "Authenticode");
        setVariableValueToObject(mojo, "tsretries", 1);
        setVariableValueToObject(mojo, "tsretrywait", 1);
        setVariableValueToObject(mojo, "proxyId", "proxima");

        Exception e = assertThrows(MojoFailureException.class, mojo::execute);
        assertEquals("Unable to complete the timestamping after 1 attempt", ExceptionUtils.getRootCause(e).getMessage());
    }

    public void testInvalidProxyProtocol() throws Exception {
        JsignMojo mojo = getMojo();

        Proxy proxy = new Proxy();
        proxy.setId("proxima");
        proxy.setProtocol("mal:formed/");
        proxy.setHost("example.com");
        proxy.setPort(1080);
        proxy.setUsername("johndoe");
        proxy.setPassword("secret");

        Settings settings = new Settings();
        settings.setProxies(Collections.singletonList(proxy));

        setVariableValueToObject(mojo, "settings", settings);

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");
        setVariableValueToObject(mojo, "proxyId", "proxima");

        Exception e = assertThrows(MojoFailureException.class, mojo::execute);
        assertEquals("Couldn't initialize proxy", e.getMessage());
    }

    public void testActiveProxy() throws Exception {
        JsignMojo mojo = getMojo();

        Proxy proxy = new Proxy();
        proxy.setHost("example.com");
        proxy.setPort(1080);
        proxy.setActive(true);
        proxy.setUsername("johndoe");
        proxy.setPassword("secret");

        Settings settings = new Settings();
        settings.setProxies(Collections.singletonList(proxy));

        setVariableValueToObject(mojo, "settings", settings);

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");
        setVariableValueToObject(mojo, "tsmode", "Authenticode");
        setVariableValueToObject(mojo, "tsretries", 1);
        setVariableValueToObject(mojo, "tsretrywait", 1);

        Exception e = assertThrows(MojoFailureException.class, mojo::execute);
        assertEquals("Unable to complete the timestamping after 1 attempt", ExceptionUtils.getRootCause(e).getMessage());
    }

    public void testBrokenSecurityDispatcher() throws Exception {
        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "securityDispatcher", (SecDispatcher) str -> { throw new SecDispatcherException(); });
        
        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");

        Exception e = assertThrows(MojoExecutionException.class, mojo::execute);
        assertEquals("error using security dispatcher: null", e.getMessage());
    }

    public void testSignUnsupportedFile() throws Exception {
        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "file", new File("pom.xml"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");

        Exception e = assertThrows(MojoFailureException.class, mojo::execute);
        assertEquals("Unsupported file: pom.xml", e.getMessage());
    }

    public void testDetachedSignature() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-maven.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "file", targetFile);
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");
        setVariableValueToObject(mojo, "detached", Boolean.TRUE);

        mojo.execute();

        assertTrue("Signature wasn't detached", new File("target/test-classes/wineyes-signed-with-maven.exe.sig").exists());
    }

    public void testSkip() throws Exception {
        File detachedSignature = new File("target/test-classes/wineyes.exe.sig");
        if (detachedSignature.exists()) {
            assertTrue(detachedSignature.delete());
        }

        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");
        setVariableValueToObject(mojo, "detached", Boolean.TRUE);
        setVariableValueToObject(mojo, "skip", Boolean.TRUE);

        mojo.execute();

        assertFalse("Signing not skipped", new File("target/test-classes/wineyes.exe.sig").exists());
    }

    public void testPasswordFromSettings() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-maven.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        File detachedSignature = new File("target/test-classes/wineyes.exe.sig");
        if (detachedSignature.exists()) {
            assertTrue(detachedSignature.delete());
        }

        JsignMojo mojo = getMojo();

        Server server = new Server();
        server.setId("jsign");
        server.setPassword("password");

        Settings settings = new Settings();
        settings.setServers(Collections.singletonList(server));

        setVariableValueToObject(mojo, "settings", settings);

        setVariableValueToObject(mojo, "file", targetFile);
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "mvn:jsign");
        setVariableValueToObject(mojo, "detached", Boolean.TRUE);

        mojo.execute();

        assertTrue("File wasn't signed", new File("target/test-classes/wineyes-signed-with-maven.exe.sig").exists());
    }

    public void testPassphraseFromSettings() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-maven.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        File detachedSignature = new File("target/test-classes/wineyes.exe.sig");
        if (detachedSignature.exists()) {
            assertTrue(detachedSignature.delete());
        }

        JsignMojo mojo = getMojo();

        Server server = new Server();
        server.setId("jsign");
        server.setPassphrase("password");

        Settings settings = new Settings();
        settings.setServers(Collections.singletonList(server));

        setVariableValueToObject(mojo, "settings", settings);

        setVariableValueToObject(mojo, "file", targetFile);
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "mvn:jsign");
        setVariableValueToObject(mojo, "detached", Boolean.TRUE);

        mojo.execute();

        assertTrue("File wasn't signed", new File("target/test-classes/wineyes-signed-with-maven.exe.sig").exists());
    }

    public void testMissingServerFromSettings() throws Exception {
        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "settings", new Settings());

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "mvn:jsign");

        Exception e = assertThrows(MojoExecutionException.class, mojo::execute);
        assertEquals("Server 'jsign' not found in settings.xml", e.getMessage());
    }

    public void testMissingPasswordFromSettings() throws Exception {
        JsignMojo mojo = getMojo();

        Server server = new Server();
        server.setId("jsign");

        Settings settings = new Settings();
        settings.setServers(Collections.singletonList(server));

        setVariableValueToObject(mojo, "settings", settings);

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "mvn:jsign");

        Exception e = assertThrows(MojoExecutionException.class, mojo::execute);
        assertEquals("No password or passphrase found for server 'jsign' in settings.xml", e.getMessage());
    }

    public void testTag() throws Exception {
        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "command", "tag");
        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));

        Exception e = assertThrows(MojoFailureException.class, mojo::execute);
        assertEquals("message", "No signature found in target/test-classes/wineyes.exe", ExceptionUtils.getRootCause(e).getMessage().replace('\\', '/'));
    }
}
