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

        try {
            mojo.execute();
        } catch (MojoFailureException e) {
            // expected
            assertEquals("Either keystore, or keyfile and certfile, or storetype elements must be set", e.getCause().getMessage());
        }
    }

    public void testFileSet() throws Exception {
        FileSet fileset = new FileSet();
        fileset.setDirectory("target/test-classes/");
        fileset.addInclude("*.exe");

        JsignMojo mojo = getMojo();
        setVariableValueToObject(mojo, "file", null);
        setVariableValueToObject(mojo, "fileset", fileset);

        try {
            mojo.execute();
        } catch (MojoFailureException e) {
            // expected
            assertEquals("Either keystore, or keyfile and certfile, or storetype elements must be set", e.getCause().getMessage());
        }
    }

    public void testMissingFileAndFileSet() throws Exception {
        JsignMojo mojo = getMojo();
        setVariableValueToObject(mojo, "file", null);
        setVariableValueToObject(mojo, "fileset", null);

        try {
            mojo.execute();
        } catch (MojoExecutionException e) {
            // expected
            assertEquals("file of fileset must be set", e.getMessage());
        }
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

        try {
            mojo.execute();
        } catch (MojoExecutionException e) {
            // expected
            assertEquals("Configured proxy with id=proxima not found", e.getMessage());
        }
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

        try {
            mojo.execute();
        } catch (MojoFailureException e) {
            // expected
            Throwable rootCause = e;
            while (rootCause.getCause() != null) {
                rootCause = rootCause.getCause();
            }
            assertEquals("Unable to complete the timestamping after 1 attempt", rootCause.getMessage());
        }
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

        try {
            mojo.execute();
        } catch (MojoFailureException e) {
            // expected
            assertEquals("Couldn't initialize proxy", e.getMessage());
        }
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

        try {
            mojo.execute();
        } catch (MojoFailureException e) {
            // expected
            Throwable rootCause = e;
            while (rootCause.getCause() != null) {
                rootCause = rootCause.getCause();
            }
            assertEquals("Unable to complete the timestamping after 1 attempt", rootCause.getMessage());
        }
    }

    public void testBrokenSecurityDispatcher() throws Exception {
        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "securityDispatcher", (SecDispatcher) str -> { throw new SecDispatcherException(); });
        
        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");

        try {
            mojo.execute();
        } catch (MojoExecutionException e) {
            // expected
            assertEquals("error using security dispatcher: null", e.getMessage());
        }
    }

    public void testSignUnsupportedFile() throws Exception {
        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "file", new File("pom.xml"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");

        try {
            mojo.execute();
        } catch (MojoFailureException e) {
            // expected
            assertEquals("Unsupported file: pom.xml", e.getMessage());
        }
    }

    public void testDetachedSignature() throws Exception {
        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "password");
        setVariableValueToObject(mojo, "detached", Boolean.TRUE);

        mojo.execute();

        assertTrue("Signature wasn't detached", new File("target/test-classes/wineyes.exe.sig").exists());
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

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "mvn:jsign");
        setVariableValueToObject(mojo, "detached", Boolean.TRUE);

        mojo.execute();

        assertTrue("File wasn't signed", new File("target/test-classes/wineyes.exe.sig").exists());
    }

    public void testPassphraseFromSettings() throws Exception {
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

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "mvn:jsign");
        setVariableValueToObject(mojo, "detached", Boolean.TRUE);

        mojo.execute();

        assertTrue("File wasn't signed", new File("target/test-classes/wineyes.exe.sig").exists());
    }

    public void testMissingServerFromSettings() throws Exception {
        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "settings", new Settings());

        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));
        setVariableValueToObject(mojo, "keystore", "keystores/keystore.jks");
        setVariableValueToObject(mojo, "alias", "test");
        setVariableValueToObject(mojo, "keypass", "mvn:jsign");

        try {
            mojo.execute();
        } catch (MojoExecutionException e) {
            // expected
            assertEquals("Server 'jsign' not found in settings.xml", e.getMessage());
        }
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

        try {
            mojo.execute();
        } catch (MojoExecutionException e) {
            // expected
            assertEquals("No password or passphrase found for server 'jsign' in settings.xml", e.getMessage());
        }
    }

    public void testTag() throws Exception {
        JsignMojo mojo = getMojo();

        setVariableValueToObject(mojo, "command", "tag");
        setVariableValueToObject(mojo, "file", new File("target/test-classes/wineyes.exe"));

        try {
            mojo.execute();
        } catch (MojoFailureException e) {
            // expected
            Throwable rootCause = e;
            while (rootCause.getCause() != null) {
                rootCause = rootCause.getCause();
            }
            assertEquals("message", "No signature found in target/test-classes/wineyes.exe", rootCause.getMessage().replace('\\', '/'));
        }
    }
}
