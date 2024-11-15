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

import java.io.IOException;
import java.net.UnknownServiceException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class AmazonIMDS2ClientTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    @Test
    public void testAzureEnvironment() {
        onRequest()
                .havingMethodEqualTo("PUT")
                .havingPathEqualTo("/latest/api/token")
                .respond()
                .withStatus(411);

        AmazonIMDS2Client client = new AmazonIMDS2Client();
        client.setEndpoint("http://localhost:" + port());

        Exception e = assertThrows(IOException.class, client::getCredentials);
        assertEquals("message", "IMDSv2 host did not respond as expected; are you in AWS cloud?", e.getMessage());
    }

    @Test
    public void testDisabled() {
        onRequest()
                .havingMethodEqualTo("PUT")
                .havingPathEqualTo("/latest/api/token")
                .respond()
                .withStatus(403);

        AmazonIMDS2Client client = new AmazonIMDS2Client();
        client.setEndpoint("http://localhost:" + port());

        Exception e = assertThrows(UnknownServiceException.class, client::getCredentials);
        assertEquals("message", "IMDSv2 is possibly disabled on this host", e.getMessage());
    }

    @Test
    public void testUnreachable() {
        AmazonIMDS2Client client = new AmazonIMDS2Client();
        client.setEndpoint("http://localhost:31457");

        Exception e = assertThrows(IOException.class, client::getCredentials);
        assertEquals("message", "IMDSv2 host was unreachable; check the hop limit if containerized", e.getMessage());
    }

    @Test
    public void testServerError() {
        onRequest()
                .havingMethodEqualTo("PUT")
                .havingPathEqualTo("/latest/api/token")
                .respond()
                .withStatus(503);

        AmazonIMDS2Client client = new AmazonIMDS2Client();
        client.setEndpoint("http://localhost:" + port());

        Exception e = assertThrows(IOException.class, client::getCredentials);
        assertTrue("message", e.getMessage().startsWith("HTTP Error 503 - Service Unavailable"));
    }

    @Test
    public void testNoInstanceProfile() {
        onRequest()
                .havingMethodEqualTo("PUT")
                .havingPathEqualTo("/latest/api/token")
                .respond()
                .withStatus(200)
                .withBody("0123456789ABCDEF");

        AmazonIMDS2Client client = new AmazonIMDS2Client();
        client.setEndpoint("http://localhost:" + port());

        Exception e = assertThrows(RuntimeException.class, client::getCredentials);
        assertEquals("message", "This EC2 instance seems not to be associated with an instance profile", e.getMessage());
    }

    @Test
    public void testGetInstanceProfileName() throws Exception {
        onRequest()
                .havingMethodEqualTo("PUT")
                .havingPathEqualTo("/latest/api/token")
                .respond()
                .withStatus(200)
                .withBody("0123456789ABCDEF");

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/latest/meta-data/iam/security-credentials")
                .havingHeaderEqualTo("X-aws-ec2-metadata-token", "0123456789ABCDEF")
                .respond()
                .withStatus(200)
                .withBody("role1\nrole2\nrole3");

        AmazonIMDS2Client client = new AmazonIMDS2Client();
        client.setEndpoint("http://localhost:" + port());

        String profile = client.getInstanceProfileName();

        assertEquals("profile", "role1", profile);
    }

    @Test
    public void testInvalidInstanceProfileName() {
        onRequest()
                .havingMethodEqualTo("PUT")
                .havingPathEqualTo("/latest/api/token")
                .respond()
                .withStatus(200)
                .withBody("0123456789ABCDEF");

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/latest/meta-data/iam/security-credentials")
                .havingHeaderEqualTo("X-aws-ec2-metadata-token", "0123456789ABCDEF")
                .respond()
                .withStatus(200)
                .withBody("!role");

        AmazonIMDS2Client client = new AmazonIMDS2Client();
        client.setEndpoint("http://localhost:" + port());

        Exception e = assertThrows(RuntimeException.class, client::getInstanceProfileName);
        assertEquals("message", "Unable to read the instance profile name", e.getMessage());
    }

    @Test
    public void testGetCredentials() throws Exception {
        onRequest()
                .havingMethodEqualTo("PUT")
                .havingPathEqualTo("/latest/api/token")
                .respond()
                .withStatus(200)
                .withBody("0123456789ABCDEF");

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/latest/meta-data/iam/security-credentials")
                .havingHeaderEqualTo("X-aws-ec2-metadata-token", "0123456789ABCDEF")
                .respond()
                .withStatus(200)
                .withBody("role1\nrole1\nrole1");

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/latest/meta-data/iam/security-credentials/role1")
                .havingHeaderEqualTo("X-aws-ec2-metadata-token", "0123456789ABCDEF")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "\"Code\" : \"Success\", " +
                        "\"AccessKeyId\" : \"accessKey\", " +
                        "\"SecretAccessKey\" : \"secretKey\", " +
                        "\"Token\" : \"sessionToken\"" +
                        "}");

        AmazonIMDS2Client client = new AmazonIMDS2Client();
        client.setEndpoint("http://localhost:" + port());

        AmazonCredentials credentials = client.getCredentials();
        assertNotNull("credentials", credentials);
        assertEquals("access key", "accessKey", credentials.getAccessKey());
        assertEquals("secret key", "secretKey", credentials.getSecretKey());
        assertEquals("session token", "sessionToken", credentials.getSessionToken());
    }
}
