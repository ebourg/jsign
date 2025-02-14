/*
 * Copyright 2024 Emmanuel Bourg
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
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import net.jsign.DigestAlgorithm;
import net.jsign.PrivateKeyUtils;

/**
 * Oracle Cloud credentials loaded from the <code>.oci/config</code> file or from the environment variables.
 * 
 * @since 7.0
 */
public class OracleCloudCredentials {

    private String user;
    private String tenancy;
    private String region;
    private String keyfile;
    private String fingerprint;
    private String passphrase;
    private PrivateKey privateKey;

    public String getUser() {
        return user;
    }

    public String getTenancy() {
        return tenancy;
    }

    public String getRegion() {
        return region;
    }

    public String getKeyfile() {
        return keyfile;
    }

    public String getFingerprint() {
        if (fingerprint == null) {
            try {
                fingerprint = getFingerprint(getPrivateKey());
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("Unable to compute the OCI API key fingerprint", e);
            }
        }
        return fingerprint;
    }

    /**
     * Compute the fingerprint of the specified key (i.e. the MD5 hash of the public key in DER format)
     * @see <a href="https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#four">How to Get the Key's Fingerprint</a>
     */
    String getFingerprint(PrivateKey privateKey) throws GeneralSecurityException {
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
        byte[] digest = DigestAlgorithm.MD5.getMessageDigest().digest(publicKey.getEncoded());
        return IntStream.range(0, digest.length).mapToObj(i -> String.format("%02x", digest[i])).collect(Collectors.joining(":"));
    }

    public String getPassphrase() {
        return passphrase;
    }

    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }

    public String getKeyId() {
        return getTenancy() + "/" + getUser() + "/" + getFingerprint();
    }

    PrivateKey getPrivateKey() {
        if (privateKey == null) {
            try {
                privateKey = PrivateKeyUtils.load(new File(getKeyfile()), getPassphrase());
            } catch (KeyException e) {
                throw new RuntimeException("Unable to load the private key", e);
            }
        }
        return privateKey;
    }

    /**
     * Loads the credentials from the specified file.
     *
     * @param file    the configuration file (null for the default location)
     * @param profile the name of the profile (null for the default profile)
     */
    public void load(File file, String profile) throws IOException {
        if (file == null) {
            file = getConfigFile();
        }
        if (profile == null) {
            profile = getDefaultProfile();
        }

        Properties properties = new Properties();

        // parse le lines of the file
        boolean profileFound = false;
        for (String line : Files.readAllLines(file.toPath())) {
            if (profileFound && line.startsWith("[")) {
                break; // end of the profile
            }

            if (line.equals("[" + profile + "]")) {
                profileFound = true;
                continue;
            }

            if (profileFound) {
                String[] elements = line.split("=", 2);
                if (elements.length == 2) {
                    properties.setProperty(elements[0].trim(), elements[1].trim());
                }
            }
        }

        if (!profileFound) {
            throw new IOException("Profile '" + profile + "' not found in " + file);
        }

        user = properties.getProperty("user");
        tenancy = properties.getProperty("tenancy");
        region = properties.getProperty("region");
        keyfile = properties.getProperty("key_file");
        fingerprint = properties.getProperty("fingerprint");
        passphrase = properties.getProperty("pass_phrase");
    }

    /**
     * Loads the credentials from the environment variables.
     * 
     * @see <a href="https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clienvironmentvariables.htm">CLI Environment Variables</a>
     */
    public void loadFromEnvironment() {
        if (getenv("OCI_CLI_USER") != null) {
            user = getenv("OCI_CLI_USER");
        }
        if (getenv("OCI_CLI_TENANCY") != null) {
            tenancy = getenv("OCI_CLI_TENANCY");
        }
        if (getenv("OCI_CLI_REGION") != null) {
            region = getenv("OCI_CLI_REGION");
        }
        if (getenv("OCI_CLI_KEY_FILE") != null) {
            keyfile = getenv("OCI_CLI_KEY_FILE");
        }
        if (getenv("OCI_CLI_FINGERPRINT") != null) {
            fingerprint = getenv("OCI_CLI_FINGERPRINT");
        }
        if (getenv("OCI_CLI_PASS_PHRASE") != null) {
            passphrase = getenv("OCI_CLI_PASS_PHRASE");
        }
    }

    /**
     * Returns the default Oracle Cloud configuration.
     */
    public static OracleCloudCredentials getDefault() throws IOException {
        OracleCloudCredentials credentials = new OracleCloudCredentials();
        File config = getConfigFile();
        if (config.exists()) {
            credentials.load(config, getDefaultProfile());
        }
        credentials.loadFromEnvironment();
        return credentials;
    }

    /**
     * Returns the name of the default profile, either the value of the OCI_CLI_PROFILE environment variable or "DEFAULT".
     */
    public static String getDefaultProfile() {
        String profile = getenv("OCI_CLI_PROFILE");
        if (profile == null) {
            profile = "DEFAULT";
        }
        return profile;
    }

    /**
     * Returns the location of the configuration file, either the value of the OCI_CLI_CONFIG_FILE environment variable
     * or <code>~/.oci/config</code>.
     */
    public static File getConfigFile() {
        String config = getenv("OCI_CLI_CONFIG_FILE");
        if (config != null) {
            return new File(config);
        } else {
            return new File(System.getProperty("user.home"), ".oci/config");
        }
    }

    static String getenv(String name) {
        return System.getenv(name);
    }
}
