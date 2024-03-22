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

package net.jsign;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static net.jsign.KeyStoreType.*;

/**
 * Keystore builder.
 *
 * <p>Example:</p>
 *
 * <pre>
 *   KeyStore keystore = new KeyStoreBuilder().storetype(PKCS12).keystore("keystore.p12").storepass("password").build();
 * </pre>
 *
 * @since 5.0
 */
public class KeyStoreBuilder {

    /** The name used to refer to a configuration parameter */
    private String parameterName = "parameter";

    private String keystore;
    private String storepass;
    private KeyStoreType storetype;
    private String keypass;
    private File keyfile;
    private File certfile;

    /** The base directory to resolve the relative paths */
    private File basedir = new File("empty").getParentFile();

    private Provider provider;

    public KeyStoreBuilder() {
    }

    KeyStoreBuilder(String parameterName) {
        this.parameterName = parameterName;
    }

    String parameterName() {
        return parameterName;
    }

    /**
     * Sets the file containing the keystore.
     */
    public KeyStoreBuilder keystore(File keystore) {
        return keystore(keystore.getPath());
    }

    /**
     * Sets the name of the resource containing the keystore. Either the path of the keystore file,
     * the SunPKCS11 configuration file or the cloud keystore name depending on the type of keystore.
     */
    public KeyStoreBuilder keystore(String keystore) {
        this.keystore = keystore;
        return this;
    }

    String keystore() {
        return keystore;
    }

    /**
     * Sets the password to access the keystore. The password can be loaded from a file by using the <code>file:</code>
     * prefix followed by the path of the file, or from an environment variable by using the <code>env:</code> prefix
     * followed by the name of the variable.
     */
    public KeyStoreBuilder storepass(String storepass) {
        this.storepass = storepass;
        return this;
    }

    String storepass() {
        storepass = readPassword("storepass", storepass);
        return storepass;
    }

    /**
     * Sets the type of the keystore.
     */
    public KeyStoreBuilder storetype(KeyStoreType storetype) {
        this.storetype = storetype;
        return this;
    }

    /**
     * Sets the type of the keystore.
     *
     * @param storetype the type of the keystore
     * @throws IllegalArgumentException if the type is not recognized
     */
    public KeyStoreBuilder storetype(String storetype) {
        try {
            this.storetype = storetype != null ? KeyStoreType.valueOf(storetype.toUpperCase()) : null;
        } catch (IllegalArgumentException e) {
            String expectedTypes = Stream.of(KeyStoreType.values())
                    .filter(type -> type != NONE).map(KeyStoreType::name)
                    .collect(Collectors.joining(", "));
            throw new IllegalArgumentException("Unknown keystore type '" + storetype + "' (expected types: " + expectedTypes + ")");
        }
        return this;
    }

    KeyStoreType storetype() {
        if (storetype == null) {
            if (keystore == null) {
                // no keystore specified, keyfile and certfile are expected
                storetype = NONE;
            } else {
                // the keystore type wasn't specified, let's try to guess it
                storetype = KeyStoreType.of(createFile(keystore));
                if (storetype == null) {
                    throw new IllegalArgumentException("Keystore type of '" + keystore + "' not recognized");
                }
            }
        }
        return storetype;
    }

    /**
     * Sets the password to access the private key. The password can be loaded from a file by using the <code>file:</code>
     * prefix followed by the path of the file, or from an environment variable by using the <code>env:</code> prefix
     * followed by the name of the variable.
     */
    public KeyStoreBuilder keypass(String keypass) {
        this.keypass = keypass;
        return this;
    }

    String keypass() throws SignerException {
        keypass = readPassword("keypass", keypass);
        return keypass;
    }

    /**
     * Sets the file containing the private key.
     */
    public KeyStoreBuilder keyfile(String keyfile) {
        return keyfile(createFile(keyfile));
    }

    /**
     * Sets the file containing the private key.
     */
    public KeyStoreBuilder keyfile(File keyfile) {
        this.keyfile = keyfile;
        return this;
    }

    File keyfile() {
        return keyfile;
    }

    /**
     * Sets the file containing the certificate chain.
     */
    public KeyStoreBuilder certfile(String certfile) {
        return certfile(createFile(certfile));
    }

    /**
     * Sets the file containing the certificate chain.
     */
    public KeyStoreBuilder certfile(File certfile) {
        this.certfile = certfile;
        return this;
    }

    File certfile() {
        return certfile;
    }

    void setBaseDir(File basedir) {
        this.basedir = basedir;
    }

    File createFile(String file) {
        if (file == null) {
            return null;
        }

        if (new File(file).isAbsolute()) {
            return new File(file);
        } else {
            return new File(basedir, file);
        }
    }

    /**
     * Read the password from the specified value. If the value is prefixed with <code>file:</code>
     * the password is loaded from a file. If the value is prefixed with <code>env:</code> the password
     * is loaded from an environment variable. Otherwise the value is returned as is.
     *
     * @param name  the name of the parameter
     * @param value the value to parse
     */
    private String readPassword(String name, String value) {
        if (value != null) {
            if (value.startsWith("file:")) {
                String filename = value.substring("file:".length());
                Path path = createFile(filename).toPath();
                try {
                    value = String.join("\n", Files.readAllLines(path, StandardCharsets.UTF_8)).trim();
                } catch (IOException e) {
                    throw new IllegalArgumentException("Failed to read the " + name + " " + parameterName + " from the file '" + filename + "'", e);
                }
            } else if (value.startsWith("env:")) {
                String variable = value.substring("env:".length());
                if (!System.getenv().containsKey(variable)) {
                    throw new IllegalArgumentException("Failed to read the " + name + " " + parameterName + ", the '" + variable + "' environment variable is not defined");
                }
                value = System.getenv(variable);
            }
        }

        return value;
    }

    /**
     * Validates the parameters.
     */
    void validate() throws IllegalArgumentException {
        // keystore or keyfile, but not both
        if (keystore != null && keyfile != null) {
            throw new IllegalArgumentException("keystore " + parameterName + " can't be mixed with keyfile");
        }

        if (keystore == null && keyfile == null && certfile == null && storetype == null) {
            throw new IllegalArgumentException("Either keystore, or keyfile and certfile, or storetype " + parameterName + "s must be set");
        }

        storetype().validate(this);
    }

    /**
     * Returns the provider used to sign with the keystore.
     */
    public Provider provider() {
        if (provider == null) {
            provider = storetype().getProvider(this);
        }
        return provider;
    }

    /**
     * Builds the keystore.
     *
     * @throws IllegalArgumentException if the parameters are invalid
     * @throws KeyStoreException if the keystore can't be loaded
     */
    public KeyStore build() throws KeyStoreException {
        validate();
        return storetype().getKeystore(this, provider());
    }
}
