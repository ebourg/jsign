/*
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
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.KeyException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import sun.misc.Unsafe;

/**
 * Helper class for loading private keys (PVK or PEM, encrypted or not).
 * 
 * @author Emmanuel Bourg
 * @since 2.0
 */
public class PrivateKeyUtils {

    private PrivateKeyUtils() {
    }

    /**
     * Load the private key from the specified file. Supported formats are PVK and PEM,
     * encrypted or not. The type of the file is inferred by trying the supported formats
     * in sequence until one parses successfully.
     *
     * @param file     the file to load the key from
     * @param password the password protecting the key
     * @return the private key loaded
     * @throws KeyException if the key cannot be loaded
     */
    public static PrivateKey load(File file, String password) throws KeyException {
        Exception pemParseException;
        try {
            return readPrivateKeyPEM(file, password != null ? password.toCharArray() : null);
        } catch (Exception e) {
            pemParseException = e;
        }

        Exception pvkParseException;
        try {
            return PVK.parse(file, password);
        } catch (Exception e) {
            pvkParseException = e;
        }

        KeyException keyException = new KeyException("Failed to load the private key from " + file + " (valid PEM or PVK file expected)");
        keyException.addSuppressed(pemParseException);
        keyException.addSuppressed(pvkParseException);
        throw keyException;
    }

    /**
     * Disables the signature verification of the jar containing the BouncyCastle provider.
     */
    private static void disableJceSecurity() {
        try {
            Class<?> jceSecurityClass = Class.forName("javax.crypto.JceSecurity");
            Field field = jceSecurityClass.getDeclaredField("verificationResults");
            field.setAccessible(true);

            Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Unsafe unsafe = (Unsafe) unsafeField.get(null);

            unsafe.putObject(unsafe.staticFieldBase(field), unsafe.staticFieldOffset(field), new HashMap<Object, Boolean>() {
                @Override
                public Boolean get(Object key) {
                    // This is not the provider you are looking for, you don't need to see its identification, move along
                    return Boolean.TRUE;
                }

                @Override
                public Boolean computeIfAbsent(Object key, Function<? super Object, ? extends Boolean> mappingFunction) {
                    return super.computeIfAbsent(key, object -> Boolean.TRUE);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PrivateKey readPrivateKeyPEM(File file, char[] password) throws IOException, OperatorCreationException, PKCSException {
        try (FileReader reader = new FileReader(file)) {
            PEMParser parser = new PEMParser(reader);
            Object object = parser.readObject();
            if (object instanceof ASN1ObjectIdentifier) {
                // ignore the EC key parameters
                object = parser.readObject();
            }
            
            if (object == null) {
                throw new IllegalArgumentException("No key found in " + file);
            }

            if (BouncyCastleProvider.class.getName().startsWith("net.jsign")) {
                // disable JceSecurity to allow the use of the repackaged BouncyCastle provider
                disableJceSecurity();
            }
            BouncyCastleProvider provider = new BouncyCastleProvider();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(provider);

            if (object instanceof PEMEncryptedKeyPair) {
                // PKCS1 encrypted key
                PEMDecryptorProvider decryptionProvider = new JcePEMDecryptorProviderBuilder().setProvider(provider).build(password);
                PEMKeyPair keypair = ((PEMEncryptedKeyPair) object).decryptKeyPair(decryptionProvider);
                return converter.getPrivateKey(keypair.getPrivateKeyInfo());

            } else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                // PKCS8 encrypted key
                InputDecryptorProvider decryptionProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(provider).build(password);
                PrivateKeyInfo info = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(decryptionProvider);
                return converter.getPrivateKey(info);
                
            } else if (object instanceof PEMKeyPair) {
                // PKCS1 unencrypted key
                return converter.getKeyPair((PEMKeyPair) object).getPrivate();
                
            } else if (object instanceof PrivateKeyInfo) {
                // PKCS8 unencrypted key
                return converter.getPrivateKey((PrivateKeyInfo) object);
                
            } else {
                throw new UnsupportedOperationException("Unsupported PEM object: " + object.getClass().getSimpleName());
            }
        }
    }
}
