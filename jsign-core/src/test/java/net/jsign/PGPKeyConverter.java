/*
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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import static org.bouncycastle.bcpg.HashAlgorithmTags.*;

/**
 * Tool to generate a PGP key from the same key material used for the tests.
 *
 * <pre>
 * $ gpg --import privatekey.asc
 * $ gpg --edit-key jsign@example.com
 *
 * gpg> keytocard
 * Really move the primary key? (y/N) y
 * Please select where to store the key:
 *    (1) Signature key
 *    (2) Encryption key
 *    (3) Authentication key
 * Your selection? 1
 *
 * Replace existing key? (y/N) y
 * </pre>
 */
public class PGPKeyConverter {

    public static void main(String[] args) throws Exception {
        File rsaPrivateKeyFile = new File("jsign-core/src/test/resources/keystores/privatekey.pkcs1.pem");
        PGPKeyPair rsaKeyPair = getKeyPair(rsaPrivateKeyFile);
        writeKeyring(rsaKeyPair, "Jsign Test Key (RSA) <jsign-rsa@example.com>", new File(rsaPrivateKeyFile.getParentFile(), "privatekey.asc"));

        File ecPrivateKeyFile = new File("jsign-core/src/test/resources/keystores/privatekey-ec-p384.pkcs1.pem");
        PGPKeyPair ecKeyPair = getKeyPair(ecPrivateKeyFile);
        writeKeyring(ecKeyPair, "Jsign Test Key (EC) <jsign-ec@example.com>", new File(ecPrivateKeyFile.getParentFile(), "privatekey-ec-p384.asc"));
    }

    private static PGPKeyPair getKeyPair(File privateKeyFile) throws PGPException, GeneralSecurityException {
        PrivateKey key = PrivateKeyUtils.load(privateKeyFile, null);

        Date creationDate = new Date(1668510000000L);

        if (key instanceof BCRSAPrivateCrtKey) {
            BCRSAPrivateCrtKey privateKey = (BCRSAPrivateCrtKey) key;
            KeySpec keySpec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, creationDate);

        } else {
            BCECPrivateKey privateKey = (BCECPrivateKey) key;
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(privateKey.getParameters().getG().multiply(privateKey.getD()), privateKey.getParameters());
            BCECPublicKey publicKey = new BCECPublicKey(privateKey.getAlgorithm(), pubSpec, BouncyCastleProvider.CONFIGURATION);
            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            return new JcaPGPKeyPair(PGPPublicKey.ECDSA, keyPair, creationDate);
        }
    }

    private static void writeKeyring(PGPKeyPair pgpKeyPair, String id, File targetFile) throws IOException, PGPException {
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.AUTHENTICATION | KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE | KeyFlags.CERTIFY_OTHER);

        PGPDigestCalculator sha1DigestCalculator = new BcPGPDigestCalculatorProvider().get(SHA1);
        PGPDigestCalculator sha2DigestCalculator = new BcPGPDigestCalculatorProvider().get(SHA256);
        PBESecretKeyEncryptor secretKeyEncryptor = new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha2DigestCalculator).build("password".toCharArray());
        PGPContentSignerBuilder contentSignerBuilder = new BcPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), SHA512);
        PGPKeyRingGenerator keyringGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, pgpKeyPair,
                id, sha1DigestCalculator, subpacketGenerator.generate(), null, contentSignerBuilder, secretKeyEncryptor);

        PGPSecretKeyRing keyring = keyringGenerator.generateSecretKeyRing();
        keyring.getSecretKeys().forEachRemaining(key -> {
            System.out.println("Key ID      : " + Long.toHexString(key.getKeyID()).toUpperCase());
            System.out.println("Size        : " + key.getPublicKey().getBitStrength());
            System.out.println("Master Key  : " + key.isMasterKey());
            System.out.println("Signing Key : " + key.isSigningKey());
            System.out.print("User IDs    : ");
            key.getUserIDs().forEachRemaining(System.out::print);
            System.out.println();
            System.out.println();
        });

        try (ArmoredOutputStream out = new ArmoredOutputStream(new BufferedOutputStream(Files.newOutputStream(targetFile.toPath())))) {
            keyring.encode(out);
        }
    }
}
