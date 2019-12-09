/**
 * Copyright 2019 Emmanuel Bourg
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcSipInfo;
import net.jsign.asn1.authenticode.SpcUuid;
import net.jsign.msi.MSIFile;

/**
 * Sign a Microsoft Installer file (.msi). Timestamping is enabled by default.
 * 
 * @author Emmanuel Bourg
 * @since 3.0
 */
public class MSISigner extends AuthenticodeSigner<MSISigner, MSIFile> {

    /**
     * Create a MSISigner with the specified certificate chain and private key.
     *
     * @param chain       the certificate chain. The first certificate is the signing certificate
     * @param privateKey  the private key
     * @throws IllegalArgumentException if the chain is empty
     */
    public MSISigner(Certificate[] chain, PrivateKey privateKey) {
        super(chain, privateKey);
    }

    /**
     * Create a MSISigner with a certificate chain and private key from the specified keystore.
     *
     * @param keystore the keystore holding the certificate and the private key
     * @param alias    the alias of the certificate in the keystore
     * @param password the password to get the private key
     * @throws KeyStoreException if the keystore has not been initialized (loaded).
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the key cannot be recovered (e.g., the given password is wrong).
     */
    public MSISigner(KeyStore keystore, String alias, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        super(keystore, alias, password);
    }

    @Override
    void sign(File file) throws Exception {
        try (MSIFile msi = new MSIFile(file)) {
            sign(msi);
        }
    }

    @Override
    public void sign(MSIFile file) throws Exception {
        if (!replace && file.hasExtendedSignature()) {
            throw new UnsupportedOperationException("The file has an extended signature which isn't supported by Jsign, it can't be signed without replacing the existing signature");
        }
        
        CMSSignedData sigData = createSignedData(file);
        
        if (!replace) {
            List<CMSSignedData> signatures = file.getSignatures();
            if (!signatures.isEmpty()) {
                // append the nested signature
                sigData = addNestedSignature(signatures.get(0), sigData);
            }
        }
        
        file.setSignature(sigData);
        
        file.save();
        file.close();
    }

    @Override
    protected ASN1Object createIndirectData(MSIFile file) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, file.computeDigest(digestAlgorithm.getMessageDigest()));

        SpcUuid uuid = new SpcUuid("F1100C00-0000-0000-C000-000000000046");
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, new SpcSipInfo(1, uuid));

        return new SpcIndirectDataContent(data, digestInfo);
    }
}
