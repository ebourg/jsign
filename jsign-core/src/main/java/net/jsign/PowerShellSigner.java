/*
 * Copyright 2019 Björn Kautler
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Base64Encoder;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcSipInfo;
import net.jsign.asn1.authenticode.SpcUuid;

import static java.lang.Math.*;
import static java.nio.charset.StandardCharsets.*;

/**
 * Sign a PowerShell file. Timestamping is enabled by default
 * and relies on the Comodo server (http://timestamp.comodoca.com/authenticode).
 * Script encoding is assumed to be UTF-8 by default.
 *
 * @author Björn Kautler
 * @since 3.0
 */
public class PowerShellSigner extends AuthenticodeSigner<PowerShellSigner, File> {

    private static final Pattern SIGNATURE_BLOCK_PATTERN = Pattern.compile("(?s)" +
            "\\r\\n" +
            "# SIG # Begin signature block\\r\\n" +
            ".*" +
            "# SIG # End signature block\\r\\n");

    private Charset scriptEncoding = UTF_8;

    /**
     * Create a PowerShellSigner with the specified certificate chain and private key.
     *
     * @param chain       the certificate chain. The first certificate is the signing certificate
     * @param privateKey  the private key
     * @throws IllegalArgumentException if the chain is empty
     */
    public PowerShellSigner(Certificate[] chain, PrivateKey privateKey) {
        super(chain, privateKey);
    }

    /**
     * Create a PowerShellSigner with a certificate chain and private key from the specified keystore.
     *
     * @param keystore the keystore holding the certificate and the private key
     * @param alias    the alias of the certificate in the keystore
     * @param password the password to get the private key
     */
    public PowerShellSigner(KeyStore keystore, String alias, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        super(keystore, alias, password);
    }

    /**
     * Set the encoding of the script to be signed (UTF-8 by default).
     */
    public PowerShellSigner withScriptEncoding(Charset scriptEncoding) {
        this.scriptEncoding = scriptEncoding;
        return this;
    }

    /**
     * Sign the specified PowerShell script.
     *
     * @throws Exception
     */
    @Override
    public void sign(File file) throws Exception {
        // strip signature block
        String scriptContent = new String(Files.readAllBytes(file.toPath()), scriptEncoding);
        scriptContent = SIGNATURE_BLOCK_PATTERN.matcher(scriptContent).replaceFirst("");

        // compute the signature
        CMSSignedData sigData = createSignedData(file);

        // base64 encode the signature blob
        byte[] signatureBytes = sigData.toASN1Structure().getEncoded("DER");
        ByteArrayOutputStream base64Stream = new ByteArrayOutputStream();
        new Base64Encoder().encode(signatureBytes, 0, signatureBytes.length, base64Stream);
        String signatureBlob = new String(base64Stream.toByteArray(), US_ASCII);

        // build the signed script content
        StringBuilder signedScriptContent = new StringBuilder(scriptContent.length() + signatureBlob.length() + 100);
        signedScriptContent.append(scriptContent);
        signedScriptContent.append("\r\n");
        signedScriptContent.append("# SIG # Begin signature block\r\n");
        for (int start = 0, blobLength = signatureBlob.length(); start < blobLength; start += 64) {
            signedScriptContent.append("# ");
            signedScriptContent.append(signatureBlob, start, min(blobLength, start + 64));
            signedScriptContent.append("\r\n");
        }
        signedScriptContent.append("# SIG # End signature block\r\n");

        Files.write(file.toPath(), signedScriptContent.toString().getBytes(scriptEncoding));
    }

    @Override
    protected ASN1Object createIndirectData(File file) throws IOException {
        // strip signature block
        String scriptContent = new String(Files.readAllBytes(file.toPath()), scriptEncoding);
        scriptContent = SIGNATURE_BLOCK_PATTERN.matcher(scriptContent).replaceFirst("");
        
        MessageDigest messageDigest = digestAlgorithm.getMessageDigest();
        messageDigest.update(scriptContent.getBytes(UTF_16LE));
        byte[] sha = messageDigest.digest();
        
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, sha);

        SpcUuid uuid = new SpcUuid("1FCC3B60-594B-084E-B724-D2C6297EF351");
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, new SpcSipInfo(65536, uuid));

        return new SpcIndirectDataContent(data, digestInfo);
    }
}
