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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import net.jsign.asn1.authenticode.AuthenticodeDigestCalculatorProvider;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcPeImageData;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.asn1.authenticode.SpcStatementType;
import net.jsign.pe.CertificateTableEntry;
import net.jsign.pe.DataDirectory;
import net.jsign.pe.DataDirectoryType;
import net.jsign.pe.PEFile;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingMode;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Store;

/**
 * Sign a portable executable file. Timestamping is enabled by default
 * and relies on the Comodo server (http://timestamp.comodoca.com/authenticode).
 * 
 * @see <a href="http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx">Windows Authenticode Portable Executable Signature Format</a>
 * @see <a href="http://msdn.microsoft.com/en-us/library/windows/desktop/bb931395%28v=vs.85%29.aspx?ppud=4">Time Stamping Authenticode Signatures</a>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PESigner {

    private Certificate[] chain;
    private PrivateKey privateKey;
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.getDefault();
    private String signatureAlgorithm;
    private Provider signatureProvider;
    private String programName;
    private String programURL;
    private boolean replace;
    private String googleCloudHsmKeyId;

    private boolean timestamping = true;
    private TimestampingMode tsmode = TimestampingMode.AUTHENTICODE;
    private String[] tsaurlOverride;
    private Timestamper timestamper;
    private int timestampingRetries = -1;
    private int timestampingRetryWait = -1;

    /**
     * Create a PESigner with the specified certificate chain and private key.
     *
     * @param chain       the certificate chain. The first certificate is the signing certificate
     * @param privateKey  the private key
     * @throws IllegalArgumentException if the chain is empty
     */
    public PESigner(Certificate[] chain, PrivateKey privateKey) {
        this.chain = chain;
        this.privateKey = privateKey;
        
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("The certificate chain is empty");
        }
    }

    /**
     * Create a PESigner with a certificate chain and private key from the specified keystore.
     *
     * @param keystore the keystore holding the certificate and the private key
     * @param alias    the alias of the certificate in the keystore
     * @param password the password to get the private key
     */
    public PESigner(KeyStore keystore, String alias, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        Certificate[] chain = keystore.getCertificateChain(alias);
        if (chain == null) {
            throw new IllegalArgumentException("No certificate found in the keystore with the alias '" + alias + "'");
        }
        this.chain = chain;
        this.privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
    }

    /**
     * Set the Google Cloud HSM Key Id to sign with.
     */
    public PESigner withGoogleHsmKeyId(String googleCloudHsmKeyId) {
        this.googleCloudHsmKeyId = googleCloudHsmKeyId;
        return this;
    }

    /**
     * Set the program name embedded in the signature.
     */
    public PESigner withProgramName(String programName) {
        this.programName = programName;
        return this;
    }

    /**
     * Set the program URL embedded in the signature.
     */
    public PESigner withProgramURL(String programURL) {
        this.programURL = programURL;
        return this;
    }

    /**
     * Enable or disable the replacement of the previous signatures (disabled by default).
     * 
     * @since 2.0
     */
    public PESigner withSignaturesReplaced(boolean replace) {
        this.replace = replace;
        return this;
    }

    /**
     * Enable or disable the timestamping (enabled by default).
     */
    public PESigner withTimestamping(boolean timestamping) {
        this.timestamping = timestamping;
        return this;
    }

    /**
     * RFC3161 or Authenticode (Authenticode by default).
     * 
     * @since 1.3
     */
    public PESigner withTimestampingMode(TimestampingMode tsmode) {
        this.tsmode = tsmode;
        return this;
    }

    /**
     * Set the URL of the timestamping authority. RFC 3161 servers as used
     * for jar signing are not compatible with Authenticode signatures.
     * 
     * @since 2.1
     */
    public PESigner withTimestampingAuthority(String url) {
        return withTimestampingAuthority(new String[] { url });
    }

    /**
     * Set the URL of the timestamping authority. RFC 3161 servers as used
     * for jar signing are not compatible with Authenticode signatures.
     * 
     * @deprecated
     */
    public PESigner withTimestampingAutority(String url) {
        return withTimestampingAuthority(url);
    }

    /**
     * Set the URL of the timestamping authority. RFC 3161 servers as used
     * for jar signing are not compatible with Authenticode signatures.
     * 
     * @since 2.1
     */
    public PESigner withTimestampingAuthority(String... url) {
        this.tsaurlOverride = url;
        return this;
    }

    /**
     * Set the URL of the timestamping authority. RFC 3161 servers as used
     * for jar signing are not compatible with Authenticode signatures.
     *
     * @since 2.0
     * @deprecated
     */
    public PESigner withTimestampingAutority(String... url) {
        return withTimestampingAuthority(url);
    }

    /**
     * Set the Timestamper implementation.
     */
    public PESigner withTimestamper(Timestamper timestamper) {
        this.timestamper = timestamper;
        return this;
    }

    /**
     * Set the number of retries for timestamping.
     */
    public PESigner withTimestampingRetries(int timestampingRetries) {
        this.timestampingRetries = timestampingRetries;
        return this;
    }

    /**
     * Set the number of seconds to wait between timestamping retries.
     */
    public PESigner withTimestampingRetryWait(int timestampingRetryWait) {
        this.timestampingRetryWait = timestampingRetryWait;
        return this;
    }

    /**
     * Set the digest algorithm to use (SHA-256 by default)
     */
    public PESigner withDigestAlgorithm(DigestAlgorithm algorithm) {
        if (algorithm != null) {
            this.digestAlgorithm = algorithm;
        }
        return this;
    }

    /**
     * Explicitly sets the signature algorithm to use.
     * 
     * @since 2.0
     */
    public PESigner withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     * 
     * @since 2.0
     */
    public PESigner withSignatureAlgorithm(String signatureAlgorithm, String signatureProvider) {
        return withSignatureAlgorithm(signatureAlgorithm, Security.getProvider(signatureProvider));
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     * 
     * @since 2.0
     */
    public PESigner withSignatureAlgorithm(String signatureAlgorithm, Provider signatureProvider) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureProvider = signatureProvider;
        return this;
    }

    /**
     * Set the signature provider to use.
     * 
     * @since 2.0
     */
    public PESigner withSignatureProvider(Provider signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    /**
     * Sign the specified executable file.
     *
     * @throws Exception
     */
    public void sign(PEFile file) throws Exception {
        // pad the file on a 8 byte boundary
        // todo only if there was no previous certificate table
        file.pad(8);
        
        if (replace) {
            DataDirectory certificateTable = file.getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
            if (certificateTable != null && !certificateTable.isTrailing()) {
                // erase the previous signature
                certificateTable.erase();
                certificateTable.write(0, 0);
            }
        }
        
        // compute the signature
        CMSSignedData sigData;
        if (googleCloudHsmKeyId != null) {
            sigData = createSignatureGoogleHsm(file, googleCloudHsmKeyId);
        } else {
            sigData = createSignature(file);
        }

        // verify the signature
        Certificate certToCheck = chain[0];
        if (googleCloudHsmKeyId != null) {
            certToCheck = chain[chain.length - 1];
        }
        DigestCalculatorProvider digestCalculatorProvider = new AuthenticodeDigestCalculatorProvider();
        SignerInformationVerifier verifier = new JcaSignerInfoVerifierBuilder(digestCalculatorProvider).build(certToCheck.getPublicKey());
        sigData.getSignerInfos().iterator().next().verify(verifier);
        
        // timestamping
        if (timestamping) {
            Timestamper ts = timestamper;
            if (ts == null) {
                ts = Timestamper.create(tsmode);
            }
            if (tsaurlOverride != null) {
                ts.setURLs(tsaurlOverride);
            }
            if (timestampingRetries != -1) {
                ts.setRetries(timestampingRetries);
            }
            if (timestampingRetryWait != -1) {
                ts.setRetryWait(timestampingRetryWait);
            }
            sigData = ts.timestamp(digestAlgorithm, sigData);
        }
        
        List<CMSSignedData> signatures = file.getSignatures();
        if (!signatures.isEmpty() && !replace) {
            // append the nested signature
            sigData = addNestedSignature(signatures.get(0), sigData);
        }

        CertificateTableEntry entry = new CertificateTableEntry(sigData);
        
        file.writeDataDirectory(DataDirectoryType.CERTIFICATE_TABLE, entry.toBytes());
        file.close();
    }

    private CMSSignedData addNestedSignature(CMSSignedData primary, CMSSignedData secondary) throws CMSException {
        SignerInformation signerInformation = primary.getSignerInfos().getSigners().iterator().next();
        
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            unsignedAttributes = new AttributeTable(new DERSet());
        }
        Attribute nestedSignaturesAttribute = unsignedAttributes.get(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID);
        if (nestedSignaturesAttribute == null) {
            // first nested signature
            unsignedAttributes = unsignedAttributes.add(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID, secondary.toASN1Structure());
        } else {
            // append the signature to the previous nested signatures
            ASN1EncodableVector nestedSignatures = new ASN1EncodableVector();
            for (ASN1Encodable nestedSignature : nestedSignaturesAttribute.getAttrValues()) {
                nestedSignatures.add(nestedSignature);
            }
            nestedSignatures.add(secondary.toASN1Structure());
            
            ASN1EncodableVector attributes = unsignedAttributes.remove(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID).toASN1EncodableVector();
            attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID, new DERSet(nestedSignatures)));
            
            unsignedAttributes = new AttributeTable(attributes);
        }
        
        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        return CMSSignedData.replaceSigners(primary, new SignerInformationStore(signerInformation));
    }

    private CMSSignedData createSignatureGoogleHsm(PEFile file, final String googleCloudHsmKeyId) throws IOException, CMSException, OperatorCreationException, CertificateEncodingException {
        byte[] sha = file.computeDigest(digestAlgorithm);

        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, sha);
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID, new SpcPeImageData());
        SpcIndirectDataContent spcIndirectDataContent = new SpcIndirectDataContent(data, digestInfo);

        DigestCalculatorProvider digestCalculatorProvider = new AuthenticodeDigestCalculatorProvider();

        // prepare the authenticated attributes
        CMSAttributeTableGenerator attributeTableGenerator = new DefaultSignedAttributeTableGenerator(createAuthenticatedAttributes());

        // fetch the signing certificate
        X509CertificateHolder certificate = new JcaX509CertificateHolder((X509Certificate) chain[chain.length - 1]);

        // prepare the signerInfo with the extra authenticated attributes
        SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);
        signerInfoGeneratorBuilder.setSignedAttributeGenerator(attributeTableGenerator);

        Store certs = new JcaCertStore(removeRoot(chain));

        //SignedHash is a base64-encoded PKCS1 block.
        ContentSigner contentSigner = ContentSignerFactory.getContentSigner(new HsmContentSigner() {
            @Override
            public byte[] apply(ByteArrayOutputStream stream) {
                try {
                    return Kms.signAsymmetric(googleCloudHsmKeyId, stream.toByteArray());
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                return new byte[0];
            }
        }, "SHA256WITHECDSA");
        // Google Cloud only accepts SHA256WITHECDSA

        AuthenticodeSignedDataGenerator gen = new AuthenticodeSignedDataGenerator();

        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(contentSigner, certificate));
        gen.addCertificates(certs);
        return gen.generate(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, spcIndirectDataContent);
    }

    private CMSSignedData createSignature(PEFile file) throws IOException, CMSException, OperatorCreationException, CertificateEncodingException {
        byte[] sha = file.computeDigest(digestAlgorithm);

        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, sha);
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID, new SpcPeImageData());
        SpcIndirectDataContent spcIndirectDataContent = new SpcIndirectDataContent(data, digestInfo);

        // create content signer
        final String sigAlg;
        if (signatureAlgorithm == null) {
            sigAlg = digestAlgorithm + "with" + privateKey.getAlgorithm();
        } else {
            sigAlg = signatureAlgorithm;
        }
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(sigAlg);
        if (signatureProvider != null) {
            contentSignerBuilder.setProvider(signatureProvider);
        }
        ContentSigner shaSigner = contentSignerBuilder.build(privateKey);

        DigestCalculatorProvider digestCalculatorProvider = new AuthenticodeDigestCalculatorProvider();

        // prepare the authenticated attributes
        CMSAttributeTableGenerator attributeTableGenerator = new DefaultSignedAttributeTableGenerator(createAuthenticatedAttributes());

        // fetch the signing certificate
        X509CertificateHolder certificate = new JcaX509CertificateHolder((X509Certificate) chain[0]);

        // prepare the signerInfo with the extra authenticated attributes
        SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);
        signerInfoGeneratorBuilder.setSignedAttributeGenerator(attributeTableGenerator);
        SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(shaSigner, certificate);

        AuthenticodeSignedDataGenerator generator = new AuthenticodeSignedDataGenerator();
        generator.addCertificates(new JcaCertStore(removeRoot(chain)));
        generator.addSignerInfoGenerator(signerInfoGenerator);

        return generator.generate(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, spcIndirectDataContent);
    }

    /**
     * Remove the root certificate from the chain, unless the chain consists in a single self signed certificate.
     */
    private List<Certificate> removeRoot(Certificate[] certificates) {
        List<Certificate> list = new ArrayList<>();
        
        if (certificates.length == 1) {
            list.add(certificates[0]);
        } else {
            for (Certificate certificate : certificates) {
                if (!isSelfSigned((X509Certificate) certificate)) {
                    list.add(certificate);
                }
            }
        }
        
        return list;
    }

    private boolean isSelfSigned(X509Certificate certificate) {
        return certificate.getSubjectDN().equals(certificate.getIssuerDN());
    }

    /**
     * Creates the authenticated attributes for the SignerInfo section of the signature.
     */
    private AttributeTable createAuthenticatedAttributes() {
        List<Attribute> attributes = new ArrayList<>();
        
        SpcStatementType spcStatementType = new SpcStatementType(AuthenticodeObjectIdentifiers.SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID);
        attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_STATEMENT_TYPE_OBJID, new DERSet(spcStatementType)));
        
        SpcSpOpusInfo spcSpOpusInfo = new SpcSpOpusInfo(programName, programURL);
        attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_SP_OPUS_INFO_OBJID, new DERSet(spcSpOpusInfo)));

        return new AttributeTable(new DERSet(attributes.toArray(new ASN1Encodable[attributes.size()])));
    }
}
