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
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import net.jsign.asn1.authenticode.AuthenticodeDigestCalculatorProvider;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.asn1.authenticode.SpcStatementType;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingMode;

/**
 * Sign a file with Authenticode. Timestamping is enabled by default and relies
 * on the Comodo server (http://timestamp.comodoca.com/authenticode).
 * 
 * @author Emmanuel Bourg
 * @since 3.0
 */
@SuppressWarnings("unchecked")
abstract class AuthenticodeSigner<S extends AuthenticodeSigner, F> {

    protected Certificate[] chain;
    protected PrivateKey privateKey;
    protected DigestAlgorithm digestAlgorithm = DigestAlgorithm.getDefault();
    protected String signatureAlgorithm;
    protected Provider signatureProvider;
    protected String programName;
    protected String programURL;
    protected boolean replace;
    protected boolean timestamping = true;
    protected TimestampingMode tsmode = TimestampingMode.AUTHENTICODE;
    protected String[] tsaurlOverride;
    protected Timestamper timestamper;
    protected int timestampingRetries = -1;
    protected int timestampingRetryWait = -1;

    /**
     * Create a signer with the specified certificate chain and private key.
     *
     * @param chain       the certificate chain. The first certificate is the signing certificate
     * @param privateKey  the private key
     * @throws IllegalArgumentException if the chain is empty
     */
    public AuthenticodeSigner(Certificate[] chain, PrivateKey privateKey) {
        this.chain = chain;
        this.privateKey = privateKey;
        
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("The certificate chain is empty");
        }
    }

    /**
     * Create a signer with a certificate chain and private key from the specified keystore.
     *
     * @param keystore the keystore holding the certificate and the private key
     * @param alias    the alias of the certificate in the keystore
     * @param password the password to get the private key
     */
    public AuthenticodeSigner(KeyStore keystore, String alias, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        Certificate[] chain = keystore.getCertificateChain(alias);
        if (chain == null) {
            throw new IllegalArgumentException("No certificate found in the keystore with the alias '" + alias + "'");
        }
        this.chain = chain;
        this.privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
    }

    /**
     * Set the program name embedded in the signature.
     */
    public S withProgramName(String programName) {
        this.programName = programName;
        return (S) this;
    }

    /**
     * Set the program URL embedded in the signature.
     */
    public S withProgramURL(String programURL) {
        this.programURL = programURL;
        return (S) this;
    }

    /**
     * Enable or disable the replacement of the previous signatures (disabled by default).
     * 
     * @since 2.0
     */
    public S withSignaturesReplaced(boolean replace) {
        this.replace = replace;
        return (S) this;
    }

    /**
     * Enable or disable the timestamping (enabled by default).
     */
    public S withTimestamping(boolean timestamping) {
        this.timestamping = timestamping;
        return (S) this;
    }

    /**
     * RFC3161 or Authenticode (Authenticode by default).
     * 
     * @since 1.3
     */
    public S withTimestampingMode(TimestampingMode tsmode) {
        this.tsmode = tsmode;
        return (S) this;
    }

    /**
     * Set the URL of the timestamping authority. RFC 3161 servers as used
     * for jar signing are not compatible with Authenticode signatures.
     * 
     * @since 2.1
     */
    public S withTimestampingAuthority(String url) {
        return withTimestampingAuthority(new String[] { url });
    }

    /**
     * Set the URL of the timestamping authority. RFC 3161 servers as used
     * for jar signing are not compatible with Authenticode signatures.
     * 
     * @since 2.1
     */
    public S withTimestampingAuthority(String... url) {
        this.tsaurlOverride = url;
        return (S) this;
    }

    /**
     * Set the Timestamper implementation.
     */
    public S withTimestamper(Timestamper timestamper) {
        this.timestamper = timestamper;
        return (S) this;
    }

    /**
     * Set the number of retries for timestamping.
     */
    public S withTimestampingRetries(int timestampingRetries) {
        this.timestampingRetries = timestampingRetries;
        return (S) this;
    }

    /**
     * Set the number of seconds to wait between timestamping retries.
     */
    
    public S withTimestampingRetryWait(int timestampingRetryWait) {
        this.timestampingRetryWait = timestampingRetryWait;
        return (S) this;
    }

    /**
     * Set the digest algorithm to use (SHA-256 by default)
     */
    public S withDigestAlgorithm(DigestAlgorithm algorithm) {
        if (algorithm != null) {
            this.digestAlgorithm = algorithm;
        }
        return (S) this;
    }

    /**
     * Explicitly sets the signature algorithm to use.
     * 
     * @since 2.0
     */
    public S withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return (S) this;
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     * 
     * @since 2.0
     */
    public S withSignatureAlgorithm(String signatureAlgorithm, String signatureProvider) {
        return withSignatureAlgorithm(signatureAlgorithm, Security.getProvider(signatureProvider));
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     * 
     * @since 2.0
     */
    public S withSignatureAlgorithm(String signatureAlgorithm, Provider signatureProvider) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureProvider = signatureProvider;
        return (S) this;
    }

    /**
     * Set the signature provider to use.
     * 
     * @since 2.0
     */
    public S withSignatureProvider(Provider signatureProvider) {
        this.signatureProvider = signatureProvider;
        return (S) this;
    }

    /**
     * Sign the specified file.
     *
     * @throws Exception
     */
    abstract void sign(File file) throws Exception;

    /**
     * Sign the specified file.
     *
     * @throws Exception
     */
    public abstract void sign(F file) throws Exception;

    /**
     * Create the PKCS7 message with the signature and the timestamp.
     */
    protected CMSSignedData createSignedData(F file) throws Exception {
        // compute the signature
        AuthenticodeSignedDataGenerator generator = createSignedDataGenerator();
        CMSSignedData sigData = generator.generate(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID, createIndirectData(file));
        
        // verify the signature
        DigestCalculatorProvider digestCalculatorProvider = new AuthenticodeDigestCalculatorProvider();
        SignerInformationVerifier verifier = new JcaSignerInfoVerifierBuilder(digestCalculatorProvider).build(chain[0].getPublicKey());
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
        
        return sigData;
    }

    /**
     * Creates the SpcIndirectDataContent structure containing the digest of the file.
     */
    protected abstract ASN1Object createIndirectData(F file) throws IOException;

    private AuthenticodeSignedDataGenerator createSignedDataGenerator() throws IOException, CMSException, OperatorCreationException, CertificateEncodingException {
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
        
        return generator;
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

    /**
     * Embed a signature as an unsigned attribute of an existing signature.
     */
    protected CMSSignedData addNestedSignature(CMSSignedData primary, CMSSignedData secondary) throws CMSException {
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
}
