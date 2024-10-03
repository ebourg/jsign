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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultCMSSignatureEncryptionAlgorithmFinder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import net.jsign.asn1.authenticode.FilteredAttributeTableGenerator;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.asn1.authenticode.SpcStatementType;
import net.jsign.jca.SigningServiceJcaProvider;
import net.jsign.nuget.NugetFile;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingMode;

/**
 * Sign a file with Authenticode. Timestamping is enabled by default and relies
 * on the Sectigo server (http://timestamp.sectigo.com).
 *
 * <p>Example:</p>
 * <pre>
 * KeyStore keystore = new KeyStoreBuilder().keystore("keystore.p12").storepass("password").build();
 *
 * AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "alias", "secret");
 * signer.withProgramName("My Application")
 *       .withProgramURL("http://www.example.com")
 *       .withTimestamping(true)
 *       .withTimestampingAuthority("http://timestamp.sectigo.com");
 *
 * try (Signable file = Signable.of(new File("application.exe"))) {
 *     signer.sign(file);
 * }
 * </pre>
 *
 * @author Emmanuel Bourg
 * @since 3.0
 */
public class AuthenticodeSigner {

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
     * @throws KeyStoreException if the keystore has not been initialized (loaded).
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the key cannot be recovered (e.g., the given password is wrong).
     */
    public AuthenticodeSigner(KeyStore keystore, String alias, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        Certificate[] chain = keystore.getCertificateChain(alias);
        if (chain == null) {
            throw new IllegalArgumentException("No certificate found in the keystore with the alias '" + alias + "'");
        }
        this.chain = chain;
        this.privateKey = (PrivateKey) keystore.getKey(alias, password != null ? password.toCharArray() : null);

        Provider provider = keystore.getProvider();
        if (provider.getName().startsWith("SunPKCS11") || provider instanceof SigningServiceJcaProvider) {
            this.signatureProvider = provider;
        }
    }

    /**
     * Set the program name embedded in the signature.
     * 
     * @param programName the program name
     * @return the current signer
     */
    public AuthenticodeSigner withProgramName(String programName) {
        this.programName = programName;
        return this;
    }

    /**
     * Set the program URL embedded in the signature.
     * 
     * @param programURL the program URL
     * @return the current signer
     */
    public AuthenticodeSigner withProgramURL(String programURL) {
        this.programURL = programURL;
        return this;
    }

    /**
     * Enable or disable the replacement of the previous signatures (disabled by default).
     * 
     * @param replace <code>true</code> if the new signature should replace the existing ones, <code>false</code> to append it
     * @return the current signer
     * @since 2.0
     */
    public AuthenticodeSigner withSignaturesReplaced(boolean replace) {
        this.replace = replace;
        return this;
    }

    /**
     * Enable or disable the timestamping (enabled by default).
     * 
     * @param timestamping <code>true</code> to enable timestamping, <code>false</code> to disable it
     * @return the current signer
     */
    public AuthenticodeSigner withTimestamping(boolean timestamping) {
        this.timestamping = timestamping;
        return this;
    }

    /**
     * RFC3161 or Authenticode (Authenticode by default).
     * 
     * @param tsmode the timestamping mode
     * @return the current signer
     * @since 1.3
     */
    public AuthenticodeSigner withTimestampingMode(TimestampingMode tsmode) {
        this.tsmode = tsmode;
        return this;
    }

    /**
     * Set the URL of the timestamping authority. Both RFC 3161 (as used for jar signing)
     * and Authenticode timestamping services are supported.
     * 
     * @param url the URL of the timestamping authority
     * @return the current signer
     * @since 2.1
     */
    public AuthenticodeSigner withTimestampingAuthority(String url) {
        return withTimestampingAuthority(new String[] { url });
    }

    /**
     * Set the URLs of the timestamping authorities. Both RFC 3161 (as used for jar signing)
     * and Authenticode timestamping services are supported.
     * 
     * @param urls the URLs of the timestamping authorities
     * @return the current signer
     * @since 2.1
     */
    public AuthenticodeSigner withTimestampingAuthority(String... urls) {
        this.tsaurlOverride = urls;
        return this;
    }

    /**
     * Set the Timestamper implementation.
     * 
     * @param timestamper the timestamper implementation to use
     * @return the current signer
     */
    public AuthenticodeSigner withTimestamper(Timestamper timestamper) {
        this.timestamper = timestamper;
        return this;
    }

    /**
     * Set the number of retries for timestamping.
     * 
     * @param timestampingRetries the number of retries
     * @return the current signer
     */
    public AuthenticodeSigner withTimestampingRetries(int timestampingRetries) {
        this.timestampingRetries = timestampingRetries;
        return this;
    }

    /**
     * Set the number of seconds to wait between timestamping retries.
     * 
     * @param timestampingRetryWait the wait time between retries (in seconds)
     * @return the current signer
     */
    public AuthenticodeSigner withTimestampingRetryWait(int timestampingRetryWait) {
        this.timestampingRetryWait = timestampingRetryWait;
        return this;
    }

    /**
     * Set the digest algorithm to use (SHA-256 by default)
     * 
     * @param algorithm the digest algorithm
     * @return the current signer
     */
    public AuthenticodeSigner withDigestAlgorithm(DigestAlgorithm algorithm) {
        if (algorithm != null) {
            this.digestAlgorithm = algorithm;
        }
        return this;
    }

    /**
     * Explicitly sets the signature algorithm to use.
     * 
     * @param signatureAlgorithm the signature algorithm
     * @return the current signer
     * @since 2.0
     */
    public AuthenticodeSigner withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * Returns the signature algorithm to use.
     */
    private String getSignatureAlgorithm() {
        if (signatureAlgorithm != null) {
            return signatureAlgorithm;
        } else if ("EC".equals(privateKey.getAlgorithm())) {
            return digestAlgorithm + "withECDSA";
        } else if ("EdDSA".equals(privateKey.getAlgorithm())) {
            X509Certificate certificate = (X509Certificate) chain[0];
            PublicKey publicKey = certificate.getPublicKey();
            if (publicKey.toString().contains("Ed25519")) {
                return "Ed25519";
            } else if (publicKey.toString().contains("Ed448")) {
                return "Ed448";
            }
            // return ((EdECKey) publicKey).getParams().getName(); // todo with Java 15+
        }

        return digestAlgorithm + "with" + privateKey.getAlgorithm();
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     * 
     * @param signatureAlgorithm the signature algorithm
     * @param signatureProvider the security provider for the specified algorithm
     * @return the current signer
     * @since 2.0
     */
    public AuthenticodeSigner withSignatureAlgorithm(String signatureAlgorithm, String signatureProvider) {
        return withSignatureAlgorithm(signatureAlgorithm, Security.getProvider(signatureProvider));
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     * 
     * @param signatureAlgorithm the signature algorithm
     * @param signatureProvider the security provider for the specified algorithm
     * @return the current signer
     * @since 2.0
     */
    public AuthenticodeSigner withSignatureAlgorithm(String signatureAlgorithm, Provider signatureProvider) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureProvider = signatureProvider;
        return this;
    }

    /**
     * Set the signature provider to use.
     * 
     * @param signatureProvider the security provider for the signature algorithm
     * @return the current signer
     * @since 2.0
     */
    public AuthenticodeSigner withSignatureProvider(Provider signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    /**
     * Sign the specified file.
     *
     * @param file the file to sign
     * @throws Exception if signing fails
     */
    public void sign(Signable file) throws Exception {
        file.validate(chain[0]);

        if (file instanceof NugetFile && !replace) {
            List<CMSSignedData> signatures = file.getSignatures();
            if (!signatures.isEmpty()) {
                throw new SignerException("The file is already signed, the existing signature must be replaced explicitly");
            }
        }

        CMSSignedData sigData = createSignedData(file);
        
        if (!replace) {
            List<CMSSignedData> signatures = file.getSignatures();
            if (!signatures.isEmpty()) {
                // append the nested signature
                sigData = SignatureUtils.addNestedSignature(signatures.get(0), false, sigData);
            }
        }
        
        file.setSignature(sigData);
        file.save();
    }

    /**
     * Create the PKCS7 message with the signature and the timestamp.
     * 
     * @param file the file to sign
     * @return the PKCS7 message with the signature and the timestamp
     * @throws Exception if an error occurs
     */
    protected CMSSignedData createSignedData(Signable file) throws Exception {
        // compute the signature
        CMSTypedData contentInfo = file.createSignedContent(digestAlgorithm);
        CMSSignedDataGenerator generator = createSignedDataGenerator(file, contentInfo);
        CMSSignedData sigData = generator.generate(contentInfo, true);
        
        // verify the signature
        verify(sigData);
        
        // timestamping
        if (timestamping) {
            Timestamper ts = timestamper;
            if (ts == null) {
                boolean authenticode = AuthenticodeObjectIdentifiers.isAuthenticode(sigData.getSignedContentTypeOID());
                ts = Timestamper.create(authenticode ? tsmode : TimestampingMode.RFC3161);
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

    private CMSSignedDataGenerator createSignedDataGenerator(Signable file, CMSTypedData contentInfo) throws CMSException, OperatorCreationException, CertificateEncodingException {
        List<X509Certificate> fullChain = CertificateUtils.getFullCertificateChain((Collection) Arrays.asList(chain));
        fullChain.removeIf(CertificateUtils::isSelfSigned);

        boolean authenticode = AuthenticodeObjectIdentifiers.isAuthenticode(contentInfo.getContentType().getId());
        CMSSignedDataGenerator generator = authenticode ? new AuthenticodeSignedDataGenerator() : new CMSSignedDataGenerator();
        generator.addCertificates(new JcaCertStore(fullChain));
        generator.addSignerInfoGenerator(createSignerInfoGenerator(file, authenticode));

        return generator;
    }

    private SignerInfoGenerator createSignerInfoGenerator(Signable file, boolean authenticode) throws OperatorCreationException, CertificateEncodingException {
        // create content signer
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(getSignatureAlgorithm());
        if (signatureProvider != null) {
            contentSignerBuilder.setProvider(signatureProvider);
        }
        ContentSigner shaSigner = contentSignerBuilder.build(privateKey);

        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        
        // prepare the authenticated attributes
        List<Attribute> attributes = new ArrayList<>(authenticode ? createAuthenticatedAttributes() : file.createSignedAttributes((X509Certificate) chain[0]));
        AttributeTable attributeTable = new AttributeTable(new DERSet(attributes.toArray(new ASN1Encodable[0])));
        CMSAttributeTableGenerator attributeTableGenerator = new DefaultSignedAttributeTableGenerator(attributeTable);
        if (authenticode) {
            attributeTableGenerator = new FilteredAttributeTableGenerator(attributeTableGenerator, CMSAttributes.cmsAlgorithmProtect, CMSAttributes.signingTime);
        } else {
            attributeTableGenerator = new FilteredAttributeTableGenerator(attributeTableGenerator, CMSAttributes.cmsAlgorithmProtect);
        }
        
        // fetch the signing certificate
        X509CertificateHolder certificate = new JcaX509CertificateHolder((X509Certificate) chain[0]);
        
        // prepare the signerInfo with the extra authenticated attributes
        SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider, new DefaultCMSSignatureEncryptionAlgorithmFinder(){
            @Override
            public AlgorithmIdentifier findEncryptionAlgorithm(final AlgorithmIdentifier signatureAlgorithm) {
                //enforce "RSA" instead of "shaXXXRSA" for digest signature to be more like signtool
                if (signatureAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.sha256WithRSAEncryption) ||
                    signatureAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.sha384WithRSAEncryption) ||
                    signatureAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.sha512WithRSAEncryption)) {
                    return new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
                } else {
                    return super.findEncryptionAlgorithm(signatureAlgorithm);
                }
            }
        });
        signerInfoGeneratorBuilder.setSignedAttributeGenerator(attributeTableGenerator);
        signerInfoGeneratorBuilder.setContentDigest(createContentDigestAlgorithmIdentifier(shaSigner.getAlgorithmIdentifier()));
        return signerInfoGeneratorBuilder.build(shaSigner, certificate);
    }

    private void verify(CMSSignedData signedData) throws SignatureException, OperatorCreationException {
        X509Certificate certificate = (X509Certificate) chain[0];
        PublicKey publicKey = certificate.getPublicKey();
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        SignerInformationVerifier verifier = new JcaSignerInfoVerifierBuilder(digestCalculatorProvider).build(publicKey);

        boolean result = false;
        Throwable cause = null;
        try {
            result = signedData.verifySignatures(signerId -> verifier, false);
        } catch (Exception e) {
            cause = e;
            while (cause.getCause() != null) {
                cause = cause.getCause();
            }
        }

        if (!result) {
            boolean ca = certificate.getBasicConstraints() != -1;
            String message = "Signature verification failed, ";
            if (ca) {
                message += "the certificate is a root or intermediate CA certificate (" + certificate.getSubjectX500Principal() + ")";
            } else {
                message += "the private key doesn't match the certificate";
            }
            throw new SignatureException(message, cause);
        }
    }

    /**
     * Creates the authenticated attributes for the SignerInfo section of the signature.
     * 
     * @return the authenticated attributes
     */
    private List<Attribute> createAuthenticatedAttributes() {
        List<Attribute> attributes = new ArrayList<>();
        
        SpcStatementType spcStatementType = new SpcStatementType(AuthenticodeObjectIdentifiers.SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID);
        attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_STATEMENT_TYPE_OBJID, new DERSet(spcStatementType)));
        
        if (programName != null || programURL != null) {
            SpcSpOpusInfo spcSpOpusInfo = new SpcSpOpusInfo(programName, programURL);
            attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_SP_OPUS_INFO_OBJID, new DERSet(spcSpOpusInfo)));
        }

        return attributes;
    }

    /**
     * Create the digest algorithm identifier to use as content digest.
     * By default looks up the default identifier but also makes sure it includes
     * the algorithm parameters and if not includes a DER NULL in order to align
     * with what signtool currently does.
     *
     * @param signatureAlgorithm to get the corresponding digest algorithm identifier for
     * @return an AlgorithmIdentifier for the digestAlgorithm and including parameters
     */
    protected AlgorithmIdentifier createContentDigestAlgorithmIdentifier(AlgorithmIdentifier signatureAlgorithm) {
        if ("1.3.101.112".equals(signatureAlgorithm.getAlgorithm().getId()) // Ed25519
            || "1.3.101.113".equals(signatureAlgorithm.getAlgorithm().getId())) { // Ed448
            return new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        }

        AlgorithmIdentifier ai = new DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm);
        if (ai.getParameters() == null) {
            // Always include parameters to align with what signtool does
            ai = new AlgorithmIdentifier(ai.getAlgorithm(), DERNull.INSTANCE);
        }
        return ai;
    }
}
