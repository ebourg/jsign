/*
 * Copyright 2012 Emmanuel Bourg
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

import net.jsign.asn1.authenticode.AuthenticodeDigestCalculatorProvider;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.asn1.authenticode.SpcStatementType;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingMode;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

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

/**
 * Sign a file. Timestamping is enabled by default
 * and relies on the Comodo server (http://timestamp.comodoca.com/authenticode).
 */
abstract class BaseSigner<T extends BaseSigner, S> {

    private Certificate[] chain;
    private PrivateKey privateKey;
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.getDefault();
    private String signatureAlgorithm;
    private Provider signatureProvider;
    private String programName;
    private String programURL;

    private boolean timestamping = true;
    private TimestampingMode tsmode = TimestampingMode.AUTHENTICODE;
    private String[] tsaurlOverride;
    private Timestamper timestamper;
    private int timestampingRetries = -1;
    private int timestampingRetryWait = -1;

    /**
     * Create a BaseSigner with the specified certificate chain and private key.
     *
     * @param chain       the certificate chain. The first certificate is the signing certificate
     * @param privateKey  the private key
     * @throws IllegalArgumentException if the chain is empty
     */
    public BaseSigner(Certificate[] chain, PrivateKey privateKey) {
        this.chain = chain;
        this.privateKey = privateKey;

        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("The certificate chain is empty");
        }
    }

    /**
     * Create a BaseSigner with a certificate chain and private key from the specified keystore.
     *
     * @param keystore the keystore holding the certificate and the private key
     * @param alias    the alias of the certificate in the keystore
     * @param password the password to get the private key
     */
    public BaseSigner(KeyStore keystore, String alias, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
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
    public T withProgramName(String programName) {
        this.programName = programName;
        return (T) this;
    }

    /**
     * Set the program URL embedded in the signature.
     */
    public T withProgramURL(String programURL) {
        this.programURL = programURL;
        return (T) this;
    }

    /**
     * Enable or disable the timestamping (enabled by default).
     */
    public T withTimestamping(boolean timestamping) {
        this.timestamping = timestamping;
        return (T) this;
    }

    /**
     * RFC3161 or Authenticode (Authenticode by default).
     *
     * @since 1.3
     */
    public T withTimestampingMode(TimestampingMode tsmode) {
        this.tsmode = tsmode;
        return (T) this;
    }

    /**
     * Set the URL of the timestamping authority.
     *
     * @since 2.1
     */
    public T withTimestampingAuthority(String url) {
        return withTimestampingAuthority(new String[] { url });
    }

    /**
     * Set the URL of the timestamping authority.
     *
     * @deprecated
     */
    public T withTimestampingAutority(String url) {
        return withTimestampingAuthority(url);
    }

    /**
     * Set the URL of the timestamping authority.
     *
     * @since 2.1
     */
    public T withTimestampingAuthority(String... url) {
        this.tsaurlOverride = url;
        return (T) this;
    }

    /**
     * Set the URL of the timestamping authority.
     *
     * @since 2.0
     * @deprecated
     */
    public T withTimestampingAutority(String... url) {
        return withTimestampingAuthority(url);
    }

    /**
     * Set the Timestamper implementation.
     */
    public T withTimestamper(Timestamper timestamper) {
        this.timestamper = timestamper;
        return (T) this;
    }

    /**
     * Set the number of retries for timestamping.
     */
    public T withTimestampingRetries(int timestampingRetries) {
        this.timestampingRetries = timestampingRetries;
        return (T) this;
    }

    /**
     * Set the number of seconds to wait between timestamping retries.
     */
    public T withTimestampingRetryWait(int timestampingRetryWait) {
        this.timestampingRetryWait = timestampingRetryWait;
        return (T) this;
    }

    /**
     * Set the digest algorithm to use (SHA-256 by default)
     */
    public T withDigestAlgorithm(DigestAlgorithm algorithm) {
        if (algorithm != null) {
            this.digestAlgorithm = algorithm;
        }
        return (T) this;
    }

    /**
     * Explicitly sets the signature algorithm to use.
     *
     * @since 2.0
     */
    public T withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return (T) this;
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     *
     * @since 2.0
     */
    public T withSignatureAlgorithm(String signatureAlgorithm, String signatureProvider) {
        return withSignatureAlgorithm(signatureAlgorithm, Security.getProvider(signatureProvider));
    }

    /**
     * Explicitly sets the signature algorithm and provider to use.
     *
     * @since 2.0
     */
    public T withSignatureAlgorithm(String signatureAlgorithm, Provider signatureProvider) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureProvider = signatureProvider;
        return (T) this;
    }

    /**
     * Set the signature provider to use.
     *
     * @since 2.0
     */
    public T withSignatureProvider(Provider signatureProvider) {
        this.signatureProvider = signatureProvider;
        return (T) this;
    }

    protected CMSSignedData computeSignedData(S signee) throws Exception {
        // compute the signature
        CMSSignedData sigData = createSignature(signee);

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

    private CMSSignedData createSignature(S signee) throws IOException, CMSException, OperatorCreationException, CertificateEncodingException {
        byte[] sha = computeDigest(digestAlgorithm, signee);

        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, sha);

        SpcAttributeTypeAndOptionalValue data = createSpiAttribute(digestAlgorithm, signee);
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

    abstract byte[] computeDigest(DigestAlgorithm digestAlgorithm, S signee) throws IOException;

    abstract SpcAttributeTypeAndOptionalValue createSpiAttribute(DigestAlgorithm digestAlgorithm, S signee) throws IOException;

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

        return new AttributeTable(new DERSet(attributes.toArray(new ASN1Encodable[0])));
    }
}
