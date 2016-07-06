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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcPeImageData;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.asn1.authenticode.SpcStatementType;
import net.jsign.pe.CertificateTableEntry;
import net.jsign.pe.DataDirectoryType;
import net.jsign.pe.PEFile;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

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
    private DigestAlgorithm algo = DigestAlgorithm.getDefault();
    private String programName;
    private String programURL;

    private boolean timestamping = true;
    private TimestampingMode tsmode = TimestampingMode.AUTHENTICODE;
    private String tsaurlOverride;
    private Timestamper timestamper;

    public PESigner(Certificate[] chain, PrivateKey privateKey) {
        this.chain = chain;
        this.privateKey = privateKey;
    }

    public PESigner(KeyStore keystore, String alias, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        this(keystore.getCertificateChain(alias), (PrivateKey) keystore.getKey(alias, password.toCharArray()));
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
     */
    public PESigner withTimestampingAutority(String url) {
        this.tsaurlOverride = url;
        return this;
    }
    
    /**
     * Set the Timestamper implementation.
     */
    public PESigner withTimestamper(Timestamper timestamper) {
        this.timestamper = timestamper;
        return this;
    }

    /**
     * Set the digest algorithm to use (default is SHA-1 until January 1 2016, SHA-256 afterward)
     */
    public PESigner withDigestAlgorithm(DigestAlgorithm algorithm) {
        if (algorithm != null) {
            this.algo = algorithm;
        }
        return this;
    }

    /**
     * Sign the specified executable file.
     * @throws Exception
     */
    public void sign(PEFile file) throws Exception {
        // pad the file on a 8 byte boundary
        // todo only if there was no previous certificate table
        file.pad(8);
        
        // compute the signature
        CertificateTableEntry entry = createCertificateTableEntry(file);
        
        file.writeDataDirectory(DataDirectoryType.CERTIFICATE_TABLE, entry.toBytes());
        file.close();
    }

    private CertificateTableEntry createCertificateTableEntry(PEFile file) throws IOException, CMSException, OperatorCreationException, CertificateEncodingException {
        CMSSignedData sigData = createSignature(file);
        
        if (timestamping) {
            Timestamper ts = timestamper;
            if (ts == null) {
                ts = Timestamper.create(tsmode);
            }
            if (tsaurlOverride != null) {
                ts.setURL(tsaurlOverride);
            }
            sigData = ts.timestamp(algo, sigData);
        }
        
        return new CertificateTableEntry(sigData);
    }

    private CMSSignedData createSignature(PEFile file) throws IOException, CMSException, OperatorCreationException, CertificateEncodingException {
        byte[] sha = file.computeDigest(algo);
        
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(algo.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, sha);
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID, new SpcPeImageData());
        SpcIndirectDataContent spcIndirectDataContent = new SpcIndirectDataContent(data, digestInfo);

        ContentSigner shaSigner = new JcaContentSignerBuilder(algo + "with" + privateKey.getAlgorithm()).build(privateKey);
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        
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
        List<Certificate> list = new ArrayList<Certificate>();
        
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
        List<Attribute> attributes = new ArrayList<Attribute>();
        
        SpcStatementType spcStatementType = new SpcStatementType(AuthenticodeObjectIdentifiers.SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID);
        attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_STATEMENT_TYPE_OBJID, new DERSet(spcStatementType)));
        
        if (programName != null || programURL != null) {
            SpcSpOpusInfo spcSpOpusInfo = new SpcSpOpusInfo(programName, programURL);
            attributes.add(new Attribute(AuthenticodeObjectIdentifiers.SPC_SP_OPUS_INFO_OBJID, new DERSet(spcSpOpusInfo)));
        }
        
        return new AttributeTable(new DERSet(attributes.toArray(new ASN1Encodable[attributes.size()])));
    }
}
