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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.AuthenticodeSignedDataGenerator;
import net.jsign.asn1.authenticode.AuthenticodeTimeStampRequest;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.asn1.authenticode.SpcStatementType;
import net.jsign.pe.DataDirectoryType;
import net.jsign.pe.PEFile;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultAuthenticatedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

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
    public enum HashAlgo {
        SHA1("SHA-1",X509ObjectIdentifiers.id_SHA1, TSPAlgorithms.SHA1),
        SHA256("SHA-256", NISTObjectIdentifiers.id_sha256, TSPAlgorithms.SHA256);

        public final String id;
        public final DERObjectIdentifier oid;
        public final ASN1ObjectIdentifier tsp;

        HashAlgo(String id, DERObjectIdentifier oid, ASN1ObjectIdentifier tsp) {
            this.id = id;
            this.oid = oid;
            this.tsp = tsp;
	}

        public static HashAlgo asMyEnum(String str) {
            if (str == null)
                return null;
            for (HashAlgo me : HashAlgo.values())
                if(me.name().equals(str))
                    return me;
            return null;
        }

        /*
             If no algorithm is specified, pick a smart default
             @see http://blogs.technet.com/b/pki/archive/2011/02/08/common-questions-about-sha2-and-windows.aspx
             @see http://support.microsoft.com/kb/2763674
        */
        public static final HashAlgo getDefault() {
            Calendar now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
            Calendar cutoff = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
            cutoff.set(2016, 1, 1);
            return (now.before(cutoff) ? HashAlgo.SHA1 : HashAlgo.SHA256);
        }
    }

    private Certificate[] chain;
    private PrivateKey privateKey;
    private HashAlgo algo = HashAlgo.getDefault();
    private String programName;
    private String programURL;

    private boolean timestamping = true;
    private boolean timestampingRFC = false;
    private String tsaurlOverride;

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
     */
    public PESigner withTimestampingProtocol(boolean useRFC3161TimestampingServer) {
        this.timestampingRFC = useRFC3161TimestampingServer;
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
     * Set the HashAlgorithm to use (default is SHA1)
     */
    public PESigner withHashAlgorith(String algorithm) {
        HashAlgo selectedAlgo = HashAlgo.asMyEnum(algorithm);
         // if the algorithm is not supported use the default instead of erroring out
        if (selectedAlgo != null) {
            this.algo = selectedAlgo;
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
        byte[] certificateTable = createCertificateTable(file);
        
        file.writeDataDirectory(DataDirectoryType.CERTIFICATE_TABLE, certificateTable);
        file.close();
    }

    private byte[] createCertificateTable(PEFile file) throws IOException, CMSException, OperatorCreationException, CertificateEncodingException {
        CMSSignedData sigData = createSignature(file);
        
        if (timestamping) {
            sigData = timestamp(sigData);
        }
        
        // pad the table
        byte[] signature = sigData.toASN1Structure().getEncoded("DER");
        signature = pad(signature, 8);
        
        // add the header
        ByteBuffer buffer = ByteBuffer.allocate(signature.length + 8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(buffer.limit());
        buffer.putShort((short) 0x0200);
        buffer.putShort((short) 0x0002);
        buffer.put(signature);
        
        return buffer.array();
    }

    private byte[] pad(byte[] data, int multiple) {
        if (data.length % multiple == 0) {
            return data;
        } else {
            byte[] copy = new byte[data.length + (multiple - data.length % multiple)];
            System.arraycopy(data, 0, copy, 0, data.length);
            return copy;
        }
    }

    private CMSSignedData createSignature(PEFile file) throws IOException, CMSException, OperatorCreationException, CertificateEncodingException {
        byte[] sha = file.computeDigest(algo.id);
        
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(algo.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, sha);
        SpcIndirectDataContent spcIndirectDataContent = new SpcIndirectDataContent(digestInfo);
        
        ContentSigner shaSigner = new JcaContentSignerBuilder(algo+"with" + privateKey.getAlgorithm()).build(privateKey);
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
        
        // prepare the authenticated attributes
        CMSAttributeTableGenerator attributeTableGenerator = new DefaultAuthenticatedAttributeTableGenerator(createAuthenticatedAttributes());
        
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

    /**
     * Add a timestamp to the signature.
     */
    private CMSSignedData timestamp(CMSSignedData sigData) throws IOException, CMSException {
        SignerInformation signerInformation = ((SignerInformation) sigData.getSignerInfos().getSigners().iterator().next());

        CMSSignedData token;
        if(timestampingRFC) {
            String tsaurl = (tsaurlOverride == null ? "http://timestamp.comodoca.com/rfc3161" : tsaurlOverride);
            token = timestampRFC(signerInformation.toASN1Structure().getEncryptedDigest().getOctets(), new URL(tsaurl));
        } else {
            String tsaurl = (tsaurlOverride == null ? "http://timestamp.comodoca.com/authenticode" : tsaurlOverride);
            token = timestampAuthenticode(signerInformation.toASN1Structure().getEncryptedDigest().getOctets(), new URL(tsaurl));
        }

        SignerInformation timestampSignerInformation = (SignerInformation) token.getSignerInfos().getSigners().iterator().next();

        Attribute counterSignature = new Attribute(CMSAttributes.counterSignature, new DERSet(timestampSignerInformation.toASN1Structure()));
        
        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, new AttributeTable(new DERSet(counterSignature)));
        
        // add the certificates for the timestamp authority
        Collection<?> certificates = new ArrayList();
        certificates.addAll(sigData.getCertificates().getMatches(null));
        certificates.addAll(token.getCertificates().getMatches(null));
        Store certificateStore = new CollectionStore(certificates);
        
        AuthenticodeSignedDataGenerator generator = new AuthenticodeSignedDataGenerator();
        generator.addCertificates(certificateStore);
        generator.addSigners(new SignerInformationStore(Arrays.asList(signerInformation)));
        
        ASN1ObjectIdentifier contentType = new ASN1ObjectIdentifier(sigData.getSignedContentTypeOID());
        ASN1Encodable content = ASN1Sequence.getInstance(sigData.getSignedContent().getContent());
                
        return generator.generate(contentType, content);
    }

    private CMSSignedData timestampAuthenticode(byte[] encryptedDigest, URL tsaurl) throws IOException, CMSException {
        AuthenticodeTimeStampRequest timestampRequest = new AuthenticodeTimeStampRequest(encryptedDigest);
        
        byte[] request = Base64.encode(timestampRequest.getEncoded("DER"));
        
        HttpURLConnection conn = (HttpURLConnection) tsaurl.openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-type", "application/octet-stream");
        conn.setRequestProperty("Content-length", String.valueOf(request.length));
        conn.setRequestProperty("Accept", "application/octet-stream");
        conn.setRequestProperty("User-Agent", "Transport");
        
        conn.getOutputStream().write(request);
        conn.getOutputStream().flush();
        
        if (conn.getResponseCode() >= 400) {
            throw new IOException("Unable to complete the timestamping due to HTTP error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
        }
        
        InputStream in = conn.getInputStream();
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        
        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) != -1) {
            bout.write(buffer, 0, n);
        }
        
        byte[] response = Base64.decode(bout.toByteArray());
        
        return new CMSSignedData(response);
    }

    private CMSSignedData timestampRFC(byte[] encryptedDigest, URL tsaurl) throws IOException, CMSException {
        OutputStream out = null;

        try {
            MessageDigest md = MessageDigest.getInstance(algo.id);
            TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
            TimeStampRequest req = reqgen.generate(algo.tsp, md.digest(encryptedDigest));
            byte request[] = req.getEncoded();

            HttpURLConnection con = (HttpURLConnection) tsaurl.openConnection();
            con.setConnectTimeout(10000);
            con.setReadTimeout(10000);
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setUseCaches(false);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/timestamp-query");
            con.setRequestProperty("Content-length", String.valueOf(request.length));
            con.setRequestProperty("Accept", "application/timestamp-query");
            con.setRequestProperty("User-Agent", "Transport");
            out = con.getOutputStream();
            out.write(request);
            out.flush();

            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
            }
            InputStream in = con.getInputStream();
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(req);
            if (response.getStatus() != 0) {
                throw new IOException("Received an invalid timestamp (status="+response.getStatusString()+")");
            }
            return response.getTimeStampToken().toCMSSignedData();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
