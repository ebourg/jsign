/*
 * Copyright 2017 Emmanuel Bourg and contributors
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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.util.encoders.Hex;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcLink;
import net.jsign.asn1.authenticode.SpcSpOpusInfo;
import net.jsign.timestamp.Timestamper;
import net.jsign.timestamp.TimestampingMode;

/**
 * Helper class to create AuthenticodeSigner instances with untyped parameters.
 * This is used internally to share the parameter validation logic
 * between the Ant task, the Maven/Gradle plugins and the CLI tool.
 *
 * @since 2.0
 */
class SignerHelper {
    public static final String PARAM_COMMAND = "command";
    public static final String PARAM_KEYSTORE = "keystore";
    public static final String PARAM_STOREPASS = "storepass";
    public static final String PARAM_STORETYPE = "storetype";
    public static final String PARAM_ALIAS = "alias";
    public static final String PARAM_KEYPASS = "keypass";
    public static final String PARAM_KEYFILE = "keyfile";
    public static final String PARAM_CERTFILE = "certfile";
    public static final String PARAM_ALG = "alg";
    public static final String PARAM_TSAURL = "tsaurl";
    public static final String PARAM_TSMODE = "tsmode";
    public static final String PARAM_TSRETRIES = "tsretries";
    public static final String PARAM_TSRETRY_WAIT = "tsretrywait";
    public static final String PARAM_NAME = "name";
    public static final String PARAM_URL = "url";
    public static final String PARAM_PROXY_URL = "proxyUrl";
    public static final String PARAM_PROXY_USER = "proxyUser";
    public static final String PARAM_PROXY_PASS = "proxyPass";
    public static final String PARAM_NON_PROXY_HOSTS = "nonProxyHosts";
    public static final String PARAM_REPLACE = "replace";
    public static final String PARAM_LAZY = "lazy";
    public static final String PARAM_ENCODING = "encoding";
    public static final String PARAM_DETACHED = "detached";
    public static final String PARAM_FORMAT = "format";
    public static final String PARAM_VALUE = "value";

    private final Logger log = Logger.getLogger(getClass().getName());

    /** The name used to refer to a configuration parameter */
    private final String parameterName;

    /** The command to execute */
    private String command = "sign";

    private final KeyStoreBuilder ksparams;
    private String alias;
    private String tsaurl;
    private String tsmode;
    private int tsretries = -1;
    private int tsretrywait = -1;
    private String alg;
    private String name;
    private String url;
    private final ProxySettings proxySettings = new ProxySettings();
    private boolean replace;
    private boolean lazy;
    private Charset encoding;
    private boolean detached;
    private String format;
    private String value;

    private AuthenticodeSigner signer;

    public SignerHelper(String parameterName) {
        this.parameterName = parameterName;
        this.ksparams = new KeyStoreBuilder(parameterName);
    }

    public SignerHelper command(String command) {
        this.command = command;
        return this;
    }

    public SignerHelper keystore(String keystore) {
        ksparams.keystore(keystore);
        signer = null;
        return this;
    }

    public SignerHelper storepass(String storepass) {
        ksparams.storepass(storepass);
        signer = null;
        return this;
    }

    public SignerHelper storetype(String storetype) {
        ksparams.storetype(storetype);
        signer = null;
        return this;
    }

    public SignerHelper alias(String alias) {
        this.alias = alias;
        signer = null;
        return this;
    }

    public SignerHelper keypass(String keypass) {
        ksparams.keypass(keypass);
        signer = null;
        return this;
    }

    public SignerHelper keyfile(String keyfile) {
        ksparams.keyfile(keyfile);
        signer = null;
        return this;
    }

    public SignerHelper keyfile(File keyfile) {
        ksparams.keyfile(keyfile);
        signer = null;
        return this;
    }

    public SignerHelper certfile(String certfile) {
        ksparams.certfile(certfile);
        signer = null;
        return this;
    }

    public SignerHelper certfile(File certfile) {
        ksparams.certfile(certfile);
        signer = null;
        return this;
    }

    public SignerHelper alg(String alg) {
        this.alg = alg;
        signer = null;
        return this;
    }

    public SignerHelper tsaurl(String tsaurl) {
        this.tsaurl = tsaurl;
        signer = null;
        return this;
    }

    public SignerHelper tsmode(String tsmode) {
        this.tsmode = tsmode;
        signer = null;
        return this;
    }

    public SignerHelper tsretries(int tsretries) {
        this.tsretries = tsretries;
        signer = null;
        return this;
    }

    public SignerHelper tsretrywait(int tsretrywait) {
        this.tsretrywait = tsretrywait;
        signer = null;
        return this;
    }

    public SignerHelper name(String name) {
        this.name = name;
        signer = null;
        return this;
    }

    public SignerHelper url(String url) {
        this.url = url;
        signer = null;
        return this;
    }

    public SignerHelper proxyUrl(String proxyUrl) {
        this.proxySettings.url = proxyUrl;
        signer = null;
        return this;
    }

    public SignerHelper proxyUser(String proxyUser) {
        this.proxySettings.username = proxyUser;
        signer = null;
        return this;
    }

    public SignerHelper proxyPass(String proxyPass) {
        this.proxySettings.password = proxyPass;
        signer = null;
        return this;
    }

    public SignerHelper nonProxyHosts(String nonProxyHosts) {
        this.proxySettings.nonProxyHosts = nonProxyHosts;
        signer = null;
        return this;
    }

    public SignerHelper replace(boolean replace) {
        this.replace = replace;
        signer = null;
        return this;
    }

    public SignerHelper lazy(boolean lazy) {
        this.lazy = lazy;
        return this;
    }

    public SignerHelper encoding(String encoding) {
        this.encoding = Charset.forName(encoding);
        return this;
    }

    public SignerHelper detached(boolean detached) {
        this.detached = detached;
        return this;
    }

    public SignerHelper format(String format) {
        this.format = format;
        return this;
    }

    public SignerHelper value(String value) {
        this.value = value;
        return this;
    }

    public SignerHelper param(String key, String value) {
        if (value == null) {
            return this;
        }
        
        switch (key) {
            case PARAM_COMMAND:    return command(value);
            case PARAM_KEYSTORE:   return keystore(value);
            case PARAM_STOREPASS:  return storepass(value);
            case PARAM_STORETYPE:  return storetype(value);
            case PARAM_ALIAS:      return alias(value);
            case PARAM_KEYPASS:    return keypass(value);
            case PARAM_KEYFILE:    return keyfile(value);
            case PARAM_CERTFILE:   return certfile(value);
            case PARAM_ALG:        return alg(value);
            case PARAM_TSAURL:     return tsaurl(value);
            case PARAM_TSMODE:     return tsmode(value);
            case PARAM_TSRETRIES:  return tsretries(Integer.parseInt(value));
            case PARAM_TSRETRY_WAIT: return tsretrywait(Integer.parseInt(value));
            case PARAM_NAME:       return name(value);
            case PARAM_URL:        return url(value);
            case PARAM_PROXY_URL:  return proxyUrl(value);
            case PARAM_PROXY_USER: return proxyUser(value);
            case PARAM_PROXY_PASS: return proxyPass(value);
            case PARAM_NON_PROXY_HOSTS: return nonProxyHosts(value);
            case PARAM_REPLACE:    return replace("true".equalsIgnoreCase(value));
            case PARAM_LAZY:       return lazy("true".equalsIgnoreCase(value));
            case PARAM_ENCODING:   return encoding(value);
            case PARAM_DETACHED:   return detached("true".equalsIgnoreCase(value));
            case PARAM_FORMAT:     return format(value);
            case PARAM_VALUE:      return value(value);
            default:
                throw new IllegalArgumentException("Unknown " + parameterName + ": " + key);
        }
    }

    void setBaseDir(File basedir) {
        ksparams.setBaseDir(basedir);
    }

    public void execute(String file) throws SignerException {
        execute(ksparams.createFile(file));
    }

    public void execute(File file) throws SignerException {
        switch (command) {
            case "sign":
                sign(file);
                break;
            case "timestamp":
                timestamp(file);
                break;
            case "extract":
                extract(file);
                break;
            case "remove":
                remove(file);
                break;
            case "show":
                show(file);
                break;
            case "tag":
                tag(file);
                break;
            default:
                throw new SignerException("Unknown command '" + command + "'");
        }
    }

    private AuthenticodeSigner build() throws SignerException {
        try {
            proxySettings.initializeProxy();
        } catch (Exception e) {
            throw new SignerException("Couldn't initialize proxy", e);
        }

        KeyStore ks;
        try {
            ks = ksparams.build();
        } catch (KeyStoreException e) {
            throw new SignerException("Failed to load the keystore " + (ksparams.keystore() != null ? ksparams.keystore() : ""), e);
        }
        KeyStoreType storetype = ksparams.storetype();
        Provider provider = ksparams.provider();

        Set<String> aliases = null;
        if (alias == null) {
            // guess the alias if there is only one in the keystore
            try {
                aliases = storetype.getAliases(ks);
            } catch (KeyStoreException e) {
                throw new SignerException(e.getMessage(), e);
            }

            if (aliases.isEmpty()) {
                throw new SignerException("No certificate found in the keystore " + (provider != null ? provider.getName() : ksparams.keystore()));
            } else if (aliases.size() == 1) {
                alias = aliases.iterator().next();
            } else {
                throw new SignerException("alias " + parameterName + " must be set to select a certificate (available aliases: " + String.join(", ", aliases) + ")");
            }
        }

        Certificate[] chain;
        if (ksparams.certfile() != null) {
            // replace the certificate chain from the keystore with the complete chain from file
            try {
                chain = CertificateUtils.loadCertificateChain(ksparams.certfile());
            } catch (Exception e) {
                throw new SignerException("Failed to load the certificate from " + ksparams.certfile(), e);
            }
        } else {
            try {
                chain = ks.getCertificateChain(alias);
            } catch (KeyStoreException e) {
                throw new SignerException(e.getMessage(), e);
            }
            if (chain == null) {
                String message = "No certificate found under the alias '" + alias + "' in the keystore " + (provider != null ? provider.getName() : ksparams.keystore());
                if (aliases == null) {
                    try {
                        aliases = new LinkedHashSet<>(Collections.list(ks.aliases()));
                        if (aliases.isEmpty()) {
                            message = "No certificate found in the keystore " + (provider != null ? provider.getName() : ksparams.keystore());
                        } else if (aliases.contains(alias)) {
                            message = "The keystore password must be specified";
                        } else {
                            message += " (available aliases: " + String.join(", ", aliases) + ")";
                        }
                    } catch (KeyStoreException e) {
                        message += " (couldn't load the list of available aliases: " + e.getMessage() + ")";
                    }
                }
                throw new SignerException(message);
            }
        }

        String keypass = ksparams.keypass();
        char[] password = keypass != null ? keypass.toCharArray() : new char[0];

        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) ks.getKey(alias, password);
        } catch (Exception e) {
            throw new SignerException("Failed to retrieve the private key from the keystore", e);
        }

        if (alg != null && DigestAlgorithm.of(alg) == null) {
            throw new SignerException("The digest algorithm " + alg + " is not supported");
        }

        // enable timestamping with Azure Artifact Signing
        if (tsaurl == null && storetype == KeyStoreType.TRUSTEDSIGNING) {
            tsaurl = "http://timestamp.acs.microsoft.com/";
            tsmode = TimestampingMode.RFC3161.name();
            tsretries = 3;
        }
        
        // configure the signer
        return new AuthenticodeSigner(chain, privateKey)
                .withProgramName(name)
                .withProgramURL(url)
                .withDigestAlgorithm(DigestAlgorithm.of(alg))
                .withSignatureProvider(provider)
                .withSignaturesReplaced(replace)
                .withTimestamping(tsaurl != null || tsmode != null)
                .withTimestampingMode(tsmode != null ? TimestampingMode.of(tsmode) : TimestampingMode.AUTHENTICODE)
                .withTimestampingRetries(tsretries)
                .withTimestampingRetryWait(tsretrywait)
                .withTimestampingAuthority(tsaurl != null ? tsaurl.split(",") : null);
    }

    public void sign(String file) throws SignerException {
        sign(ksparams.createFile(file));
    }

    public void sign(File file) throws SignerException {
        if (file == null) {
            throw new SignerException("No file specified");
        }
        if (!file.exists()) {
            throw new SignerException("The file " + file + " couldn't be found");
        }
        
        try (Signable signable = Signable.of(file, encoding)) {
            File detachedSignature = getDetachedSignature(file);
            if (detached && detachedSignature.exists()) {
                try {
                    log.info("Attaching Authenticode signature to " + file);
                    attach(signable, detachedSignature);
                } catch (Exception e) {
                    throw new SignerException("Couldn't attach the signature to " + file, e);
                }

            } else {
                if (lazy && !signable.getSignatures().isEmpty()) {
                    log.info("Skipping already signed file " + file);
                    return;
                }

                if (signer == null) {
                    signer = build();
                }

                log.info("Adding Authenticode signature to " + file);
                signer.sign(signable);

                if (detached) {
                    detach(signable, detachedSignature);
                }
            }

        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            throw new SignerException(e.getMessage(), e);
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException("Couldn't sign " + file, e);
        }
    }

    private void attach(Signable signable, File detachedSignature) throws IOException {
        byte[] signatureBytes = Files.readAllBytes(detachedSignature.toPath());
        signable.setSignatures(SignatureUtils.getSignatures(signatureBytes));
        signable.save();
        // todo warn if the hashes don't match
    }

    private void detach(Signable signable, File detachedSignature) throws IOException {
        List<CMSSignedData> signatures = signable.getSignatures();

        // ensure the secondary signatures are nested in the first one (for EFI files)
        CMSSignedData signedData = signatures.get(0);
        if (signatures.size() > 1) {
            List<CMSSignedData> nestedSignatures = signatures.subList(1, signatures.size());
            signedData = SignatureUtils.addNestedSignature(signedData, true, nestedSignatures.toArray(new CMSSignedData[0]));
        }

        byte[] content = signedData.toASN1Structure().getEncoded("DER");
        if (format == null || "DER".equalsIgnoreCase(format)) {
            Files.write(detachedSignature.toPath(), content);
        } else if ("PEM".equalsIgnoreCase(format)) {
            try (FileWriter out = new FileWriter(detachedSignature)) {
                String encoded = Base64.getEncoder().encodeToString(content);
                out.write("-----BEGIN PKCS7-----\n");
                for (int i = 0; i < encoded.length(); i += 64) {
                    out.write(encoded.substring(i, Math.min(i + 64, encoded.length())));
                    out.write('\n');
                }
                out.write("-----END PKCS7-----\n");
            }
        } else {
            throw new IllegalArgumentException("Unknown output format '" + format + "'");
        }
    }

    private File getDetachedSignature(File file) {
        return new File(file.getParentFile(), file.getName() + ".sig");
    }

    private void extract(File file) throws SignerException {
        if (!file.exists()) {
            throw new SignerException("Couldn't find " + file);
        }

        try (Signable signable = Signable.of(file)) {
            List<CMSSignedData> signatures = signable.getSignatures();
            if (signatures.isEmpty()) {
                throw new SignerException("No signature found in " + file);
            }

            File detachedSignature = getDetachedSignature(file);
            if ("PEM".equalsIgnoreCase(format)) {
                detachedSignature = new File(detachedSignature.getParentFile(), detachedSignature.getName() + ".pem");
            }
            log.info("Extracting signature to " + detachedSignature);
            detach(signable, detachedSignature);
        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            throw new SignerException(e.getMessage(), e);
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException("Couldn't extract the signature from " + file, e);
        }
    }

    private void remove(File file) throws SignerException {
        if (!file.exists()) {
            throw new SignerException("Couldn't find " + file);
        }

        try (Signable signable = Signable.of(file)) {
            List<CMSSignedData> signatures = signable.getSignatures();
            if (signatures.isEmpty()) {
                log.severe("No signature found in " + file);
                return;
            }

            log.info("Removing " + signatures.size() + " signature" + (signatures.size() > 1 ? "s" : "") + " from " + file);
            signable.setSignatures(null);
            signable.save();
        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            throw new SignerException(e.getMessage(), e);
        } catch (Exception e) {
            throw new SignerException("Couldn't remove the signature from " + file, e);
        }
    }

    private void show(File file) throws SignerException {
        if (!file.exists()) {
            throw new SignerException("Couldn't find " + file);
        }

        AnsiFormatter ansiFormatter = new AnsiFormatter();
        log.setFilter(record -> {
            record.setMessage(ansiFormatter.format(record.getMessage()));
            return true;
        });

        try (Signable signable = Signable.of(file)) {
            boolean verbose = log.isLoggable(Level.FINE);

            List<CMSSignedData> signatures = signable.getSignatures();
            if (signatures.isEmpty()) {
                log.info("No signature found in " + (verbose ? file.getAbsolutePath() : file.getName()));
                return;
            }

            log.info("Signature" + (signatures.size() > 1 ? "s" : "") + " of " + (verbose ? file.getAbsolutePath() : file.getName()) + ":");
            log.info("");

            DateFormat datetimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
            DateFormat dateFormat = verbose ? datetimeFormat : new SimpleDateFormat("yyyy-MM-dd");

            for (int i = 0; i < signatures.size(); i++) {
                CMSSignedData signature = signatures.get(i);
                SignerInformation signer = signature.getSignerInfos().iterator().next();
                DigestInfo digestInfo = SignatureUtils.getDigestInfo(signature);
                X509CertificateHolder cert = (X509CertificateHolder) signature.getCertificates().getMatches(signer.getSID()).iterator().next();

                boolean expired = cert.getNotAfter().before(new Date());
                long daysLeft = Duration.between(Instant.now(), cert.getNotAfter().toInstant()).toDays();

                if (signatures.size() > 1) {
                    log.info("Signature #" + (i + 1));
                }
                if (digestInfo != null) {
                    DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(signer.getDigestAlgorithmID().getAlgorithm());
                    byte[] computedDigest = signable.computeDigest(digestAlgorithm);
                    boolean matches = Arrays.equals(computedDigest, digestInfo.getDigest());
                    log.info("  <b>Digest:</b>          (" + digestAlgorithm.id + ") " + Hex.toHexString(digestInfo.getDigest()) + (matches ? " (<green>matches</green>)" : " (<red>mismatches</red>)"));
                    if (!matches) {
                        log.info("  <b>Expected Digest:</b> (" + digestAlgorithm.id + ") " + Hex.toHexString(computedDigest));
                    }
                }

                Date timestamp = SignatureUtils.getTimestampDate(signature);
                if (timestamp != null) {
                    X509CertificateHolder timestampCertificate = SignatureUtils.getTimestampCertificate(signature);
                    log.info("  <b>Timestamp:</b>       " + datetimeFormat.format(timestamp) + " (" + formatName(timestampCertificate.getSubject(), verbose) + ")");
                }

                SpcSpOpusInfo spOpusInfo = SignatureUtils.getSpcSpOpusInfo(signature);
                if (spOpusInfo != null) {
                    if (spOpusInfo.getProgramName() != null && !spOpusInfo.getProgramName().trim().isEmpty()) {
                        log.info("  <b>Program Name:</b>    " + spOpusInfo.getProgramName());
                    }
                    SpcLink moreInfo = spOpusInfo.getMoreInfo();
                    if (moreInfo != null && moreInfo.getUrl() != null && !moreInfo.getUrl().trim().isEmpty()) {
                        log.info("  <b>URL:</b>             " + moreInfo.getUrl());
                    }
                }

                String tag = formatTag(SignatureUtils.getTag(signature));
                if (tag != null) {
                    log.info("  <b>Tag:</b>             " + tag.trim());
                }

                log.info("  <b>Certificate</b>");
                log.info("    <b>Subject:</b>       " + formatName(cert.getSubject(), verbose));
                log.info("    <b>Issuer:</b>        " + formatName(cert.getIssuer(), verbose));
                log.info("    <b>Key:</b>           " + getKeyAlgorithm(cert));
                log.info("    <b>Validity:</b>      " + dateFormat.format(cert.getNotBefore()) + " - " + dateFormat.format(cert.getNotAfter()) + " (" + (expired ? "expired" : daysLeft + " days left") + ")");
                log.info("    <b>Serial:</b>        " + String.format("%032x", cert.getSerialNumber()));
                log.info("");
            }
        } catch (Exception e) {
            throw new SignerException("Couldn't show the signatures of " + file, e);
        }
    }

    /**
     * Formats the X500 name:
     * <ul>
     *   <li>in normal mode, returns only the common name (CN)</li>
     *   <li>in verbose mode, returns the full name in LDAP order (starting with the common name)</li>
     * </ul>
     */
    private String formatName(X500Name name, boolean verbose) {
        if (verbose) {
            return new X500Name(new BCStyle() {
                public String toString(X500Name name) {
                    StringBuilder buf = new StringBuilder();
                    RDN[] rdns = name.getRDNs();
                    for (int i = rdns.length - 1; i >= 0; i--) {
                        if (i != rdns.length - 1) {
                            buf.append(", ");
                        }
                        IETFUtils.appendRDN(buf, rdns[i], defaultSymbols);
                    }
                    return buf.toString();
                }
            }, name.getRDNs()).toString().replaceAll("\\\\,", ",");
        } else {
            return name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
        }
    }

    /**
     * Returns the algorithm of the public key of the certificate (for example "RSA 2048" or "EC 384").
     */
    private String getKeyAlgorithm(X509CertificateHolder certificate) throws IOException, CertificateException {
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
        PublicKey publicKey = cert.getPublicKey();

        if (publicKey instanceof RSAPublicKey) {
            return "RSA " + ((RSAPublicKey) publicKey).getModulus().bitLength();
        } else if (publicKey instanceof ECPublicKey) {
            return "EC " + (((ECPublicKey) publicKey).getParams()).getCurve().getField().getFieldSize();
        } else {
            return publicKey.getAlgorithm();
        }
    }

    /**
     * Formats the value of the unsigned tag.
     */
    static String formatTag(ASN1Encodable value) {
        if (value != null) {
            if (value instanceof ASN1UTF8String) {
                return ((ASN1UTF8String) value).getString();
            }

            if (value instanceof DEROctetString) {
                int limit = 100;
                byte[] bytes = ((DEROctetString) value).getOctets();
                return "(" + bytes.length + " bytes) " + new String(bytes).substring(0, limit) + (bytes.length > limit ? " ... (truncated)" : "");
            }
        }
        return null;
    }

    private void tag(File file) throws SignerException {
        if (!file.exists()) {
            throw new SignerException("Couldn't find " + file);
        }

        try (Signable signable = Signable.of(file)) {
            List<CMSSignedData> signatures = signable.getSignatures();
            if (signatures.isEmpty()) {
                throw new SignerException("No signature found in " + file);
            }

            log.info("Adding tag to " + file);
            signatures.set(0, SignatureUtils.addUnsignedAttribute(signatures.get(0), AuthenticodeObjectIdentifiers.JSIGN_UNSIGNED_DATA_OBJID, getTagValue()));
            signable.setSignatures(signatures);
            signable.save();
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException("Couldn't modify the signature of " + file, e);
        }
    }

    private ASN1Encodable getTagValue() throws IOException {
        if (value == null) {
            byte[] array = new byte[1024];
            String begin = "-----BEGIN TAG-----";
            System.arraycopy(begin.getBytes(), 0, array, 0, begin.length());
            String end = "-----END TAG-----";
            System.arraycopy(end.getBytes(), 0, array, array.length - end.length(), end.length());
            return new DEROctetString(array);

        } else if (value.startsWith("0x")) {
            byte[] array = Hex.decode(value.substring(2));
            return new DEROctetString(array);

        } else if (value.startsWith("file:")) {
            byte[] array = Files.readAllBytes(new File(value.substring("file:".length())).toPath());
            return new DEROctetString(array);

        } else {
            return new DERUTF8String(value);
        }
    }

    private void timestamp(File file) throws SignerException {
        if (!file.exists()) {
            throw new SignerException("Couldn't find " + file);
        }

        try {
            proxySettings.initializeProxy();
        } catch (Exception e) {
            throw new SignerException("Couldn't initialize proxy", e);
        }

        try (Signable signable = Signable.of(file)) {
            if (signable.getSignatures().isEmpty()) {
                throw new SignerException("No signature found in " + file);
            }

            Timestamper timestamper = Timestamper.create(tsmode != null ? TimestampingMode.of(tsmode) : TimestampingMode.AUTHENTICODE);
            timestamper.setRetries(tsretries);
            timestamper.setRetryWait(tsretrywait);
            if (tsaurl != null) {
                timestamper.setURLs(tsaurl.split(","));
            }
            DigestAlgorithm digestAlgorithm = alg != null ? DigestAlgorithm.of(alg) : DigestAlgorithm.getDefault();

            List<CMSSignedData> signatures = new ArrayList<>();
            for (CMSSignedData signature : signable.getSignatures()) {
                SignerInformation signerInformation = signature.getSignerInfos().iterator().next();
                SignerId signerId = signerInformation.getSID();
                X509CertificateHolder certificate = (X509CertificateHolder) signature.getCertificates().getMatches(signerId).iterator().next();

                String digestAlgorithmName = new DefaultAlgorithmNameFinder().getAlgorithmName(signerInformation.getDigestAlgorithmID()); 
                String keyAlgorithmName = new DefaultAlgorithmNameFinder().getAlgorithmName(new ASN1ObjectIdentifier(signerInformation.getEncryptionAlgOID()));
                String name = digestAlgorithmName + "/" + keyAlgorithmName + " signature from '" + certificate.getSubject() + "'";

                if (SignatureUtils.isTimestamped(signature) && !replace) {
                    log.fine(name + " already timestamped");
                    signatures.add(signature);
                    continue;
                }

                boolean expired = certificate.getNotAfter().before(new Date());
                if (expired) {
                    log.fine(name + " is expired, skipping");
                    signatures.add(signature);
                    continue;
                }

                log.info("Adding timestamp to " + name);
                signature = SignatureUtils.removeTimestamp(signature);
                signature = timestamper.timestamp(digestAlgorithm, signature);

                signatures.add(signature);
            }

            signable.setSignatures(signatures);
            signable.save();
        } catch (IOException | CMSException e) {
            throw new SignerException("Couldn't timestamp " + file, e);
        }
    }
}
