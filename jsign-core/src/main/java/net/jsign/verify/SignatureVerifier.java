/*
 * Copyright 2026 Emmanuel Bourg
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

package net.jsign.verify;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Selector;

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.cat.CatalogFile;
import net.jsign.pe.PEFile;

import static net.jsign.verify.CheckResult.Status.*;

/**
 * Authenticode signature verifier.
 *
 * @since 8.0
 */
public class SignatureVerifier {

    private boolean lazy;
    private Date date;

    /** The list of trusted certificates */
    private final List<X509Certificate> trustedCertificates = new ArrayList<>();

    /**
     * Tells if the verification is halted when an issue is found.
     */
    public void setLazy(boolean lazy) {
        this.lazy = lazy;
    }

    /**
     * Sets the date of the verification (will be overridden by a valid timestamp if present).
     */
    public void setDate(Date date) {
        this.date = date;
    }

    /**
     * Adds a trusted certificate.
     */
    public void addTrustedCertificate(X509Certificate certificate) {
        trustedCertificates.add(certificate);
    }

    /**
     * Verifies the signatures of a signable file.
     */
    public VerificationResult verify(Signable signable) throws IOException {
        List<CMSSignedData> signatures = signable.getSignatures();
        if (signatures.isEmpty()) {
            return new VerificationResult();
        }

        Date now = date != null ? date : new Date();

        Map<DigestAlgorithm, byte[]> digestCache = new HashMap<>();

        VerificationResult result = new VerificationResult();
        for (CMSSignedData signature : signatures) {
            if (signature.getSignerInfos().getSigners().isEmpty()) {
                result.getSignatureVerifications().add(new VerificationResult.SignatureVerification(new CheckResult("SignatureData", FAILED, "No signer found", null)));
                continue;
            }
            
            SignerInformation signer = signature.getSignerInfos().iterator().next();
            
            Selector<X509CertificateHolder> selector = signer.getSID();
            Collection<X509CertificateHolder> certs = signature.getCertificates().getMatches(selector);
            if (certs.isEmpty()) {
                result.getSignatureVerifications().add(new VerificationResult.SignatureVerification(new CheckResult("SignatureData", FAILED, "No certificate found for signer " + signer.getSID(), null)));
                continue;
            }

            X509Certificate certificate;
            try {
                certificate = new JcaX509CertificateConverter().getCertificate(certs.iterator().next());
            } catch (CertificateException e) {
                throw new IOException(e);
            }

            DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(signer.getDigestAlgorithmID().getAlgorithm());
            if (digestAlgorithm == null) {
                result.getSignatureVerifications().add(new VerificationResult.SignatureVerification(new CheckResult("SignatureData", FAILED, "Unsupported digest algorithm: " + signer.getDigestAlgorithmID().getAlgorithm(), null)));
                continue;
            }

            VerificationContext context = new VerificationContext(signable, digestCache, signature, signer, certificate);
            context.setDate(now);

            List<VerificationRule> rules = new ArrayList<>();
            if (!(signable instanceof CatalogFile)) {
                rules.add(new FileIntegrityRule());
            }
            rules.add(new TimestampRule());
            rules.add(new CertificateChainTrustRule().withTrustedCertificates(trustedCertificates));
            rules.add(new SignatureIntegrityRule());
            if (signable instanceof PEFile) {
                rules.add(new CertificateTableRule());
            }

            List<CheckResult> checks = new ArrayList<>();
            for (VerificationRule rule : rules) {
                CheckResult check = rule.check(context);
                checks.add(check);
                if (check.getStatus() == FAILED && lazy) {
                    break;
                }
            }

            result.getSignatureVerifications().add(new VerificationResult.SignatureVerification(certificate, digestAlgorithm, checks));
        }

        return result;
    }
}
