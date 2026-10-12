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

import net.jsign.pe.PEFile;

import static net.jsign.verify.CheckResult.Status.*;

/**
 * Verification rule checking that the PE certificate table doesn't hold extra data after the signature.
 * The Authenticode digest excludes the whole certificate table region declared by the data directory, so
 * any trailing bytes there aren't covered by the signature and could be used to smuggle content into a
 * validly signed file (CVE-2013-3900). Windows rejects such files.
 *
 * @since 8.0
 */
class CertificateTableRule extends VerificationRule {

    @Override
    public CheckResult check(VerificationContext context) throws IOException {
        if (!(context.getSignable() instanceof PEFile)) {
            return new CheckResult(getName(), SKIPPED, "The file has no certificate table");
        }

        long trailing = ((PEFile) context.getSignable()).getCertificateTableTrailingBytes();
        if (trailing > 0) {
            return new CheckResult(getName(), FAILED, "The certificate table contains " + trailing + " extra bytes after the signature");
        }

        return new CheckResult(getName(), PASSED, "The certificate table doesn't contain extra data");
    }
}
