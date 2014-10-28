/**
 * Copyright 2014 Florent Daigniere
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

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;

/**
 * Digest algorithm.
 * 
* @author Florent Daigniere
* @since 1.3
*/
public enum DigestAlgorithm {
    SHA1("SHA-1", TSPAlgorithms.SHA1),
    SHA256("SHA-256", TSPAlgorithms.SHA256);

    public final String id;
    public final ASN1ObjectIdentifier oid;

    private DigestAlgorithm(String id, ASN1ObjectIdentifier oid) {
        this.id = id;
        this.oid = oid;
    }

    public static DigestAlgorithm asMyEnum(String str) {
        if (str == null)
            return null;
        for (DigestAlgorithm me : DigestAlgorithm.values())
            if(me.name().equals(str))
                return me;
        return null;
    }

    /**
     * Return the default algorithm depending on the current date (SHA-1 until
     * January 1 2016 and SHA-256 afterward). SHA-1 is used as long as possible
     * to preserve the compatibility with older versions of Windows.
     * 
     * @see <a href="http://social.technet.microsoft.com/wiki/contents/articles/1760.windows-root-certificate-program-technical-requirements-version-2-0.aspx">Windows Root Certificate Program - Technical Requirements version 2.0</a>
     * @see <a href="http://blogs.technet.com/b/pki/archive/2011/02/08/common-questions-about-sha2-and-windows.aspx">Common Questions about SHA2 and Windows</a>
     */
    public static DigestAlgorithm getDefault() {
        Calendar cutoff = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        cutoff.set(2016, Calendar.JANUARY, 1, 0, 0, 0);
        return (new Date().before(cutoff.getTime()) ? SHA1 : SHA256);
    }
}
