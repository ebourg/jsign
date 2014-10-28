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
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;

/**
* @author Florent Daigniere
* @since 1.3
*/
public enum HashAlgo {
    SHA1("SHA-1", TSPAlgorithms.SHA1),
    SHA256("SHA-256", TSPAlgorithms.SHA256);

    public final String id;
    public final ASN1ObjectIdentifier oid;

    HashAlgo(String id, ASN1ObjectIdentifier oid) {
        this.id = id;
        this.oid = oid;
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
    public static HashAlgo getDefault() {
        TimeZone tz = TimeZone.getTimeZone("GMT");
        Calendar now = Calendar.getInstance(tz);
        Calendar cutoff = Calendar.getInstance(tz);
        cutoff.set(2016, Calendar.JANUARY, 1);
        return (now.before(cutoff) ? SHA1 : SHA256);
    }
}
