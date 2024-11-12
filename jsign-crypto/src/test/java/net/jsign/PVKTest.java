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

import java.io.File;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import static org.junit.Assert.*;

public class PVKTest {

    private static final BigInteger PRIVATE_EXPONENT =
            new BigInteger("19817169968742658351655981881520728567515742675458028238722873450752489545290027368716540" +
                           "85097631066624963034561175250684606477209898571693535966680219017373301210696301524715693" +
                           "32813430171550590717633111906205004670354975513186220085378522264569873656534297526647600" +
                           "67210063630643422050150940116280163778449179706229972233451580723669324903567379792001184" +
                           "91356375507388894454096016139651604806035749246665341527152435463187733601651656903848705" +
                           "65286430323121648102905511694715343290174710008776316150944558295836976757991350461460249" +
                           "74312281235327661476877170425283316600383477434537031658944220883861196634055190385");

    private static final BigInteger MODULUS =
            new BigInteger("21026727350227266993580359812994381921240779505585390203202048947528063647735401163462300" +
                           "86859381987362186967086563090389966401102613413199269296684661935039649674509098920544828" +
                           "04160697025157625655471712322064490603089902864113285504160024182057017660373472193953143" +
                           "34915827871864878509572136616650526875973283568659516641764756350187822313708568281541241" +
                           "25894972756560367055415648944079653776940135747175611707440205148780641189836753755730849" +
                           "75361800377220985613778039805484004477512603469900215280058609596725867024141000565592363" +
                           "54073693540785721987884073701191374782240076396034877799330433856497845306219279631");

    @Test
    public void testParseUnencrypted() throws Exception {
        testParse("target/test-classes/keystores/privatekey.pvk");
    }

    @Test
    public void testParseEncryptedWeak() throws Exception {
        testParse("target/test-classes/keystores/privatekey-encrypted.pvk");
    }

    @Test
    public void testParseEncryptedStrong() throws Exception {
        testParse("target/test-classes/keystores/privatekey-encrypted-strong.pvk");
    }

    private void testParse(String filename) throws Exception {
        PrivateKey key = PVK.parse(new File(filename), "password");
        assertNotNull("private key", key);
        
        RSAPrivateKey rsakey = (RSAPrivateKey) key;
        assertEquals("private exponent", PRIVATE_EXPONENT, rsakey.getPrivateExponent());
        assertEquals("modulus", MODULUS, rsakey.getModulus());
    }

    @Test
    public void testCompare() throws Exception {
        PrivateKey key1 = PVK.parse(new File("target/test-classes/keystores/privatekey.pvk"), "password");
        PrivateKey key2 = PVK.parse(new File("target/test-classes/keystores/privatekey-encrypted.pvk"), "password");
        
        assertEquals("private key", key1, key2);
    }

    @Test
    public void testInvalidFile() {
        assertThrows(IllegalArgumentException.class, () -> PVK.parse(new File("target/test-classes/keystores/keystore.jks"), null));
    }

    @Test
    public void testInvalidPassword() {
        Exception e = assertThrows(IllegalArgumentException.class,
                () -> PVK.parse(new File("target/test-classes/keystores/privatekey-encrypted.pvk"), "secret"));
        assertEquals("message", "Unable to decrypt the PVK key, please verify the password", e.getMessage());
    }

    @Test
    public void testMissingPassword() {
        Exception e = assertThrows(IllegalArgumentException.class,
                () -> PVK.parse(new File("target/test-classes/keystores/privatekey-encrypted.pvk"), null));
        assertEquals("message", "Unable to decrypt the PVK key, please verify the password", e.getMessage());
    }

    @Test
    public void testInvalidKeyFormat() throws Exception {
        File original = new File("target/test-classes/keystores/privatekey.pvk");
        File modified = new File("target/test-classes/keystores/privatekey-invalid.pvk");
        FileUtils.copyFile(original, modified);

        // modify the type of the RSA key
        FileChannel channel = FileChannel.open(modified.toPath(), StandardOpenOption.WRITE);
        channel.position(0x20);
        channel.write(ByteBuffer.wrap("RSA3".getBytes()));
        channel.close();

        Exception e = assertThrows(IllegalArgumentException.class, () -> PVK.parse(modified, null));
        assertEquals("message", "Unable to parse the PVK key, unsupported key format: RSA3", e.getMessage());
    }
}
