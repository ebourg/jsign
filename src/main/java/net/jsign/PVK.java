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
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * PVK file parser. Based on the documentation and the code from Stephen N Henson.
 * 
 * @see <a href="http://www.drh-consultancy.demon.co.uk/pvk.html">PVK file information</a>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PVK {

    /** Header signature of PVK files */
    private static final long PVK_MAGIC = 0xB0B5F11EL;

    private PVK() {
    }

    public static PrivateKey parse(File file, String password) throws GeneralSecurityException, IOException {
        ByteBuffer buffer = ByteBuffer.allocate((int) file.length());
        
        FileInputStream in = new FileInputStream(file);
        try {
            in.getChannel().read(buffer);
            return parse(buffer, password);
        } finally {
            in.close();
        }
    }

    public static PrivateKey parse(ByteBuffer buffer, String password) throws GeneralSecurityException {
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.rewind();
        
        long magic = buffer.getInt() & 0xFFFFFFFFL;
        if (PVK_MAGIC != magic) {
            throw new IllegalArgumentException("PVK header signature not found");
        }
        
        int res = buffer.getInt();
        int keyType = buffer.getInt();
        int encrypted = buffer.getInt();
        int saltLength = buffer.getInt();
        int keyLength = buffer.getInt();
        byte[] salt = new byte[saltLength];
        buffer.get(salt);
        
        byte btype = buffer.get();
        byte version = buffer.get();
        short reserved = buffer.getShort();
        int keyalg = buffer.getInt();
        
        byte[] key = new byte[keyLength - 8];
        buffer.get(key);
        
        if (encrypted == 0) {
            return parseKey(key);
        } else {
            try {
                // strong key (128 bits)
                return parseKey(decrypt(key, salt, password, false));
            } catch (IllegalArgumentException e) {
                // weak key (40 bits)
                return parseKey(decrypt(key, salt, password, true));
            }
        }
    }

    private static byte[] decrypt(byte[] encoded, byte[] salt, String password, boolean weak) throws GeneralSecurityException {
        // key derivation SHA1(salt + password)
        MessageDigest digest = MessageDigest.getInstance("SHA1");
        digest.update(salt);
        digest.update(password.getBytes());
        byte[] hash = digest.digest();
        if (weak) {
            // trim the key to 40 bits
            Arrays.fill(hash, 5, hash.length, (byte) 0);
        }
        
        // decryption
        Cipher rc4 = Cipher.getInstance("RC4");
        rc4.init(Cipher.DECRYPT_MODE, new SecretKeySpec(hash, 0, 16, "RC4"));
        return rc4.doFinal(encoded);
    }

    private static PrivateKey parseKey(byte[] key) throws GeneralSecurityException {
        ByteBuffer buffer = ByteBuffer.wrap(key);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        
        byte[] keymagic = new byte[4];
        buffer.get(keymagic);
        
        if (!"RSA2".equals(new String(keymagic))) {
            throw new IllegalArgumentException("Unsupported key format: " + new String(keymagic));
        }
        
        int bitlength = buffer.getInt();
        BigInteger publicExponent = new BigInteger(String.valueOf(buffer.getInt()));
        
        int l = bitlength / 8;
        
        BigInteger modulus = getBigInteger(buffer, l);
        BigInteger primeP = getBigInteger(buffer, l / 2);
        BigInteger primeQ = getBigInteger(buffer, l / 2);
        BigInteger primeExponentP = getBigInteger(buffer, l / 2);
        BigInteger primeExponentQ = getBigInteger(buffer, l / 2);
        BigInteger crtCoefficient = getBigInteger(buffer, l / 2);
        BigInteger privateExponent = getBigInteger(buffer, l);
        
        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        
        return factory.generatePrivate(spec);
    }

    private static BigInteger getBigInteger(ByteBuffer buffer, int length) {
        byte[] array = new byte[length];
        buffer.get(array);        
        
        // reverse the array and prepend a zero
        byte[] bigintBytes = new byte[length + 1];
        for (int i = 0; i < array.length; i++) {
            bigintBytes[i + 1] = array[array.length - 1 - i];
        }
        
        return new BigInteger(bigintBytes);
    }
}
