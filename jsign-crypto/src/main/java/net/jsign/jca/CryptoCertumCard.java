/*
 * Copyright 2025 Emmanuel Bourg
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

package net.jsign.jca;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Simple smart card interface for Certum cards (cryptoCertum 3.6 Common Profile).
 *
 * @since 7.4
 */
public class CryptoCertumCard extends SmartCard {

    /** AID of the eSign application with the Common profile */
    static final byte[] ESIGN_COMMON_PROFILE_AID = new byte[] { (byte) 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4F };

    /** AID of the eSign application with the Secure profile (eIDAS) */
    //static final byte[] ESIGN_SECURE_PROFILE_AID = new byte[] { (byte) 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E };

    private CryptoCertumCard(CardChannel channel) throws CardException {
        super(channel);
        select();
    }

    /**
     * Select the eSign application on the card.
     */
    private void select() throws CardException {
        select("Certum", ESIGN_COMMON_PROFILE_AID);
    }

    /**
     * Verify the PIN required for the protected operations.
     *
     * @param p1  0x00: verify, 0xFF: reset
     * @param p2  0x83: PIN, 0x84: PUK
     * @param pin the PIN
     */
    public void verify(int p1, int p2, String pin) throws CardException {
        if (pin == null) {
            pin = "";
        }
        byte[] mask = new byte[16]; // ASCII, zero-padded
        System.arraycopy(pin.getBytes(), 0, mask, 0, pin.length());
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x20, p1, p2, pin.isEmpty() ? null : mask)); // VERIFY
        handleError(response);
    }

    /**
     * Get a challenge from the card.
     *
     * @param length the length of the challenge in bytes (8 or 16)
     */
    public byte[] getChallenge(int length) throws CardException {
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x84, 0x00, 0x00, length)); // GET CHALLENGE
        handleError(response);
        return response.getData();
    }

    /**
     * Get a file from the card.
     *
     * Known FIDs:
     * <ul>
     *   <li>0x1021-0x102B: RSA Key #1-10</li>
     *   <li>0x1031-0x103B: EC Key #1-10</li>
     *   <li>0x2001-0x2015: Certificate #1-20</li>
     *   <li>0x5032: object directory</li>
     *   <li>0x5034: card info (factory id, serial number)</li>
     * </ul>
     *
     * @param fid the identifier of the file
     */
    public byte[] getFile(int fid) throws CardException {
        return getFile(fid, false);
    }

    /**
     * Get a file from the card.
     *
     * Known FIDs:
     * <ul>
     *   <li>0x1021-0x102B: RSA Key #1-10</li>
     *   <li>0x1031-0x103B: EC Key #1-10</li>
     *   <li>0x2001-0x2015: Certificate #1-20</li>
     *   <li>0x5032: object directory</li>
     *   <li>0x5034: card info (factory id, serial number)</li>
     * </ul>
     *
     * @param fid the identifier of the file
     * @param partial if true, return only the first 256 bytes of the file
     */
    public byte[] getFile(int fid, boolean partial) throws CardException {
        int cacheId = partial ? (fid | 0x80000000) : fid;
        if (dataObjectCache.containsKey(cacheId)) {
            return dataObjectCache.get(cacheId);
        }
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xA4, 0x02, 0x0C, new byte[]{(byte) ((fid & 0xFF00) >> 8), (byte) (fid & 0xFF)})); // SELECT FILE
        handleError(response);

        byte[] data = readBinary(partial);
        dataObjectCache.put(cacheId, data);
        return data;
    }

    private byte[] readBinary(boolean partial) throws CardException {
        int offset = 0;   // page
        int length = 256; // max length per page
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        while (true) {
            ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xB0, offset & 0xFF, (offset & 0xFF00) >> 8, length)); // READ BINARY
            handleError(response);
            byte[] data = response.getData();
            bout.write(data, 0, data.length);
            if (data.length < length || partial) {
                break;
            }
            offset++;
        }

        return bout.toByteArray();
    }

    /**
     * Return the public key data (modulus for RSA keys)
     *
     * @param keyref the reference of the key
     */
    public byte[] getKeyData(int keyref) throws CardException {
        byte[] template = {(byte) 0xB6, 0x03, (byte) 0x83, 0x01, (byte) keyref, 0x7F, 0x49, 0x02, (byte) 0x81, 0x00};

        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xCB, 0x00, 0xFF, template));
        handleError(response);

        TLV tlv = TLV.parse(ByteBuffer.wrap(response.getData()));

        return tlv.children().get(1).children().get(0).value();
    }

    /**
     * An entry on the card (key or certificate).
     */
    public abstract class Entry {
        /** Index of the object (1-10) */
        public int index;

        public abstract int fid();

        public byte[] data() throws CardException {
            return getFile(fid());
        }

        public String name() throws CardException {
            byte[] data = getFile(fid(), true);
            int length = data[2];
            return new String(data, 3, length, StandardCharsets.UTF_8);
        }
    }

    public class Key extends Entry {
        /** Type of key (0: RSA key, 1: EC key) */
        public int type;

        /** Key size in bits */
        public int size;

        public byte ref() {
            return (byte) ((type == 0 ? 0x20 : 0x30) + index);
        }

        public int fid() {
            return 0x1000 + ref();
        }
    }

    public class Certificate extends Entry {

        public int fid() {
            return 0x2000 + index;
        }

        public X509Certificate getCertificate() throws CardException {
            ByteBuffer buffer = ByteBuffer.wrap(data()).order(ByteOrder.BIG_ENDIAN);
            buffer.position(0x84);
            int length = buffer.getShort() & 0xFFFF;

            byte[] data = new byte[length];
            buffer.get(data);

            try {
                InputStream in = new ByteArrayInputStream(data);
                return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            } catch (CertificateException e) {
                throw new CardException("Invalid data for certificate #" + index, e);
            }
        }
    }

    /**
     * Return the list of keys and certificates available on the card.
     */
    public List<Entry> getEntries() throws CardException {
        byte[] data = getFile(0x5032);

        List<Entry> objects = new ArrayList<>();
        for (int i = 0x24; i < data.length - 2; i += 2) {
            int type = (data[i] & 0xF0) >> 4;
            int index = data[i] & 0x0F;

            Entry entry = null;
            if (index != 0) {
                if (type == 2) {
                    Certificate certificate = new Certificate();
                    certificate.index = index;
                    entry = certificate;

                } else {
                    Key key = new Key();
                    key.index = index;
                    key.type = type;

                    // Key Algorithm (0x40: certificate, 0x41: RSA 2048 or P256, 0x42: RSA 3072 or P384, 0x43: RSA 4096 or P521, 0x44: RSA 1024)
                    int algorithm = data[i + 1];
                    switch (type) {
                        case 0: // RSA
                            switch (algorithm) {
                                case 0x41: key.size = 2048; break;
                                case 0x42: key.size = 3072; break;
                                case 0x43: key.size = 4096; break;
                                case 0x44: key.size = 1024; break;
                            }
                            break;
                        case 1: // EC
                            switch (algorithm) {
                                case 0x41: key.size = 256; break;
                                case 0x42: key.size = 384; break;
                                case 0x43: key.size = 521; break;
                            }
                            break;
                    }

                    entry = key;
                }
            }

            if (entry != null) {
                objects.add(entry);
            }
        }

        return objects;
    }

    /**
     * Return the key with the specified name.
     */
    public Key getKey(String name) throws CardException {
        for (Entry entry : getEntries()) {
            if (entry instanceof Key && entry.name().equals(name)) {
                return (Key) entry;
            }
        }
        return null;
    }

    /**
     * Return the certificate with the specified name.
     */
    public Certificate getCertificate(String name) throws CardException {
        for (Entry entry : getEntries()) {
            if (entry instanceof Certificate && entry.name().equals(name)) {
                return (Certificate) entry;
            }
        }
        return null;
    }

    /**
     * Return the name of the keys available on the card.
     */
    public List<String> aliases() throws CardException {
        List<String> aliases = new ArrayList<>();
        for (Entry entry : getEntries()) {
            if (entry instanceof Key) {
                aliases.add(entry.name());
            }
        }
        return aliases;
    }

    /**
     * Sign the specified hash with the specified key.
     *
     * @param key  the key to use for signing
     * @param hash the hash to sign
     */
    public byte[] sign(Key key, byte[] hash) throws CardException {
        if (pin != null) {
            verify(0x00, 0x83, pin);
        }

        manageSecurityEnvironment(key);
        hash(hash);
        return computeDigitalSignature();
    }

    /**
     * Assign the specified key to the COMPUTE DIGITAL SIGNATURE operation
     *
     * @param key the key
     */
    private void manageSecurityEnvironment(Key key) throws CardException {
        byte[] template = new byte[] {(byte) 0x80, 0x01, (byte) (key.type == 0 ? 0x42 : 0x44), (byte) 0x84, 0x01, key.ref()};

        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x22, 0x81, 0xB6, template)); // MANAGE SECURITY ENVIRONMENT
        handleError(response);
    }

    /**
     * Set the hash of the data to sign
     */
    private void hash(byte[] hash) throws CardException {
        TLV template = new TLV("90", hash);

        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x2A, 0x90, 0xA0, template.getEncoded())); // HASH
        handleError(response);
    }

    /**
     * Sign the specified data.
     */
    private byte[] computeDigitalSignature() throws CardException {
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, 0x80)); // COMPUTE DIGITAL SIGNATURE
        if (response.getSW() == 0x6a88) {
            throw new CardException("Signature key not found");
        }
        handleError(response);
        return response.getData();
    }

    /**
     * Get the CryptoCertum card.
     */
    public static CryptoCertumCard getCard() throws CardException {
        CardChannel channel = openChannel(ESIGN_COMMON_PROFILE_AID);
        return channel != null ? new CryptoCertumCard(channel) : null;
    }
}
