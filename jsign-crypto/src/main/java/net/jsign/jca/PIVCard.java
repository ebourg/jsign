/*
 * Copyright 2024 Emmanuel Bourg
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
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.zip.GZIPInputStream;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Simple smart card interface for PIV cards.
 *
 * @see <a href="https://csrc.nist.gov/pubs/sp/800/73/4/upd1/final">NIST SP 800-73-4 Interfaces for Personal Identity Verification</a>
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-5.ipd.pdf">NIST SP 800-78-5 Cryptographic Algorithms and Key Sizes for Personal Identity Verification</a>
 * @see <a href="https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html">Yubikey User's Manual - PIV commands</a>
 * @since 6.0
 */
class PIVCard extends SmartCard {

    public enum Key {
        AUTHENTICATION(0x9A, 0x5FC105, "X.509 Certificate for PIV Authentication"),
        SIGNATURE(0x9C, 0x5FC10A, "X.509 Certificate for Digital Signature"),
        KEY_MANAGEMENT(0x9D, 0x5FC10B, "X.509 Certificate for Key Management"),
        CARD_AUTHENTICATION(0x9E, 0x5FC101, "X.509 Certificate for Card Authentication"),
        RETIRED1(0x82, 0x5FC10D, "X.509 Certificate for Retired Key 1"),
        RETIRED2(0x83, 0x5FC10E, "X.509 Certificate for Retired Key 2"),
        RETIRED3(0x84, 0x5FC10F, "X.509 Certificate for Retired Key 3"),
        RETIRED4(0x85, 0x5FC110, "X.509 Certificate for Retired Key 4"),
        RETIRED5(0x86, 0x5FC111, "X.509 Certificate for Retired Key 5"),
        RETIRED6(0x87, 0x5FC112, "X.509 Certificate for Retired Key 6"),
        RETIRED7(0x88, 0x5FC113, "X.509 Certificate for Retired Key 7"),
        RETIRED8(0x89, 0x5FC114, "X.509 Certificate for Retired Key 8"),
        RETIRED9(0x8A, 0x5FC115, "X.509 Certificate for Retired Key 9"),
        RETIRED10(0x8B, 0x5FC116, "X.509 Certificate for Retired Key 10"),
        RETIRED11(0x8C, 0x5FC117, "X.509 Certificate for Retired Key 11"),
        RETIRED12(0x8D, 0x5FC118, "X.509 Certificate for Retired Key 12"),
        RETIRED13(0x8E, 0x5FC119, "X.509 Certificate for Retired Key 13"),
        RETIRED14(0x8F, 0x5FC11A, "X.509 Certificate for Retired Key 14"),
        RETIRED15(0x90, 0x5FC11B, "X.509 Certificate for Retired Key 15"),
        RETIRED16(0x91, 0x5FC11C, "X.509 Certificate for Retired Key 16"),
        RETIRED17(0x92, 0x5FC11D, "X.509 Certificate for Retired Key 17"),
        RETIRED18(0x93, 0x5FC11E, "X.509 Certificate for Retired Key 18"),
        RETIRED19(0x94, 0x5FC11F, "X.509 Certificate for Retired Key 19"),
        RETIRED20(0x95, 0x5FC120, "X.509 Certificate for Retired Key 20");

        Key(int slot, int tag, String alias) {
            this.slot = slot;
            this.tag = tag;
            this.alias = alias;
        }

        final int slot;
        final int tag;
        final String alias;

        /**
         * Return the key for the specified name or slot.
         *
         * @param name The name, the alias or the slot of the key
         * @return the key or null if not found
         */
        public static Key of(String name) {
            if (name == null) {
                return null;
            }

            if (name.length() == 2) {
                int slot = Integer.parseInt(name, 16);
                for (Key key : values()) {
                    if (key.slot == slot) {
                        return key;
                    }
                }
            } else {
                for (Key key : values()) {
                    if (key.name().equalsIgnoreCase(name) || key.alias.equalsIgnoreCase(name)) {
                        return key;
                    }
                }
            }

            return null;
        }
    }

    public static class KeyInfo {
        public String algorithm;

        /**
         * The PIV algorithm identifier.
         *
         * <ul>
         *   <li>0x06: RSA-1024</li>
         *   <li>0x07: RSA-2048</li>
         *   <li>0x05: RSA-3072</li>
         *   <li>0x16: RSA-4096</li>
         *   <li>0x11: ECC-P256</li>
         *   <li>0x14: ECC-P384</li>
         * </ul>
         */
        public int algorithmId;

        /** Key size in bits */
        public int size;
    }

    private PIVCard(CardChannel channel) throws CardException {
        super(channel);
        select();
    }

    /**
     * Select the PIV application on the card.
     */
    private void select() throws CardException {
        select("PIV", new byte[] { (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00 });
    }

    /**
     * Verify the PIN required for the protected operations.
     *
     * @param p1  0x00: verify, 0xFF: reset
     * @param p2  0x80: PIN
     * @param pin the PIN
     */
    public void verify(int p1, int p2, String pin) throws CardException {
        if (pin == null) {
            pin = "";
        }
        byte[] mask = new byte[8];
        Arrays.fill(mask, (byte) 0xFF);
        System.arraycopy(pin.getBytes(), 0, mask, 0, pin.length());
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x20, p1, p2, mask)); // VERIFY
        handleError(response);
    }

    /**
     * Read a data object from the card.
     */
    public byte[] getData(int tag) throws CardException {
        if (dataObjectCache.containsKey(tag)) {
            return dataObjectCache.get(tag);
        }
        byte[] data;
        if (tag < 0x100) {
            data = new byte[] { 0x5C, 0x01, (byte) (tag & 0xFF) };
        } else if (tag < 0x10000) {
            data = new byte[] { 0x5C, 0x02, (byte) ((tag & 0xFF00) >> 8), (byte) (tag & 0xFF) };
        } else if (tag < 0x1000000) {
            data = new byte[] { 0x5C, 0x03, (byte) ((tag & 0xFF0000) >> 16), (byte) ((tag & 0xFF00) >> 8), (byte) (tag & 0xFF) };
        } else {
            throw new CardException("Invalid tag 0x" + Integer.toHexString(tag).toUpperCase());
        }
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, data)); // GET DATA
        if (response.getSW() == 0x6A88) {
            throw new CardException("Data object 0x" + Integer.toHexString(tag).toUpperCase() + " not found");
        }
        handleError(response);
        dataObjectCache.put(tag, response.getData());
        return response.getData();
    }

    /**
     * Return the version of the firmware.
     */
    public String getVersion() throws CardException {
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xFD, 0x00, 0x00));
        handleError(response);
        byte[] version = response.getData();
        int major = version[0];
        int minor = version[1];
        int patch = version[2];
        return major + "." + minor + "." + patch;
    }

    /**
     * Return the available keys.
     */
    public Set<Key> getAvailableKeys() throws CardException {
        Set<Key> keys = new LinkedHashSet<>();

        for (Key key : Key.values()) {
            if (getCertificate(key) != null) {
                keys.add(key);
            }
        }

        return keys;
    }

    /**
     * Return the certificate for the specified key.
     */
    public Certificate getCertificate(Key key) throws CardException {
        byte[] data;
        try {
            data = getData(key.tag);
        } catch (CardException e) {
            if ("Incorrect P1 or P2 parameter".equals(e.getMessage())) {
                return null;
            } else {
                throw e;
            }
        }

        // parse the encoded certificate
        // (see https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#encoded-certificate)
        TLV tlv = TLV.parse(ByteBuffer.wrap(data));
        tlv = TLV.parse(ByteBuffer.wrap(tlv.value()), false);

        boolean compressed = false;
        TLV compressionField = tlv.find("71");
        if (compressionField != null) {
            compressed = compressionField.value()[0] == 1;
        }

        try {
            TLV certificateField = tlv.find("70");
            InputStream in = new ByteArrayInputStream(certificateField.value());
            if (compressed) {
                in = new GZIPInputStream(in);
            }
            return CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException | CertificateException e) {
            throw new CardException("Invalid certificate for " + key.name() + " key", e);
        }
    }

    /**
     * Return the key information for the specified key.
     */
    public KeyInfo getKeyInfo(Key key) throws CardException {
        Certificate certificate = getCertificate(key);
        // todo read the metadata if the certificate is missing
        if (certificate == null) {
            throw new CardException(key.name() + " key not found");
        }

        PublicKey publicKey = certificate.getPublicKey();

        KeyInfo info = new KeyInfo();
        info.algorithm = publicKey.getAlgorithm();
        if ("RSA".equals(info.algorithm)) {
            info.size = ((RSAKey) publicKey).getModulus().bitLength();
        } else if ("EC".equals(info.algorithm)) {
            ECParameterSpec spec = ((ECKey) publicKey).getParams();
            if (spec != null) {
                info.size = spec.getOrder().bitLength();
            }
        }
        info.algorithmId = getAlgorithmId(info.algorithm, info.size);

        return info;
    }

    private int getAlgorithmId(String algorithm, int size) {
        if ("RSA".equals(algorithm)) {
            switch (size) {
                case 1024:
                    return 0x06;
                case 2048:
                    return 0x07;
                case 3072:
                    return 0x05;
                case 4096:
                    return 0x16;
            }
        } else if ("EC".equals(algorithm)) {
            switch (size) {
                case 256:
                    return 0x11;
                case 384:
                    return 0x14;
            }
        }

        throw new IllegalArgumentException("Unsupported algorithm " + algorithm + " with key size " + size);
    }

    /**
     * Sign the specified data.
     *
     * @param key  the key to use for the signature
     * @param data the data to sign (the encoded DigestInfo structure for RSA, or the hash for ECDSA)
     */
    public byte[] sign(Key key, byte[] data) throws CardException {
        KeyInfo info = getKeyInfo(key);
        if ("RSA".equalsIgnoreCase(info.algorithm)) {
            data = rsaPadding(data, info.size);
        }

        if (pin != null) {
            verify(0, 0x80, pin);
        }

        // Dynamic Authentication Template
        TLV template = new TLV("7C");
        template.children().add(new TLV("82", new byte[0])); // Response
        template.children().add(new TLV("81", data)); // Challlenge

        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x87, info.algorithmId, key.slot, template.getEncoded())); // GENERAL AUTHENTICATE
        handleError(response);

        TLV tlv = TLV.parse(ByteBuffer.wrap(response.getData()), true);
        return tlv.find("82").value();
    }

    /**
     * PKCS #1 v1.5 padding.
     */
    private byte[] rsaPadding(byte[] message, int keyLength) {
        byte[] padded = new byte[keyLength / 8];
        Arrays.fill(padded, (byte) 0xFF);
        padded[0] = 0x00;
        padded[1] = 0x01;
        System.arraycopy(message, 0, padded, padded.length - message.length, message.length);
        padded[padded.length - message.length - 1] = 0;
        return padded;
    }

    /**
     * Get the PIV card.
     */
    public static PIVCard getCard() throws CardException {
        return getCard(null);
    }

    /**
     * Get the PIV card with the specified name.
     *
     * @param name the partial name of the card
     */
    public static PIVCard getCard(String name) throws CardException {
        CardChannel channel = openChannel(name);
        return channel != null ? new PIVCard(channel) : null;
    }
}
