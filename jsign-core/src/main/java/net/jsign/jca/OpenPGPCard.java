/**
 * Copyright 2023 Emmanuel Bourg
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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.apache.commons.io.HexDump;

/**
 * Simple smart card interface for OpenPGP cards.
 *
 * @see <a href="https://www.gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf">Functional Specification of the OpenPGP application on ISO Smart Card Operating Systems</a>
 * @since 4.3
 */
class OpenPGPCard {

    private final CardChannel channel;

    private String pin;

    /** Data Object cache */
    private final Map<Integer, byte[]> dataObjectCache = new HashMap<>();

    /** The extended capabilities flag list */
    private byte[] extendedCapabilities;

    /** Information about the keys */
    private KeyInfo[] keyInfos;

    private boolean debug;

    public enum Key {
        SIGNATURE, ENCRYPTION, AUTHENTICATION;
    }

    public static class KeyInfo {
        public byte[] fingerprint;
        public int algorithm;
        public int size;

        public boolean isRSA() {
            return algorithm == 1 || algorithm == 2 || algorithm == 3;
        }

        public boolean isEC() {
            return algorithm == 18 || algorithm == 19;
        }

        public boolean isPresent() {
            return !Arrays.equals(fingerprint, new byte[20]);
        }
    }

    private OpenPGPCard(CardChannel channel) throws CardException {
        this.channel = channel;
        select();
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    private void handleError(ResponseAPDU response) throws CardException {
        switch (response.getSW()) {
            case 0x9000:
                return;
            case 0x63C0:
            case 0x63C1:
            case 0x63C2:
            case 0x63C3:
                throw new CardException("PIN verification failed, " + (response.getSW() & 0x0F) + " tries left");
            case 0x6700:
                throw new CardException("Wrong length");
            case 0x6982:
                throw new CardException("PIN verification required");
            case 0x6A80:
                throw new CardException("The parameters in the data field are incorrect");
            case 0x6A82:
                throw new CardException("Incorrect P1 or P2 parameter");
            case 0x6D00:
                throw new CardException("Instruction code not supported or invalid");
            default:
                throw new CardException("Error " + Integer.toHexString(response.getSW()));
        }
    }

    /**
     * Select the OpenPGP application on the card.
     */
    private void select() throws CardException {
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, new byte[] { (byte) 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 })); // SELECT
        switch (response.getSW()) {
            case 0x6A82:
            case 0x6A86:
                throw new CardException("OpenPGP application not found on the card/token");
        }
        handleError(response);
    }

    /**
     * Set the PIN for the verify operation.
     */
    public void verify(String pin) {
        this.pin = pin;
    }

    /**
     * Verify the PIN required for the protected operations.
     *
     * @param p1  0x00: verify, 0xFF: reset
     * @param p2  0x81: PW1 (PSO:CDS), 0x82: PW1, 0x83: PW3 (PSO:DECIPHER)
     * @param pin the PIN
     */
    public void verify(int p1, int p2, String pin) throws CardException {
        if (pin == null) {
            pin = "";
        }
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x20, p1, p2, p1 == 0 ? pin.getBytes() : new byte[0])); // VERIFY
        handleError(response);
    }

    /**
     * Select the n-th occurence of a data object.
     *
     * @param tag   the tag of the data object (only 0x7F21 is supported)
     * @param index the index of the data object (0-based)
     */
    public void selectData(int tag, int index) throws CardException {
        byte[] data = new byte[] { 0x60, 0x04, 0x5C, 0x02, (byte) ((tag & 0xFF00) >> 8), (byte) (tag & 0xFF) };
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xA5, index, 0x04, data)); // SELECT DATA
        handleError(response);
    }

    /**
     * Read a data object from the card.
     */
    public byte[] getData(int tag) throws CardException {
        if (dataObjectCache.containsKey(tag)) {
            return dataObjectCache.get(tag);
        }
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xCA, (tag & 0xFF00) >> 8, tag & 0xFF, 0x10000)); // GET DATA
        if (response.getSW() == 0x6A88) {
            throw new CardException("Data object 0x" + Integer.toHexString(tag).toUpperCase() + " not found");
        }
        handleError(response);
        if (tag != 0x7F21) {
            dataObjectCache.put(tag, response.getData());
        }
        return response.getData();
    }

    /**
     * Return the application identifier.
     */
    public byte[] getAID() throws CardException {
        return getData(0x4F);
    }

    /**
     * Return the version of the OpenPGP specification implemented by the card.
     */
    public float getVersion() throws CardException {
        byte[] aid = getAID();
        int major = aid[6];
        int minor = aid[7];
        return major + minor / 10f;
    }

    /**
     * Return the keys available for signing.
     */
    public Set<Key> getAvailableKeys() throws CardException {
        Set<Key> keys = new LinkedHashSet<>();

        for (Key key : Key.values()) {
            if (getKeyInfo(key).isPresent() && (key != Key.ENCRYPTION || supportsManageSecurityEnvironment())) {
                keys.add(key);
            }
        }

        return keys;
    }

    /**
     * Return the certificate for the specified key.
     */
    public byte[] getCertificate(Key key) throws CardException {
        if (key == Key.AUTHENTICATION) {
            return getData(0x7F21);
        }

        if (getVersion() < 3) {
            return new byte[0];
        }

        int position = 0;
        if (key == Key.ENCRYPTION) {
            position = 1;
        } else if (key == Key.SIGNATURE) {
            position = 2;
        }
        selectData(0x7F21, position);
        return getData(0x7F21);
    }

    /**
     * Return the key information for the specified key.
     */
    public KeyInfo getKeyInfo(Key key) throws CardException {
        if (keyInfos == null) {
            this.keyInfos = getKeyInfo();
        }
        return keyInfos[key.ordinal()];
    }

    private KeyInfo[] getKeyInfo() throws CardException {
        KeyInfo[] keyInfos = new KeyInfo[3];
        keyInfos[0] = new KeyInfo();
        keyInfos[1] = new KeyInfo();
        keyInfos[2] = new KeyInfo();

        TLV relatedData = TLV.parse(ByteBuffer.wrap(getData(0x6E)));

        // read the fingerprints
        TLV fingerprints = relatedData.find("73", "C5");
        if (fingerprints != null) {
            byte[] data = fingerprints.value();
            for (Key key : Key.values()) {
                byte[] fingerprint = new byte[20];
                System.arraycopy(data, 20 * key.ordinal(), fingerprint, 0, 20);
                keyInfos[key.ordinal()].fingerprint = fingerprint;
            }
        }

        // read the algorithm attributes
        for (Key key : Key.values()) {
            TLV algorithmAttributes = relatedData.find("73", "C" + (key.ordinal() + 1));
            ByteBuffer buffer = ByteBuffer.wrap(algorithmAttributes.value());
            keyInfos[key.ordinal()].algorithm = buffer.get();
            if (keyInfos[key.ordinal()].isRSA()) {
                keyInfos[key.ordinal()].size = buffer.getShort() & 0xFFFF;
            }
        }

        extendedCapabilities = relatedData.find("73", "C0").value();

        return keyInfos;
    }

    /**
     * Return the extended capabilities.
     */
    private byte[] getExtendedCapabilities() throws CardException {
        if (extendedCapabilities == null) {
            TLV relatedData = TLV.parse(ByteBuffer.wrap(getData(0x6E)));
            System.out.println(relatedData);
            extendedCapabilities = relatedData.find("73", "C0").value();
        }
        return extendedCapabilities;
    }

    /**
     * Tell if the MANAGE SECURITY ENVIRONMENT command is supported.
     */
    protected boolean supportsManageSecurityEnvironment() throws CardException {
        return getVersion() > 3 && (getExtendedCapabilities()[9] & 0x01) != 0;
    }

    /**
     * Put the specified data object on the card.
     */
    public void putData(int tag, byte[] data) throws CardException {
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0xDA, (tag & 0xFF00) >> 8, tag & 0xFF, data)); // PUT DATA
        handleError(response);

        // clear the cache
        dataObjectCache.clear();
    }

    /**
     * Sign the specified data.
     *
     * @param key  the key to use for the signature
     * @param data the data to sign
     */
    public byte[] sign(Key key, byte[] data) throws CardException {
        if (key == Key.SIGNATURE) {
            verify(0, 0x81, pin);
            return computeDigitalSignature(data);
        } else {
            verify(0, 0x82, pin);
            if (key == Key.ENCRYPTION) {
                manageSecurityEnvironment(0xA4, (byte) 2);
            }
            return authenticate(data);
        }
    }

    /**
     * Sign the specified data.
     */
    public byte[] computeDigitalSignature(byte[] data) throws CardException {
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, data)); // COMPUTE DIGITAL SIGNATURE
        if (response.getSW() == 0x6a88) {
            throw new CardException("Signature key not found");
        }
        handleError(response);
        return response.getData();
    }

    /**
     * Sign the specified data with the authentication key.
     */
    public byte[] authenticate(byte[] data) throws CardException {
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x88, 0x00, 0x00, data)); // INTERNAL AUTHENTICATE
        if (response.getSW() == 0x6a88) {
            throw new CardException("Authentication key not found");
        }
        handleError(response);
        return response.getData();
    }

    /**
     * Assign the encryption of the authentication key to the DECIPHER and INTERNAL AUTHENTICATE operations
     *
     * @param p2     the operation (0xA4: INTERNAL AUTHENTICATE, 0xB8: DECIPHER)
     * @param keyRef the reference of the key (2: encryption key, 3: authentication key)
     */
    public void manageSecurityEnvironment(int p2, byte keyRef) throws CardException {
        ResponseAPDU response = transmit(new CommandAPDU(0x00, 0x22, 0x41, p2, new byte[] {(byte) 0x83, 0x01, keyRef})); // MANAGE SECURITY ENVIRONMENT
        handleError(response);
    }

    /**
     * Transmit the command to the card and display the APDU request/response if debug is enabled.
     */
    private ResponseAPDU transmit(CommandAPDU command) throws CardException {
        if (debug) {
            System.out.println(command);
            try {
                HexDump.dump(command.getBytes(), 0, System.out, 0);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        long t1 = System.nanoTime();
        ResponseAPDU response = channel.transmit(command);
        long t2 = System.nanoTime();

        if (debug) {
            System.out.println(response + " (" + (t2 - t1) / 1000000 + " ms)");
            if (response.getData().length > 0) {
                try {
                    HexDump.dump(response.getData(), 0, System.out, 0);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            System.out.println();
        }

        return response;
    }

    /**
     * Get the OpenPGP card matching the specified name.
     */
    public static OpenPGPCard getCard() throws CardException {
        killSmartCardDaemon();

        CardTerminals terminals = TerminalFactory.getDefault().terminals();
        for (CardTerminal terminal : terminals.list(CardTerminals.State.CARD_PRESENT)) {
            try {
                Card card = terminal.connect("T=1");
                CardChannel channel = card.getBasicChannel();
                return new OpenPGPCard(channel);
            } catch (CardException e) {
                e.printStackTrace();
            }
        }

        return null;
    }

    /**
     * Kill scdaemon to release the card.
     */
    private static void killSmartCardDaemon() {
        try {
            new ProcessBuilder("gpgconf", "--kill", "scdaemon").start().waitFor(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            // gpgconf not found, let's continue
        }
    }
}
