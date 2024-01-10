/**
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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
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
 * Base class for the smart card implementations.
 *
 * @since 5.1
 */
abstract class SmartCard {

    private final CardChannel channel;

    /** Personal Identification Number */
    protected String pin;

    /** Data Object cache */
    protected final Map<Integer, byte[]> dataObjectCache = new HashMap<>();

    protected boolean debug;

    protected SmartCard(CardChannel channel) {
        this.channel = channel;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    /**
     * Set the PIN for the verify operation.
     */
    public void verify(String pin) {
        this.pin = pin;
    }

    /**
     * Transmit the command to the card and display the APDU request/response if debug is enabled.
     */
    protected ResponseAPDU transmit(CommandAPDU command) throws CardException {
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
     * Throws a CardException with a meaningful message if the APDU response status indicates an error.
     */
    protected void handleError(ResponseAPDU response) throws CardException {
        switch (response.getSW()) {
            case 0x9000:
                return;
            case 0x63C0:
            case 0x63C1:
            case 0x63C2:
            case 0x63C3:
            case 0x63C4:
            case 0x63C5:
            case 0x63C6:
            case 0x63C7:
            case 0x63C8:
            case 0x63C9:
            case 0x63CA:
            case 0x63CB:
            case 0x63CC:
            case 0x63CD:
            case 0x63CE:
            case 0x63CF:
                throw new CardException("PIN verification failed, " + (response.getSW() & 0x0F) + " tries left");
            case 0x6700:
                throw new CardException("Wrong length");
            case 0x6982:
                throw new CardException("PIN verification required");
            case 0x6983:
                throw new CardException("PIN blocked");
            case 0x6985:
                throw new CardException("Conditions of use not satisfied");
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
     * Opens a channel to the first available smart card matching the specified name.
     *
     * @param name the partial name of the terminal
     */
    static CardChannel openChannel(String name) throws CardException {
        CardTerminal terminal = getTerminal(name);
        if (terminal != null) {
            try {
                Card card = terminal.connect("T=1");
                return card.getBasicChannel();
            } catch (CardException e) {
                e.printStackTrace();
            }
        }

        return null;
    }

    /**
     * Returns the first available smart card terminal matching the specified name.
     *
     * @param name the partial name of the terminal
     */
    static CardTerminal getTerminal(String name) throws CardException {
        CardTerminals terminals = TerminalFactory.getDefault().terminals();
        for (CardTerminal terminal : terminals.list(CardTerminals.State.CARD_PRESENT)) {
            if (name == null || terminal.getName().toLowerCase().contains(name.toLowerCase())) {
                return terminal;
            }
        }

        return null;
    }
}
