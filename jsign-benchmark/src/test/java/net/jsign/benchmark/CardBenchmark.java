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

package net.jsign.benchmark;

import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Warmup;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Measurement(iterations = 10)
@Warmup(iterations = 3)
@Fork(1)
public abstract class CardBenchmark {

    public static class CardState {
        public CardChannel card;

        public void openCardChannel() throws Exception {
            List<CardTerminal> activeTerminals = TerminalFactory.getDefault().terminals().list(CardTerminals.State.CARD_PRESENT);
            if (activeTerminals.isEmpty()) {
                throw new IllegalStateException("No smart card terminal with a card present");
            }
            CardTerminal terminal = activeTerminals.get(0);
            card = terminal.connect("*").getBasicChannel();
        }

        public void select(byte[] aid) throws Exception {
            ResponseAPDU response = card.transmit(new CommandAPDU(0x00, (byte) 0xA4, 0x04, 0x00, aid));
            switch (response.getSW()) {
                case 0x6A82:
                case 0x6A86:
                    throw new CardException("Application not found on the card/token");
            }
            handleError(response);
        }

        public void verifyPin(int p1, int p2, byte[] pin) throws Exception {
            ResponseAPDU response = card.transmit(new CommandAPDU(0x00, 0x20, p1, p2, pin));
            handleError(response);
        }

        public void manageSecurityEnvironment(int p1, int p2, byte[] data) throws Exception {
            ResponseAPDU response = card.transmit(new CommandAPDU(0x00, 0x22, p1, p2, data)); // MANAGE SECURITY ENVIRONMENT
            handleError(response);
        }
    }

    public static void handleError(ResponseAPDU response) throws CardException {
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
            case 0x6A88:
                throw new CardException("Referenced data not found");
            case 0x6B00:
                throw new CardException("Wrong parameter(s) P1-P2");
            case 0x6D00:
                throw new CardException("Instruction code not supported or invalid");
            default:
                throw new CardException("Error " + Integer.toHexString(response.getSW()));
        }
    }
}
