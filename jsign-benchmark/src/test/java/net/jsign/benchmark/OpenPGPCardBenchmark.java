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

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

/**
 * Benchmark for OpenPGP cards.
 *
 * <p>The benchmarks expects an OpenPGP card or token to be present,
 * with the PIN set to "123456", and 3 keys of the same type in the 3 slots (authentication, encryption, signature).
 * and 2 EC keys (P256, P384) in the slots 9D and 9E.</p>
 *
 * Results with Nitrokey 3A NFC, firmware 1.8.2 (OpenPGP 3.4):
 * <pre>
 * Benchmark                                     Mode  Cnt    Score   Error  Units
 * OpenPGPCardBenchmark.selectApplet             avgt   50   35,631 ± 0,057  ms/op
 * OpenPGPCardBenchmark.verifyPin                avgt   50  568,602 ± 6,743  ms/op
 * OpenPGPCardBenchmark.authenticate (RSA 2048)  avgt   50  306,781 ± 1,229  ms/op
 * OpenPGPCardBenchmark.encrypt      (RSA 2048)  avgt   50  353,342 ± 2,842  ms/op
 * OpenPGPCardBenchmark.sign         (RSA 2048)  avgt   50  666,822 ± 4,557  ms/op
 * OpenPGPCardBenchmark.authenticate (RSA 3072)  avgt   50  411,991 ± 1,787  ms/op
 * OpenPGPCardBenchmark.encrypt      (RSA 3072)  avgt   50  458,407 ± 3,560  ms/op
 * OpenPGPCardBenchmark.sign         (RSA 3072)  avgt   50  830,260 ± 9,284  ms/op
 * OpenPGPCardBenchmark.authenticate (RSA 4096)  avgt   50  578,423 ± 3,252  ms/op
 * OpenPGPCardBenchmark.encrypt      (RSA 4096)  avgt   50  623,885 ± 4,485  ms/op
 * OpenPGPCardBenchmark.sign         (RSA 4096)  avgt   50  937,428 ± 5,922  ms/op
 * OpenPGPCardBenchmark.authenticate (EC P256)   avgt   50  433,962 ± 3,455  ms/op
 * OpenPGPCardBenchmark.encrypt      (EC P256)   avgt   50  476,991 ± 5,480  ms/op
 * OpenPGPCardBenchmark.sign         (EC P256)   avgt   50  816,355 ±12,088  ms/op
 * </pre>
 *
 * Results with Yubikey 5.1.2 (OpenPGP 2.1):
 * <pre>
 * Benchmark                                     Mode  Cnt    Score   Error  Units
 * OpenPGPCardBenchmark.selectApplet             avgt   10    0,893 ± 0,126  ms/op
 * OpenPGPCardBenchmark.verifyPin                avgt   10    9,373 ± 0,085  ms/op
 * OpenPGPCardBenchmark.authenticate (RSA 2048)  avgt   10  134,191 ± 1,112  ms/op
 * OpenPGPCardBenchmark.sign         (RSA 2048)  avgt   10  137,750 ± 0,133  ms/op
 * OpenPGPCardBenchmark.authenticate (RSA 3072)  avgt   10  506,692 ± 7,450  ms/op
 * OpenPGPCardBenchmark.sign         (RSA 3072)  avgt   10  517,010 ± 9,573  ms/op
 * OpenPGPCardBenchmark.authenticate (RSA 4096)  avgt   10  854,132 ± 2,455  ms/op
 * OpenPGPCardBenchmark.sign         (RSA 4096)  avgt   10  855,868 ± 5,322  ms/op
 * </pre>
 */
public class OpenPGPCardBenchmark extends CardBenchmark {

    public static final byte[] AID = new byte[]{(byte) 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
    public static final byte[] PIN = "123456".getBytes();

    @State(Scope.Benchmark)
    public static class UnselectedAppletState extends CardState {
        @Setup(Level.Invocation)
        public void setUp() throws Exception {
            openCardChannel();
        }
    }

    @State(Scope.Benchmark)
    public static class UnauthenticatedState extends CardState {
        @Setup(Level.Invocation)
        public void setUp() throws Exception {
            openCardChannel();
            select(AID);
        }
    }

    @State(Scope.Benchmark)
    public static class AuthenticatedState extends CardState {
        @Setup(Level.Invocation)
        public void setUp() throws Exception {
            openCardChannel();
            select(AID);
            verifyPin(0x00, 0x81, PIN);
        }
    }

    @State(Scope.Benchmark)
    public static class AuthenticatedState2 extends CardState {
        @Setup(Level.Invocation)
        public void setUp() throws Exception {
            openCardChannel();
            select(AID);
            verifyPin(0x00, 0x82, PIN);
        }
    }

    @Benchmark
    public void selectApplet(UnselectedAppletState state) throws Exception {
        state.select(AID);
    }

    @Benchmark
    public void verifyPin(UnauthenticatedState state) throws Exception {
        state.verifyPin(0x00, 0x81, PIN);
    }

    @Benchmark
    public void sign(AuthenticatedState state, Blackhole bh) throws Exception {
        byte[] data = new byte[32];
        ResponseAPDU response = state.card.transmit(new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, data)); // COMPUTE DIGITAL SIGNATURE
        if (response.getSW() == 0x6a88) {
            throw new CardException("Signature key not found");
        }
        handleError(response);
        bh.consume(response.getData());
    }

    @Benchmark
    public void authenticate(AuthenticatedState2 state, Blackhole bh) throws Exception {
        byte[] data = new byte[32];
        ResponseAPDU response = state.card.transmit(new CommandAPDU(0x00, 0x88, 0x00, 0x00, data)); // INTERNAL AUTHENTICATE
        if (response.getSW() == 0x6a88) {
            throw new CardException("Authentication key not found");
        }
        handleError(response);
        bh.consume(response.getData());
    }

    @Benchmark
    public void encrypt(AuthenticatedState2 state, Blackhole bh) throws Exception {
        byte keyref = 2;
        ResponseAPDU response = state.card.transmit(new CommandAPDU(0x00, 0x22, 0x41, 0xA4, new byte[] {(byte) 0x83, 0x01, keyref})); // MANAGE SECURITY ENVIRONMENT
        handleError(response);

        byte[] data = new byte[32];
        response = state.card.transmit(new CommandAPDU(0x00, 0x88, 0x00, 0x00, data)); // INTERNAL AUTHENTICATE
        if (response.getSW() == 0x6a88) {
            throw new CardException("Encryption key not found");
        }
        handleError(response);
        bh.consume(response.getData());
    }
}
