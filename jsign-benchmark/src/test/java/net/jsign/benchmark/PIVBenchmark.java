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

import java.util.Arrays;
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
 * Benchmark for PIV cards.
 *
 * <p>The benchmarks expects a PIV card or token to be present,
 * with the PIN set to "123456", 2 RSA keys (1024, 2048) in the slots 9A and 9C,
 * and 2 EC keys (P256, P384) in the slots 9D and 9E.</p>
 *
 * Results with Yubikey 5.1.2:
 * <pre>
 * Benchmark                             Mode  Cnt     Score   Error  Units
 * PIVBenchmark.selectApplet             avgt   10     1,257 ± 0,212  ms/op
 * PIVBenchmark.getCertificate           avgt   10     7,298 ± 0,157  ms/op
 * PIVBenchmark.verifyPin                avgt   10     9,135 ± 0,099  ms/op
 * PIVBenchmark.signRSA1024              avgt   10    56,238 ± 0,652  ms/op
 * PIVBenchmark.signRSA2048              avgt   10   138,491 ± 2,433  ms/op
 * PIVBenchmark.signP256                 avgt   10    71,572 ± 0,246  ms/op
 * PIVBenchmark.signP384                 avgt   10   118,563 ± 0,228  ms/op
 * </pre>
 *
 * Results with Nitrokey 3A NFC, firmware 1.8.2:
 * <pre>
 * Benchmark                             Mode  Cnt     Score   Error  Units
 * PIVBenchmark.selectApplet             avgt   20     7,193 ± 0,073  ms/op
 * PIVBenchmark.getCertificate           avgt   20   132,630 ± 0,785  ms/op
 * PIVBenchmark.verifyPin                avgt   20   230,584 ± 2,911  ms/op
 * PIVBenchmark.signRSA2048              avgt   20   931,171 ± 0,519  ms/op
 * PIVBenchmark.signRSA3072              avgt   20  1030,787 ± 0,665  ms/op
 * PIVBenchmark.signP256                 avgt   20  1023,819 ± 0,238  ms/op
 * </pre>
 */
public class PIVBenchmark extends CardBenchmark {

    public static final byte[] AID = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00};
    public static final byte[] PIN = new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, (byte) 0xFF, (byte) 0xFF};

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
            verifyPin(0x00, 0x80, PIN);
        }
    }

    @Benchmark
    public void selectApplet(UnselectedAppletState state) throws Exception {
        state.select(AID);
    }

    @Benchmark
    public void verifyPin(UnauthenticatedState state) throws Exception {
        state.verifyPin(0x00, 0x80, PIN);
    }

    @Benchmark
    public void getCertificate(UnauthenticatedState state, Blackhole bh) throws Exception {
        int tag = 0x5FC10A; // X.509 Certificate for Digital Signature
        byte[] data = new byte[] { 0x5C, 0x03, (byte) ((tag & 0xFF0000) >> 16), (byte) ((tag & 0xFF00) >> 8), (byte) (tag & 0xFF) };
        ResponseAPDU response = state.card.transmit(new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, data)); // GET DATA
        if (response.getSW() == 0x6A88) {
            throw new CardException("Data object 0x" + Integer.toHexString(tag).toUpperCase() + " not found");
        }
        handleError(response);
        bh.consume(response.getData());
    }

    public byte[] sign(CardState state, int slot, String algorithm, int size) throws CardException {
        byte[] data = new byte[32];
        if ("RSA".equalsIgnoreCase(algorithm)) {
            data = rsaPadding(data, size);
        }

        int algorithmId = getAlgorithmId(algorithm, size);

        TLV template = new TLV("7C");
        template.children().add(new TLV("82", new byte[0])); // Response
        template.children().add(new TLV("81", data)); // Challenge

        ResponseAPDU response = state.card.transmit(new CommandAPDU(0x00, 0x87, algorithmId, slot, template.getEncoded())); // GENERAL AUTHENTICATE
        handleError(response);

        return response.getData();
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

    @Benchmark
    public void signRSA1024(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x9A, "RSA", 1024));
    }

    @Benchmark
    public void signRSA2048(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x9C, "RSA", 2048));
    }

    //@Benchmark Not supported with firmware 5.1.2
    public void signRSA3072(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x9A, "RSA", 3072));
    }

    //@Benchmark Not supported with firmware 5.1.2
    public void signRSA4096(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x9C,"RSA", 4096));
    }

    @Benchmark
    public void signP256(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x9D, "EC", 256));
    }

    @Benchmark
    public void signP384(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x9E, "EC", 384));
    }
}
