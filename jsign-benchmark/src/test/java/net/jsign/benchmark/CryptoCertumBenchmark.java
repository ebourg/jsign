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

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

/**
 * Benchmark for CryptoCertum cryptographic cards (common profile only).
 *
 * <p>The benchmarks expects a CryptoCertum card to be present in the smart card reader,
 * with the PIN set to "123456", 4 RSA keys (1024, 2048, 3072, 4096 bits) in the
 * first 4 slots. and 3 EC keys (P256, P384, P521) in the next slots.</p>
 *
 * Typical results (CryptoCertum 3.6):
 * <pre>
 * Benchmark                             Mode  Cnt     Score   Error  Units
 * CryptoCertumBenchmark.selectApplet    avgt   10     9,451 ± 0,018  ms/op
 * CryptoCertumBenchmark.getCertificate  avgt   10   164,283 ± 0,584  ms/op
 * CryptoCertumBenchmark.verifyPin       avgt   10    33,029 ± 0,201  ms/op
 * CryptoCertumBenchmark.signRSA1024     avgt   10   119,064 ± 3,464  ms/op
 * CryptoCertumBenchmark.signRSA2048     avgt   10   269,214 ± 3,375  ms/op
 * CryptoCertumBenchmark.signRSA3072     avgt   10  1098,486 ± 1,312  ms/op
 * CryptoCertumBenchmark.signRSA4096     avgt   10  1511,895 ± 2,334  ms/op
 * CryptoCertumBenchmark.signP256        avgt   10   157,705 ± 0,700  ms/op
 * CryptoCertumBenchmark.signP384        avgt   10   230,692 ± 1,392  ms/op
 * CryptoCertumBenchmark.signP521        avgt   10   315,247 ± 1,842  ms/op
 * </pre>
 */
public class CryptoCertumBenchmark extends CardBenchmark {

    public static final byte[] AID = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4F};
    public static final byte[] PIN = new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

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
            verifyPin(0x00, 0x83, PIN);
        }
    }

    @Benchmark
    public void selectApplet(UnselectedAppletState state) throws Exception {
        state.select(AID);
    }

    @Benchmark
    public void verifyPin(UnauthenticatedState state) throws Exception {
        state.verifyPin(0x00, 0x83, PIN);
    }

    @Benchmark
    public void getCertificate(UnauthenticatedState state, Blackhole bh) throws Exception {
        ResponseAPDU response = state.card.transmit(new CommandAPDU(0x00, 0xA4, 0x02, 0x0C, new byte[]{0x20, 0x02})); // SELECT FILE
        handleError(response);

        int offset = 0;   // page
        int length = 256; // max length per page
        while (true) {
            response = state.card.transmit(new CommandAPDU(0x00, 0xB0, offset & 0xFF, (offset & 0xFF00) >> 8, length)); // READ BINARY
            handleError(response);
            byte[] data = response.getData();
            bh.consume(data);
            if (data.length < length) {
                break;
            }
            offset++;
        }
    }

    public byte[] sign(CardState state, int keyref) throws Exception {
        byte[] template = new byte[]{(byte) 0x80, 0x01, (byte) (keyref < 0x30 ? 0x42 : 0x44), (byte) 0x84, 0x01, (byte) keyref};
        state.manageSecurityEnvironment(0x81, 0xB6, template);

        byte[] hash = new byte[34];
        hash[0] = (byte) 0x90;
        hash[1] = 0x20;
        ResponseAPDU response = state.card.transmit(new CommandAPDU(0x00, 0x2A, 0x90, 0xA0, hash)); // HASH
        handleError(response);

        response = state.card.transmit(new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, 0x80)); // COMPUTE DIGITAL SIGNATURE
        handleError(response);

        return response.getData();
    }

    @Benchmark
    public void signRSA1024(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x21));
    }

    @Benchmark
    public void signRSA2048(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x22));
    }

    @Benchmark
    public void signRSA3072(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x23));
    }

    @Benchmark
    public void signRSA4096(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x24));
    }

    @Benchmark
    public void signP256(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x31));
    }

    @Benchmark
    public void signP384(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x32));
    }

    @Benchmark
    public void signP521(AuthenticatedState state, Blackhole bh) throws Exception {
        bh.consume(sign(state, 0x33));
    }
}
