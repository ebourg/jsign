Jsign Benchmarks
----------------

This module contains benchmarks for the cryptographic card/token supported by Jsign.

### Running the benchmarks

Each benchmark requires a specific configuration (a specific smart card or token connected to the system
with keys and certificates installed). Please refer to the individual benchmark classes for setup instructions.

To run the benchmarks, use the following command:

```mvn test -Pbenchmark```

To run only one benchmark, use the following command:

```mvn test -Pbenchmark -Dbenchmark=BenchmarkClassName```


### Results

#### CryptoCertum (common profile 3.6.1)

    Benchmark                             Mode  Cnt     Score   Error  Units
    CryptoCertumBenchmark.selectApplet    avgt   10     9,451 ± 0,018  ms/op
    CryptoCertumBenchmark.getCertificate  avgt   10   164,283 ± 0,584  ms/op
    CryptoCertumBenchmark.verifyPin       avgt   10    33,029 ± 0,201  ms/op
    CryptoCertumBenchmark.signRSA1024     avgt   10   119,064 ± 3,464  ms/op
    CryptoCertumBenchmark.signRSA2048     avgt   10   269,214 ± 3,375  ms/op
    CryptoCertumBenchmark.signRSA3072     avgt   10  1098,486 ± 1,312  ms/op
    CryptoCertumBenchmark.signRSA4096     avgt   10  1511,895 ± 2,334  ms/op
    CryptoCertumBenchmark.signP256        avgt   10   157,705 ± 0,700  ms/op
    CryptoCertumBenchmark.signP384        avgt   10   230,692 ± 1,392  ms/op
    CryptoCertumBenchmark.signP521        avgt   10   315,247 ± 1,842  ms/op

#### Yubikey PIV (firmware 5.1.2)

    Benchmark                             Mode  Cnt     Score   Error  Units
    PIVBenchmark.selectApplet             avgt   10     1,257 ± 0,212  ms/op
    PIVBenchmark.getCertificate           avgt   10     7,298 ± 0,157  ms/op
    PIVBenchmark.verifyPin                avgt   10     9,135 ± 0,099  ms/op
    PIVBenchmark.signRSA1024              avgt   10    56,238 ± 0,652  ms/op
    PIVBenchmark.signRSA2048              avgt   10   138,491 ± 2,433  ms/op
    PIVBenchmark.signP256                 avgt   10    71,572 ± 0,246  ms/op
    PIVBenchmark.signP384                 avgt   10   118,563 ± 0,228  ms/op
