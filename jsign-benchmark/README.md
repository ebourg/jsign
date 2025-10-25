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

#### CryptoCertum - Common Profile 3.6.1

    Benchmark                                     Mode  Cnt     Score   Error  Units
    CryptoCertumBenchmark.selectApplet            avgt   10     9,451 ± 0,018  ms/op
    CryptoCertumBenchmark.getCertificate          avgt   10   164,283 ± 0,584  ms/op
    CryptoCertumBenchmark.verifyPin               avgt   10    33,029 ± 0,201  ms/op
    CryptoCertumBenchmark.signRSA1024             avgt   10   119,064 ± 3,464  ms/op
    CryptoCertumBenchmark.signRSA2048             avgt   10   269,214 ± 3,375  ms/op
    CryptoCertumBenchmark.signRSA3072             avgt   10  1098,486 ± 1,312  ms/op
    CryptoCertumBenchmark.signRSA4096             avgt   10  1511,895 ± 2,334  ms/op
    CryptoCertumBenchmark.signP256                avgt   10   157,705 ± 0,700  ms/op
    CryptoCertumBenchmark.signP384                avgt   10   230,692 ± 1,392  ms/op
    CryptoCertumBenchmark.signP521                avgt   10   315,247 ± 1,842  ms/op

#### Yubikey 5 NFC - PIV (firmware 5.1.2)

    Benchmark                                     Mode  Cnt     Score   Error  Units
    PIVBenchmark.selectApplet                     avgt   10     1,257 ± 0,212  ms/op
    PIVBenchmark.getCertificate                   avgt   10     7,298 ± 0,157  ms/op
    PIVBenchmark.verifyPin                        avgt   10     9,135 ± 0,099  ms/op
    PIVBenchmark.signRSA1024                      avgt   10    56,238 ± 0,652  ms/op
    PIVBenchmark.signRSA2048                      avgt   10   138,491 ± 2,433  ms/op
    PIVBenchmark.signP256                         avgt   10    71,572 ± 0,246  ms/op
    PIVBenchmark.signP384                         avgt   10   118,563 ± 0,228  ms/op

#### Yubikey 5 NFC - OpenPGP 2.1 (firmware 5.1.2)

    Benchmark                                     Mode  Cnt     Score   Error  Units
    OpenPGPCardBenchmark.selectApplet             avgt   10     0,893 ± 0,126  ms/op
    OpenPGPCardBenchmark.verifyPin                avgt   10     9,373 ± 0,085  ms/op
    OpenPGPCardBenchmark.authenticate (RSA 2048)  avgt   10   134,191 ± 1,112  ms/op
    OpenPGPCardBenchmark.sign         (RSA 2048)  avgt   10   137,750 ± 0,133  ms/op
    OpenPGPCardBenchmark.authenticate (RSA 3072)  avgt   10   506,692 ± 7,450  ms/op
    OpenPGPCardBenchmark.sign         (RSA 3072)  avgt   10   517,010 ± 9,573  ms/op
    OpenPGPCardBenchmark.authenticate (RSA 4096)  avgt   10   854,132 ± 2,455  ms/op
    OpenPGPCardBenchmark.sign         (RSA 4096)  avgt   10   855,868 ± 5,322  ms/op

#### Nitrokey 3A NFC - PIV (firmware 1.8.2)

    Benchmark                                     Mode  Cnt     Score   Error  Units
    PIVBenchmark.selectApplet                     avgt   20     7,193 ± 0,073  ms/op
    PIVBenchmark.getCertificate                   avgt   20   132,630 ± 0,785  ms/op
    PIVBenchmark.verifyPin                        avgt   20   230,584 ± 2,911  ms/op
    PIVBenchmark.signRSA2048                      avgt   20   931,171 ± 0,519  ms/op
    PIVBenchmark.signRSA3072                      avgt   20  1030,787 ± 0,665  ms/op
    PIVBenchmark.signP256                         avgt   20  1023,819 ± 0,238  ms/op

#### Nitrokey 3A NFC - OpenPGP 3.4 (firmware 1.8.2)

    Benchmark                                     Mode  Cnt     Score   Error  Units
    OpenPGPCardBenchmark.selectApplet             avgt   50    35,631 ± 0,057  ms/op
    OpenPGPCardBenchmark.verifyPin                avgt   50   568,602 ± 6,743  ms/op
    OpenPGPCardBenchmark.authenticate (RSA 2048)  avgt   50   306,781 ± 1,229  ms/op
    OpenPGPCardBenchmark.encrypt      (RSA 2048)  avgt   50   353,342 ± 2,842  ms/op
    OpenPGPCardBenchmark.sign         (RSA 2048)  avgt   50   666,822 ± 4,557  ms/op
    OpenPGPCardBenchmark.authenticate (RSA 3072)  avgt   50   411,991 ± 1,787  ms/op
    OpenPGPCardBenchmark.encrypt      (RSA 3072)  avgt   50   458,407 ± 3,560  ms/op
    OpenPGPCardBenchmark.sign         (RSA 3072)  avgt   50   830,260 ± 9,284  ms/op
    OpenPGPCardBenchmark.authenticate (RSA 4096)  avgt   50   578,423 ± 3,252  ms/op
    OpenPGPCardBenchmark.encrypt      (RSA 4096)  avgt   50   623,885 ± 4,485  ms/op
    OpenPGPCardBenchmark.sign         (RSA 4096)  avgt   50   937,428 ± 5,922  ms/op
    OpenPGPCardBenchmark.authenticate (EC P256)   avgt   50   433,962 ± 3,455  ms/op
    OpenPGPCardBenchmark.encrypt      (EC P256)   avgt   50   476,991 ± 5,480  ms/op
    OpenPGPCardBenchmark.sign         (EC P256)   avgt   50   816,355 ±12,088  ms/op
