# Simulator of the CDPA Based Attack on HMAC SHA2

This repository implements the CDPA based attack on HMAC SHA2 as described in the paper [Carry-based Differential Power Analysis (CDPA) and its Application to Attacking HMAC-SHA-2](https://tches.iacr.org/index.php/TCHES/article/view/10955/10262). It includes the repository [https://github.com/fortify-iq/sha2-attack](https://github.com/fortify-iq/sha2-attack) which implements the CDPA based attack on SHA2, as a submodule.

The attack assumptions are as follows. A device calculates the full HMAC SHA2 (either 32-bit HMAC SHA256 or 64-bit HMAC SHA512), one round per clock cycle. The attacker feeds the device randomly distributed known inputs, and observes the side channel leakage traces. Analyzing these traces, the attacker finds the internal states before the second application of the compression function in both the inner and outer hashes of HMAC SHA2, by attacking first the inner hash and then the outer hash. This enables the attacker to forge the HMAC SHA2 tag for arbitrary messages. The leakage model assumes that the Hamming distance between the consecutive internal states leaks. Optionally, a normally distributed random noise is added.

The repository contains two folders:

* `src` - The Python code that implements the attack
* `results` - Statistical data produced using this code

Folder `src` contains the following files:

* `hmac_trace_generation.py` - generates traces for the attack on HMAC SHA2.
* `hmac_end_to_end.py` - calls the trace generation function from `hmac_trace_generation.py`, then calls the attack function from `sha2_attack.py` first for the inner hash and then for the outer hash. In the case of a failure, more traces are generated (their number is doubled each time). After both the first and the second stages, the hypothesis with the highest correlation between the expected and actual traces is chosen.
* `test_hmac_attack.py` - a command line utility which performs the attack on SHA2 in a loop using `sha2_end_to_end.py` and collects statistics.

Folder `results` contains the following files:

* `stat32_0.csv, stat32_5.csv, stat64_0.csv, stat64_5.csv` - statistics for HMAC SHA256 and HMAC SHA512, without noise and with noise=5, each one for 1,000 randomly generated HMAC keys.

## Usage of `test_hmac_attack.py`

`test_hmac_attack.py [-h] [-b BIT_COUNT] [-t TRACE_COUNT] [-s SECOND_STAGE_COUNT] [-n NOISE] [-e EXPERIMENT_COUNT] [-r RANDOM_SEED] [-f] [-v]`

- `-h` - Help.
- `-b` - Bit size (32 for HMAC SHA256, 64 for HMAC SHA5120). Default value 32 (HMAC SHA256).
- `-t` - log<sub>2</sub> of the initial number of traces. Default value 15 (2<sup>15</sup> traces).
- `-m` - log<sub>2</sub> of the maximal number of traces + 1. Default value 31 (2<sup>30</sup> traces).
- `-n` - Amplitude of normally distributed noise added to the traces. Default value 0 (no noise).
- `-k` - HMAC SHA2 key (hexadecimal). If not provided, the key is generated at random.
- `-r` - Random seed. If no random seed is provided, the experiments are not reproducible, since each time different random values are used. If a random seed is provided, the experiments are reproducible, and the same command line always produces the same result.
- `-f` - Filter hypotheses. After a successful completion of stage 1, performs stage 2 with only the correct hypothesis, in both the inner and the outer hashes. (In some cases, the first stage generates as many as 2,048 hypotheses.)
- `-v` - Verbose. Prints a detailed log of all the steps of the attack.
- `-l` - Log. Writes a short log into a file.

## Environment Requirements

* Python of version `>= 3.8`.

## Installation of Dependencies

This repository contains [https://github.com/fortify-iq/sha2-attack](https://github.com/fortify-iq/sha2-attack) as a submodule. Therefore, when cloning this repository, use the following:

```bash
git clone --recursive https://github.com/fortify-iq/hmac-attack
```

Alternatively, after the cloning use the following:

```bash
git submodule init
git submodule update
```

The codebase of the attack has a few dependencies.

The simplest way to install them is by using the [pip](https://pip.pypa.io/en/stable/) package manager.
The list of dependencies is contained within the `requirements.txt` file.

To install the dependencies run the `pip install` command:

```bash
python -m pip install -r requirements.txt
```

For more details on installation refer to the `pip` [user guide](https://pip.pypa.io/en/stable/user_guide/#requirements-files).

Note that in case of unmet [environment requirements](#environment-requirements) an error message will appear after running the command above, and the dependencies will not be installed. An appropriate version of a Python interpreter should be installed to fix the problem.
