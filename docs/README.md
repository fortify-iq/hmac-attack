# Statistics for the CDPA Based Attack on HMAC SHA2

This folder contains four files with statistical data:

* `stat0_32.csv` - HMAC SHA256, no noise
* `stat5_32.csv` - HMAC SHA256, noise=5
* `stat0_64.csv` - HMAC SHA512, no noise
* `stat5_64.csv` - HMAC SHA512, noise=5

Each table contains 1000 lines, not counting the header line. 

Each line corresponds to the attack on a single HMAC SHA2 key.

The columns have the following meanings:

* Column A - the seed used to generate the key and the traces
* Column B - pass/fail
* Columns C, D - log<sub>2</sub> of the number of traces used to attack the inner and the outer hashes
* Columns E, F - log<sub>2</sub> of the number of hypotheses after stage 1 for the inner and the outer hashes
* Column G - the total time in seconds of the attack (not counting the trace generation)
* Columns H-AM - time in seconds for each stage of the attack. FOr each column, log<sub>2</sub> of the number of traces and inner vs. outer hash are specified in the header line