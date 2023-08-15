# Copyright © 2022-present FortifyIQ, Inc. All rights reserved. 
#
# This program, sha2-attack, is free software: you can redistribute it and/or modify
# it under the terms and conditions of FortifyIQ’s free use license (”License”)
# which is located at
# https://raw.githubusercontent.com/fortify-iq/sha2-attack/master/LICENSE.
# This license governs use of the accompanying software. If you use the
# software, you accept this license. If you do not accept the license, do not
# use the software.
#
# The License permits non-commercial use, but does not permit commercial use or
# resale. This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY OR RIGHT TO ECONOMIC DAMAGES; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# If you have any questions regarding the software of the license, please
# contact kreimer@fortifyiq.com
import warnings
import argparse
import sys

sys.path.insert(1, 'sha2-attack/src')

from sha2 import Sha256, Sha512
from hmac_end_to_end import hmac_end_to_end


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-b',
        '--bit-count',
        type=int,
        choices=[32, 64],
        default=32,
        help='Bit size of words - 32 for SHA256 or 64 for SHA512 (32 by default)',
    )
    parser.add_argument(
        '-t',
        '--trace-count-log2',
        type=int,
        default=15,
        help='Log2 of the number of traces to initially acquire '
        'for the attack (15 by default)',
    )
    parser.add_argument(
        '-m',
        '--maximal-trace-count-log2',
        type=int,
        default=31,
        help='Log2 of the maximal number of traces + 1 to acquire '
        'for the attack (31 by default)',
    )
    parser.add_argument(
        '-n',
        '--noise',
        type=float,
        default=None,
        help='Standard deviation of the normally distributed noise '
        'added to the trace (0 by default)',
    )
    parser.add_argument(
        '-k',
        '--key',
        type=str,
        required=False,
        help='Key',
    )
    parser.add_argument(
        '-r',
        '--random-seed',
        type=int,
        default=None,
        help='Random seed for the secret generation (None by default)',
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Provide detailed printout',
    )
    parser.add_argument(
        '-l',
        '--log',
        action='store_true',
        help='Write the log into a file',
    )

    args = parser.parse_args()

    return (
        args.bit_count,
        args.trace_count_log2,
        args.maximal_trace_count_log2,
        args.noise,
        args.key,
        args.random_seed,
        args.verbose,
        args.log,
    )


if __name__ == '__main__':
    # Parse the command line
    (
        bit_count,
        trace_count_log2,
        maximal_trace_count_log2,
        noise,
        key,
        seed,
        verbose,
        log,
    ) = parse()
    # Suppress expected overflows in addition and subtraction
    warnings.filterwarnings('ignore', category=RuntimeWarning)
    sha = Sha256() if bit_count == 32 else Sha512()
    itrace_count, otrace_count, istage1_count, istage2_count, total_time, times = hmac_end_to_end(
        sha, trace_count_log2, maximal_trace_count_log2, noise, key, seed, verbose
    )
    if log:
        n = int(noise) if noise else 0
        file_name = f'stat{n:d}_{bit_count:d}.csv'
        with open(file_name, 'at') as f:
            f.write(f'{seed},')
            f.write('Failure,' if otrace_count is None else 'Success,')
            f.write(f'{itrace_count},{otrace_count},{istage1_count},{istage2_count},{total_time:5.3f},')
            f.write(','.join(f'{x:5.3f}' if x else '' for y in times for x in y))
            f.write('\n')
