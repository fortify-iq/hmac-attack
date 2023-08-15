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
import random
import time
import numpy as np
import sys

sys.path.insert(1, 'sha2-attack/src')

from hmac_trace_generation import generate_hmac_traces, generate_hmac_secrets
from sha2_attack import sha2_attack, Stage1hypo


def show(sha, sec):
    print(' '.join(sha.formatter.format(x) for x in sec[:8]), end='  ')
    print(' '.join(sha.formatter.format(x) for x in sec[8:]))


def stage3(sha, key, test_data, exp_traces, isec, secs, random_state):
    '''Stage 3 (see section 3.3). For every hypothesis, calculate the
    correlation coefficient between one calculated trace and one
    experimental traces (which may contain noise)'''
    is_inner = isec is None
    name = 'inner' if is_inner else 'outer'
    print(f'All found {name} hash IV candidates and their correlation coefficients')
    max_corr = -1.
    for cur_sec in secs:
        if is_inner:
            junk, act_traces = generate_hmac_traces(
                sha, 1, key, cur_sec, None, 0, random_state, len(sha.round_const), test_data
            )
        else:
            junk, junk, act_traces = generate_hmac_traces(
                sha, 1, key, isec, cur_sec, 0, random_state, len(sha.round_const), test_data
            )
        corr = np.corrcoef(exp_traces.flatten(), act_traces.flatten())[0, 1]
        print(' '.join(sha.formatter.format(x) for x in cur_sec) + f'  {corr:6.3f}')
        if corr > max_corr:
            found_sec = cur_sec
            max_corr = corr
    print(f'Found {name} hash IV')
    show(sha, found_sec)
    return found_sec


def hmac_end_to_end(
    sha,
    min_trace_count_log2,
    max_trace_count_log2,
    noise,
    key=None,
    seed=None,
    filter_hypo=False,
    verbose=False,
):
    if key is None:
        if seed is not None:
            random.seed(seed)
        key = []
        for i in range(16):
            key.append(sha.dtype(random.getrandbits(sha.bit_count)))
    else:
        assert len(key) < sha.nibbles_in_block
        tmp = key + '0' * (sha.nibbles_in_block - len(key))
        key = [sha.dtype(int(tmp[i:i + sha.nibble_count], 16))
               for i in range(0, sha.nibbles_in_block, sha.nibble_count)]

    if seed is not None:
        random_state = np.random.RandomState(seed)
    isec, osec = generate_hmac_secrets(sha, key)
    print('key')
    print(' '.join(sha.formatter.format(x) for x in key[:8]))
    print(' '.join(sha.formatter.format(x) for x in key[8:]))
    print()
    print('Actual inner hash IV')
    show(sha, isec)
    print('Actual outer hash IV')
    show(sha, osec)
    print('Collecting the traces')
    data, itraces, otraces = generate_hmac_traces(
        sha, 1 << min_trace_count_log2, key, isec, osec, noise, random_state
    )
    test_data, exp_itraces, exp_otraces = generate_hmac_traces(
        sha, 1, key, isec, osec, noise, random_state, len(sha.round_const)
    )

    itimes, otimes, total_time = [], [], 0.
    itrace_count, otrace_count, istage1_count, istage2_count = None, None, None, None
    print('\nAttacking the inner hash')
    for trace_count in range(min_trace_count_log2, max_trace_count_log2):
        print(f'Trying {1<<trace_count} traces')
        try:
            start = time.time()
            isecs, istage1_count = sha2_attack(
                sha,
                np.transpose(data),
                np.transpose(itraces),
                1 << trace_count,
                None,
                verbose
            )
            istage1_count = istage1_count.bit_length() - 4
            itrace_count = trace_count
            found_isec = stage3(sha, key, test_data, exp_itraces, None, isecs, random_state)
            assert np.all(found_isec == isec[:8])
            end = time.time()
            passed = end - start
            total_time += passed
            itimes.append(passed)
            print(f'{passed:5.3f} sec passed. Inner hash found successfully.')
            break
        except ValueError:
            end = time.time()
            passed = end - start
            total_time += passed
            print(f'{passed:5.3f} sec passed.', end=' ')
            itimes.append(passed)
            print('Inner hash failure.')
            if trace_count == max_trace_count_log2 - 1:
                break
            print('Collecting more traces')
            new_data, new_itraces, new_otraces = generate_hmac_traces(
                sha, 1 << trace_count, key, isec, osec, noise, random_state
            )
            data = np.append(data, new_data, axis=1)
            itraces = np.append(itraces, new_itraces, axis=1)
            otraces = np.append(otraces, new_otraces, axis=1)
    else:
        print('Inner hash failure')
        return None

    print('\nAttacking the outer hash')
    for trace_count in range(min_trace_count_log2, max_trace_count_log2):
        print(f'Trying {1 << trace_count} traces')
        try:
            start = time.time()
            ipadding = np.transpose(np.broadcast_to(np.array(
                [0x80000000] + [0] * 11 + sha.isize, dtype=sha.dtype), (1 << trace_count, 14)))
            idata = np.append(data[:, :1 << trace_count], ipadding, axis=0)
            ires, junk = sha.compress(idata, found_isec)
            opadding = np.transpose(np.broadcast_to(np.array(
                [0x80000000] + [0] * 6 + [0x300], dtype=np.uint32), (1 << trace_count, 8)))
            odata = np.append(ires, opadding, axis=0)
            osecs, istage2_count = sha2_attack(
                sha,
                np.transpose(odata),
                np.transpose(otraces[:, :1 << trace_count]),
                1 << trace_count,
                None,
                verbose
            )
            istage2_count = istage2_count.bit_length() - 4
            otrace_count = trace_count
            found_osec = stage3(sha, key, test_data, exp_otraces, found_isec, osecs, random_state)
            end = time.time()
            passed = end - start
            total_time += passed
            otimes.append(passed)
            assert np.all(found_osec == osec[:8])
            print(f'{passed:5.3f} sec passed. Outer hash found successfully.')
            break
        except ValueError:
            end = time.time()
            passed = end - start
            total_time += passed
            print(f'{passed:5.3f} sec passed.', end=' ')
            otimes.append(passed)
            print('Outer hash failure.')
            if trace_count == max_trace_count_log2 - 1:
                break
            if trace_count < itrace_count:
                continue
            print('Collecting more traces')
            new_data, junk, new_otraces = generate_hmac_traces(
                sha, 1 << trace_count, key, isec, osec, noise, random_state
            )
            data = np.append(data, new_data, axis=1)
            otraces = np.append(otraces, new_otraces, axis=1)
    else:
        print('Outer hash failure')
        return None

    print(f'\nTotal attack time {total_time:5.3f} sec.')
    if itrace_count > otrace_count:
        otimes += [None] * (itrace_count - otrace_count)
    elif otrace_count > itrace_count:
        itimes += [None] * (otrace_count - itrace_count)
    return (
        itrace_count,
        otrace_count,
        istage1_count,
        istage2_count,
        total_time,
        zip(itimes, otimes)
    )
