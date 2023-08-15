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

import numpy as np


def generate_hmac_secrets(sha, key):
    return sha.compress(key ^ sha.ipad), sha.compress(key ^ sha.opad)


def generate_hmac_traces(
        sha,
        trace_count,
        key,
        isec,
        osec,
        noise,
        random_state,
        trace_size=2,
        data=None
):
    if data is None:
        data = random_state.randint(1 << sha.bit_count, size=(2, trace_count), dtype=sha.dtype)
    ipadding = np.transpose(np.broadcast_to(np.array(
        [0x80000000] + [0] * 11 + sha.isize, dtype=sha.dtype), (trace_count, 14)))
    idata = np.append(data, ipadding, axis=0)
    ires, itraces = sha.compress(idata, isec[:8], trace_size)
    if osec is None:
        return data, itraces
    opadding = np.transpose(np.broadcast_to(np.array(
        [0x80000000] + [0] * 6 + [0x300], dtype=np.uint32), ((trace_count, 8))))
    odata = np.append(ires, opadding, axis=0)
    ores, otraces = sha.compress(odata, osec[:8], trace_size)
    if noise:
        itraces = itraces.astype(float)
        itraces += random_state.normal(scale=noise, size=itraces.shape)
        otraces = otraces.astype(float)
        otraces += random_state.normal(scale=noise, size=otraces.shape)
    return data, itraces, otraces
