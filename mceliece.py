import os
import hashlib

class ClassicMcEliece:
    def __init__(self, variant):
        self.variant = variant
        self._init_params()
        self._init_crypto_constants()

    def _init_params(self):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            self.GFBITS = 12
            self.SYS_N = 3488
            self.SYS_T = 64
        elif self.variant in ['mceliece460896', 'mceliece460896f']:
            self.GFBITS = 13
            self.SYS_N = 4608
            self.SYS_T = 96
        elif self.variant in ['mceliece6688128', 'mceliece6688128f']:
            self.GFBITS = 13
            self.SYS_N = 6688
            self.SYS_T = 128
        elif self.variant in ['mceliece6960119', 'mceliece6960119f']:
            self.GFBITS = 13
            self.SYS_N = 6960
            self.SYS_T = 119
        elif self.variant in ['mceliece8192128', 'mceliece8192128f']:
            self.GFBITS = 13
            self.SYS_N = 8192
            self.SYS_T = 128
        else:
            raise ValueError(f'Unsupported variant: {self.variant}')
        self.COND_BYTES = (1 << self.GFBITS - 4) * (2 * self.GFBITS - 1)
        self.IRR_BYTES = self.SYS_T * 2
        self.PK_NROWS = self.SYS_T * self.GFBITS
        self.PK_NCOLS = self.SYS_N - self.PK_NROWS
        self.PK_ROW_BYTES = (self.PK_NCOLS + 7) // 8
        self.SYND_BYTES = (self.PK_NROWS + 7) // 8
        self.GFMASK = (1 << self.GFBITS) - 1
        self.N_BYTES = self.SYS_N // 8
        if self.variant in ['mceliece6960119', 'mceliece6960119f']:
            self.tail = self.PK_NROWS % 8
            self.INNER_PK_ACCESSES = self.N_BYTES - 1 - (self.PK_NROWS - 1) // 8 + 1

    def _init_crypto_constants(self):
        self.CRYPTO_BYTES = 32
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            self.CRYPTO_PUBLICKEYBYTES = 261120
            self.CRYPTO_SECRETKEYBYTES = 6492
            self.CRYPTO_CIPHERTEXTBYTES = 96
        elif self.variant in ['mceliece460896', 'mceliece460896f']:
            self.CRYPTO_PUBLICKEYBYTES = 524160
            self.CRYPTO_SECRETKEYBYTES = 13608
            self.CRYPTO_CIPHERTEXTBYTES = 156
        elif self.variant in ['mceliece6688128', 'mceliece6688128f']:
            self.CRYPTO_PUBLICKEYBYTES = 1044992
            self.CRYPTO_SECRETKEYBYTES = 13932
            self.CRYPTO_CIPHERTEXTBYTES = 208
        elif self.variant in ['mceliece6960119', 'mceliece6960119f']:
            self.CRYPTO_PUBLICKEYBYTES = 1047319
            self.CRYPTO_SECRETKEYBYTES = 13948
            self.CRYPTO_CIPHERTEXTBYTES = 194
        elif self.variant in ['mceliece8192128', 'mceliece8192128f']:
            self.CRYPTO_PUBLICKEYBYTES = 1357824
            self.CRYPTO_SECRETKEYBYTES = 14120
            self.CRYPTO_CIPHERTEXTBYTES = 208

    def gf_iszero(self, a):
        t = a - 1 & 4294967295
        t >>= 19
        return t & 65535

    def gf_add(self, in0, in1):
        return in0 ^ in1

    def gf_mul(self, in0, in1):
        t0 = in0
        t1 = in1
        tmp = t0 * (t1 & 1)
        for i in range(1, self.GFBITS):
            tmp ^= t0 * (t1 & 1 << i)
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            t = tmp & 8372224
            tmp ^= t >> 9 ^ t >> 12
            t = tmp & 12288
            tmp ^= t >> 9 ^ t >> 12
        else:
            t = tmp & 33488896
            tmp ^= t >> 9 ^ t >> 10 ^ t >> 12 ^ t >> 13
            t = tmp & 57344
            tmp ^= t >> 9 ^ t >> 10 ^ t >> 12 ^ t >> 13
        return tmp & self.GFMASK

    def gf_sq(self, in0):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            b = [1431655765, 858993459, 252645135, 16711935]
            x = in0
            x = (x | x << 8) & b[3]
            x = (x | x << 4) & b[2]
            x = (x | x << 2) & b[1]
            x = (x | x << 1) & b[0]
            t = x & 8372224
            x ^= t >> 9 ^ t >> 12
            t = x & 12288
            x ^= t >> 9 ^ t >> 12
            return x & self.GFMASK
        else:
            return self.gf_mul(in0, in0)

    def gf_sq2(self, in0):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            return self.gf_sq(self.gf_sq(in0))
        else:
            B = [1229782938247303441, 217020518514230019, 4222189076152335, 1095216660735]
            M = [561850441793536, 1097364144128, 2143289344, 4186112]
            x = in0
            x = (x | x << 24) & B[3]
            x = (x | x << 12) & B[2]
            x = (x | x << 6) & B[1]
            x = (x | x << 3) & B[0]
            for i in range(4):
                t = x & M[i]
                x ^= t >> 9 ^ t >> 10 ^ t >> 12 ^ t >> 13
            return x & self.GFMASK

    def gf_sqmul(self, in0, m):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            return self.gf_mul(self.gf_sq(in0), m)
        else:
            M = [137170518016, 267911168, 516096]
            t0 = in0
            t1 = m
            x = (t1 << 6) * (t0 & 1 << 6)
            t0 ^= t0 << 7
            x ^= t1 * (t0 & 16385)
            x ^= t1 * (t0 & 32770) << 1
            x ^= t1 * (t0 & 65540) << 2
            x ^= t1 * (t0 & 131080) << 3
            x ^= t1 * (t0 & 262160) << 4
            x ^= t1 * (t0 & 524320) << 5
            for i in range(3):
                t = x & M[i]
                x ^= t >> 9 ^ t >> 10 ^ t >> 12 ^ t >> 13
            return x & self.GFMASK

    def gf_sq2mul(self, in0, m):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            return self.gf_mul(self.gf_sq2(in0), m)
        else:
            M = [2301339409586323456, 4494803534348288, 8778913153024, 17146314752, 33423360, 122880]
            t0 = in0
            t1 = m
            x = (t1 << 18) * (t0 & 1 << 6)
            t0 ^= t0 << 21
            x ^= t1 * (t0 & 268435457)
            x ^= t1 * (t0 & 536870914) << 3
            x ^= t1 * (t0 & 1073741828) << 6
            x ^= t1 * (t0 & 2147483656) << 9
            x ^= t1 * (t0 & 4294967312) << 12
            x ^= t1 * (t0 & 8589934624) << 15
            for i in range(6):
                t = x & M[i]
                x ^= t >> 9 ^ t >> 10 ^ t >> 12 ^ t >> 13
            return x & self.GFMASK

    def gf_frac(self, den, num):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            return self.gf_mul(self.gf_inv(den), num)
        else:
            tmp_11 = self.gf_sqmul(den, den)
            tmp_1111 = self.gf_sq2mul(tmp_11, tmp_11)
            out = self.gf_sq2(tmp_1111)
            out = self.gf_sq2mul(out, tmp_1111)
            out = self.gf_sq2(out)
            out = self.gf_sq2mul(out, tmp_1111)
            return self.gf_sqmul(out, num)

    def gf_inv(self, in0):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            out = self.gf_sq(in0)
            tmp_11 = self.gf_mul(out, in0)
            out = self.gf_sq(tmp_11)
            out = self.gf_sq(out)
            tmp_1111 = self.gf_mul(out, tmp_11)
            out = self.gf_sq(tmp_1111)
            out = self.gf_sq(out)
            out = self.gf_sq(out)
            out = self.gf_sq(out)
            out = self.gf_mul(out, tmp_1111)
            out = self.gf_sq(out)
            out = self.gf_sq(out)
            out = self.gf_mul(out, tmp_11)
            out = self.gf_sq(out)
            out = self.gf_mul(out, in0)
            return self.gf_sq(out)
        else:
            return self.gf_frac(in0, 1)

    def gf_mul_inplace(self, out, in0, in1):
        prod = [0] * (self.SYS_T * 2 - 1)
        for i in range(self.SYS_T):
            for j in range(self.SYS_T):
                prod[i + j] ^= self.gf_mul(in0[i], in1[j])
        for i in range((self.SYS_T - 1) * 2, self.SYS_T - 1, -1):
            if self.variant in ['mceliece348864', 'mceliece348864f']:
                if i - self.SYS_T + 3 < len(prod):
                    prod[i - self.SYS_T + 3] ^= prod[i]
                if i - self.SYS_T + 1 < len(prod):
                    prod[i - self.SYS_T + 1] ^= prod[i]
                if i - self.SYS_T >= 0:
                    prod[i - self.SYS_T] ^= self.gf_mul(prod[i], 2)
            elif self.variant in ['mceliece460896', 'mceliece460896f']:
                if i - self.SYS_T + 10 < len(prod):
                    prod[i - self.SYS_T + 10] ^= prod[i]
                if i - self.SYS_T + 9 < len(prod):
                    prod[i - self.SYS_T + 9] ^= prod[i]
                if i - self.SYS_T + 6 < len(prod):
                    prod[i - self.SYS_T + 6] ^= prod[i]
                if i - self.SYS_T >= 0:
                    prod[i - self.SYS_T] ^= prod[i]
            elif self.variant in ['mceliece6960119', 'mceliece6960119f']:
                if i - self.SYS_T + 8 < len(prod):
                    prod[i - self.SYS_T + 8] ^= prod[i]
                if i - self.SYS_T >= 0:
                    prod[i - self.SYS_T] ^= prod[i]
            else:
                if i - self.SYS_T + 7 < len(prod):
                    prod[i - self.SYS_T + 7] ^= prod[i]
                if i - self.SYS_T + 2 < len(prod):
                    prod[i - self.SYS_T + 2] ^= prod[i]
                if i - self.SYS_T + 1 < len(prod):
                    prod[i - self.SYS_T + 1] ^= prod[i]
                if i - self.SYS_T >= 0:
                    prod[i - self.SYS_T] ^= prod[i]
        for i in range(self.SYS_T):
            out[i] = prod[i]

    def store_gf(self, gf):
        return gf.to_bytes(2, byteorder='little')

    def load_gf(self, src):
        return int.from_bytes(src, byteorder='little') & self.GFMASK

    def bitrev(self, a):
        a = (a & 255) << 8 | (a & 65280) >> 8
        a = (a & 3855) << 4 | (a & 61680) >> 4
        a = (a & 13107) << 2 | (a & 52428) >> 2
        a = (a & 21845) << 1 | (a & 43690) >> 1
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            return a >> 4
        else:
            return a >> 3

    def eval(self, f, a):
        r = f[self.SYS_T]
        for i in range(self.SYS_T - 1, -1, -1):
            r = self.gf_mul(r, a)
            r = self.gf_add(r, f[i])
        return r

    def root(self, out, f, l):
        for i in range(self.SYS_N):
            out[i] = self.eval(f, l[i])

    def synd(self, out, f, l, r):
        for i in range(self.SYS_T * 2):
            out[i] = 0
        for i in range(self.SYS_N):
            c = r[i // 8] >> i % 8 & 1
            e = self.eval(f, l[i])
            e_inv = self.gf_inv(self.gf_mul(e, e))
            for j in range(self.SYS_T * 2):
                out[j] = self.gf_add(out[j], self.gf_mul(e_inv, c))
                e_inv = self.gf_mul(e_inv, l[i])

    def genpoly_gen(self, out, f):
        mat = [[0] * self.SYS_T for _ in range(self.SYS_T + 1)]
        mat[0][0] = 1
        for j in range(1, self.SYS_T):
            mat[0][j] = 0
        for j in range(self.SYS_T):
            mat[1][j] = f[j]
        for j in range(2, self.SYS_T + 1):
            self.gf_mul_inplace(mat[j], mat[j - 1], f)
        for j in range(self.SYS_T):
            for k in range(j + 1, self.SYS_T):
                mask = self.gf_iszero(mat[j][j])
                if mask != 0:
                    for c in range(j, self.SYS_T + 1):
                        mat[c][j] ^= mat[c][k]
            if mat[j][j] == 0:
                return -1
            inv = self.gf_inv(mat[j][j])
            for c in range(self.SYS_T + 1):
                mat[c][j] = self.gf_mul(mat[c][j], inv)
            for k in range(self.SYS_T):
                if k != j:
                    t = mat[j][k]
                    for c in range(self.SYS_T + 1):
                        mat[c][k] ^= self.gf_mul(mat[c][j], t)
        for i in range(self.SYS_T):
            out[i] = mat[self.SYS_T][i]
        return 0

    def ctz(self, input_val):
        if not self.variant.endswith('f'):
            raise NotImplementedError("The `ctz` function only works with variants ending in 'f'")
        m = 0
        r = 0
        for i in range(64):
            b = input_val >> i & 1
            m |= b
            r += (m ^ 1) & (b ^ 1)
        return r

    def same_mask(self, x, y):
        if not self.variant.endswith('f'):
            raise NotImplementedError("The `same_mask` function only works with variants that have the 'f'")
        mask = (x ^ y) & 65535
        mask = mask - 1
        mask >>= 63
        mask = 0 - mask
        return mask

    def same_mask_u8(self, x, y):
        mask = (x ^ y) & 4294967295
        mask = mask - 1 & 4294967295
        mask >>= 31
        mask = 0 - mask
        return mask & 255

    def mov_columns(self, mat, pi, pivots):
        if not self.variant.endswith('f'):
            raise NotImplementedError("The `mov_columns` function only works with variants that end in 'f'.")
        buf = [0] * 64
        ctz_list = [0] * 32
        row = self.PK_NROWS - 32
        block_idx = row // 8
        if self.variant == 'mceliece6960119f':
            tail = row % 8
            tmp = [0] * 9
            for i in range(32):
                for j in range(9):
                    tmp[j] = mat[row + i][block_idx + j]
                for j in range(8):
                    tmp[j] = tmp[j] >> tail | tmp[j + 1] << 8 - tail
                buf[i] = int.from_bytes(tmp[:8], byteorder='little')
        else:
            for i in range(32):
                buf[i] = int.from_bytes(mat[row + i][block_idx:block_idx + 8], byteorder='little')
        pivots[0] = 0
        for i in range(32):
            t = buf[i]
            for j in range(i + 1, 32):
                t |= buf[j]
            if t == 0:
                return -1
            ctz_list[i] = self.ctz(t)
            s = ctz_list[i]
            pivots[0] |= 1 << s
            for j in range(i + 1, 32):
                mask = buf[i] >> s & 1
                mask = mask - 1
                buf[i] ^= buf[j] & mask
            for j in range(i + 1, 32):
                mask = buf[j] >> s & 1
                mask = 0 - mask
                buf[j] ^= buf[i] & mask
        for j in range(32):
            for k in range(j + 1, 64):
                d = (pi[row + j] ^ pi[row + k]) & 65535
                d &= self.same_mask(k, ctz_list[j])
                pi[row + j] ^= d
                pi[row + k] ^= d
        if self.variant == 'mceliece6960119f':
            for i in range(self.PK_NROWS):
                tmp = [0] * 9
                for k in range(9):
                    tmp[k] = mat[i][block_idx + k]
                for k in range(8):
                    tmp[k] = tmp[k] >> tail | tmp[k + 1] << 8 - tail
                t = int.from_bytes(tmp[:8], byteorder='little')
                for j in range(32):
                    d = t >> j ^ t >> ctz_list[j]
                    d &= 1
                    t ^= d << ctz_list[j]
                    t ^= d << j
                bytes_t = t.to_bytes(8, byteorder='little')
                for k in range(8):
                    tmp[k] = bytes_t[k]
                mat[i][block_idx + 8] = mat[i][block_idx + 8] >> tail << tail | tmp[7] >> 8 - tail
                mat[i][block_idx] = tmp[0] << tail | mat[i][block_idx] << 8 - tail >> 8 - tail
                for k in range(1, 8):
                    mat[i][block_idx + k] = tmp[k] << tail | tmp[k - 1] >> 8 - tail
        else:
            for i in range(self.PK_NROWS):
                t = int.from_bytes(mat[i][block_idx:block_idx + 8], byteorder='little')
                for j in range(32):
                    d = t >> j ^ t >> ctz_list[j]
                    d &= 1
                    t ^= d << ctz_list[j]
                    t ^= d << j
                bytes_t = t.to_bytes(8, byteorder='little')
                for k in range(8):
                    mat[i][block_idx + k] = bytes_t[k]
        return 0

    def pk_gen(self, pk, sk, perm, pi, pivots=None):
        buf = [0] * (1 << self.GFBITS)
        mat = [[0 for _ in range(self.N_BYTES)] for _ in range(self.PK_NROWS)]
        g = [0] * (self.SYS_T + 1)
        l = [0] * self.SYS_N
        inv = [0] * self.SYS_N
        g[self.SYS_T] = 1
        for i in range(self.SYS_T):
            g[i] = self.load_gf(sk[i * 2:(i + 1) * 2])
        for i in range(1 << self.GFBITS):
            buf[i] = perm[i] << 31 | i
        buf.sort()
        for i in range(1, 1 << self.GFBITS):
            if buf[i - 1] >> 31 == buf[i] >> 31:
                return -1
        for i in range(1 << self.GFBITS):
            pi[i] = buf[i] & self.GFMASK
        for i in range(self.SYS_N):
            l[i] = self.bitrev(pi[i])
        self.root(inv, g, l)
        for i in range(self.SYS_N):
            inv[i] = self.gf_inv(inv[i])
        for i in range(self.SYS_T):
            for j in range(0, self.SYS_N, 8):
                for k in range(self.GFBITS):
                    b = 0
                    if j + 7 < self.SYS_N:
                        b = inv[j + 7] >> k & 1
                    b <<= 1
                    if j + 6 < self.SYS_N:
                        b |= inv[j + 6] >> k & 1
                    b <<= 1
                    if j + 5 < self.SYS_N:
                        b |= inv[j + 5] >> k & 1
                    b <<= 1
                    if j + 4 < self.SYS_N:
                        b |= inv[j + 4] >> k & 1
                    b <<= 1
                    if j + 3 < self.SYS_N:
                        b |= inv[j + 3] >> k & 1
                    b <<= 1
                    if j + 2 < self.SYS_N:
                        b |= inv[j + 2] >> k & 1
                    b <<= 1
                    if j + 1 < self.SYS_N:
                        b |= inv[j + 1] >> k & 1
                    b <<= 1
                    b |= inv[j] >> k & 1
                    mat[i * self.GFBITS + k][j // 8] = b
            for j in range(self.SYS_N):
                inv[j] = self.gf_mul(inv[j], l[j])
        rows = (self.PK_NROWS + 7) // 8
        for i in range(rows):
            for j in range(8):
                row = i * 8 + j
                if row >= self.PK_NROWS:
                    break
                if self.variant.endswith('f') and row == self.PK_NROWS - 32:
                    if self.mov_columns(mat, pi, pivots) != 0:
                        return -1
                for k in range(row + 1, self.PK_NROWS):
                    mask = (mat[row][i] ^ mat[k][i]) >> j
                    mask &= 1
                    mask = 0 - mask & 255
                    for c in range(self.N_BYTES):
                        mat[row][c] ^= mat[k][c] & mask
                if mat[row][i] >> j & 1 == 0:
                    return -1
                for k in range(self.PK_NROWS):
                    if k == row:
                        continue
                    mask = mat[k][i] >> j & 1
                    mask = 0 - mask & 255
                    for c in range(self.N_BYTES):
                        mat[k][c] ^= mat[row][c] & mask
        if self.variant in ['mceliece6960119', 'mceliece6960119f']:
            for i in range(self.PK_NROWS):
                start = (self.PK_NROWS - 1) // 8
                for (idx, j) in enumerate(range(start, self.N_BYTES - 1)):
                    pk[i * self.INNER_PK_ACCESSES + idx] = mat[i][j] >> self.tail | mat[i][j + 1] << 8 - self.tail
                pk[(i + 1) * self.INNER_PK_ACCESSES - 1] = mat[i][self.N_BYTES - 1] >> self.tail
        else:
            start_col = self.PK_NROWS // 8
            for i in range(self.PK_NROWS):
                pk[i * self.PK_ROW_BYTES:(i + 1) * self.PK_ROW_BYTES] = mat[i][start_col:start_col + self.PK_ROW_BYTES]
        return 0

    def gen_e(self, e, rng):
        ind = [0] * self.SYS_T
        val = [0] * self.SYS_T
        if self.variant in ['mceliece8192128', 'mceliece8192128f']:
            while True:
                bytes_data = bytearray(rng(self.SYS_T * 2))
                for i in range(self.SYS_T):
                    ind[i] = self.load_gf(bytes_data[i * 2:(i + 1) * 2])
                duplicate = False
                for i in range(1, self.SYS_T):
                    for j in range(i):
                        if ind[i] == ind[j]:
                            duplicate = True
                            break
                    if duplicate:
                        break
                if not duplicate:
                    break
            for j in range(self.SYS_T):
                val[j] = 1 << (ind[j] & 7)
            for i in range(self.N_BYTES):
                e[i] = 0
                for j in range(self.SYS_T):
                    mask = self.same_mask_u8(i, ind[j] >> 3)
                    e[i] |= val[j] & mask
        else:
            while True:
                bytes_data = bytearray(rng(self.SYS_T * 4))
                nums = [0] * (self.SYS_T * 2)
                for i in range(self.SYS_T * 2):
                    nums[i] = self.load_gf(bytes_data[i * 2:(i + 1) * 2])
                count = 0
                for num in nums:
                    if count >= self.SYS_T:
                        break
                    if num < self.SYS_N:
                        ind[count] = num
                        count += 1
                if count < self.SYS_T:
                    continue
                duplicate = False
                for i in range(1, self.SYS_T):
                    for j in range(i):
                        if ind[i] == ind[j]:
                            duplicate = True
                            break
                    if duplicate:
                        break
                if not duplicate:
                    break
            for j in range(self.SYS_T):
                val[j] = 1 << (ind[j] & 7)
            for i in range(len(e)):
                e[i] = 0
                for j in range(self.SYS_T):
                    mask = self.same_mask_u8(i, ind[j] >> 3)
                    e[i] |= val[j] & mask

    def syndrome(self, s, pk, e):
        row = [0] * self.N_BYTES
        pk_segment = bytearray(pk)
        for i in range(self.SYND_BYTES):
            s[i] = 0
        if self.variant in ['mceliece6960119', 'mceliece6960119f']:
            tail = self.PK_NROWS % 8
            for i in range(self.PK_NROWS):
                for j in range(self.N_BYTES):
                    row[j] = 0
                for j in range(self.PK_ROW_BYTES):
                    if j < len(pk_segment):
                        row[self.N_BYTES - self.PK_ROW_BYTES + j] = pk_segment[j]
                for j in range(self.N_BYTES - self.PK_ROW_BYTES, self.N_BYTES - 1):
                    row[j] = row[j] << tail | row[j - 1] >> 8 - tail
                row[i // 8] |= 1 << i % 8
                b = 0
                for j in range(self.N_BYTES):
                    b ^= row[j] & e[j]
                b ^= b >> 4
                b ^= b >> 2
                b ^= b >> 1
                b &= 1
                s[i // 8] |= b << i % 8
                pk_segment = pk_segment[self.PK_ROW_BYTES:]
        else:
            for i in range(self.PK_NROWS):
                for j in range(self.N_BYTES):
                    row[j] = 0
                for j in range(self.PK_ROW_BYTES):
                    if j < len(pk_segment):
                        row[self.N_BYTES - self.PK_ROW_BYTES + j] = pk_segment[j]
                row[i // 8] |= 1 << i % 8
                b = 0
                for j in range(self.N_BYTES):
                    b ^= row[j] & e[j]
                b ^= b >> 4
                b ^= b >> 2
                b ^= b >> 1
                b &= 1
                s[i // 8] |= b << i % 8
                pk_segment = pk_segment[self.PK_ROW_BYTES:]

    def encrypt(self, s, pk, e, rng):
        self.gen_e(e, rng)
        self.syndrome(s, pk, e)

    def bm(self, out, s):
        l = 0
        c = [0] * (self.SYS_T + 1)
        b = [0] * (self.SYS_T + 1)
        base = 1
        b[1] = 1
        c[0] = 1
        for n in range(2 * self.SYS_T):
            d = 0
            max_i = min(n, self.SYS_T)
            for i in range(max_i + 1):
                d ^= self.gf_mul(c[i], s[n - i])
            mne = d
            mne = mne - 1 & 65535
            mne >>= 15
            mne = mne - 1 & 65535
            mle = n - 2 * l & 65535
            mle >>= 15
            mle = mle - 1 & 65535
            mle &= mne
            t = c.copy()
            f = self.gf_frac(base, d)
            for i in range(self.SYS_T + 1):
                c[i] ^= self.gf_mul(f, b[i]) & mne
            l = l & ~mle | n + 1 - l & mle
            for i in range(self.SYS_T + 1):
                b[i] = b[i] & ~mle | t[i] & mle
            base = base & ~mle | d & mle
            for i in range(self.SYS_T, 0, -1):
                b[i] = b[i - 1]
            b[0] = 0
        for i in range(self.SYS_T + 1):
            out[i] = c[self.SYS_T - i]

    def transpose(self, output, input_matrix):
        masks = [[6148914691236517205, 12297829382473034410], [3689348814741910323, 14757395258967641292], [1085102592571150095, 17361641481138401520], [71777214294589695, 18374966859414961920], [281470681808895, 18446462603027742720], [4294967295, 18446744069414584320]]
        for i in range(64):
            output[i] = input_matrix[i]
        for d in reversed(range(6)):
            s = 1 << d
            i = 0
            while i < 64:
                for j in range(i, i + s):
                    x = output[j] & masks[d][0] | (output[j + s] & masks[d][0]) << s
                    y = (output[j] & masks[d][1]) >> s | output[j + s] & masks[d][1]
                    output[j] = x
                    output[j + s] = y
                i += s * 2

    def transpose_64x64_inplace(self, arg):
        if self.variant not in ['mceliece348864', 'mceliece348864f']:
            raise NotImplementedError('`transpose_64x64_inplace` applies only to mceliece348864 and its f variant')
        masks = [[6148914691236517205, 12297829382473034410], [3689348814741910323, 14757395258967641292], [1085102592571150095, 17361641481138401520], [71777214294589695, 18374966859414961920], [281470681808895, 18446462603027742720], [4294967295, 18446744069414584320]]
        for d in reversed(range(6)):
            s = 1 << d
            i = 0
            while i < 64:
                for j in range(i, i + s):
                    x = arg[j] & masks[d][0] | (arg[j + s] & masks[d][0]) << s
                    y = (arg[j] & masks[d][1]) >> s | arg[j + s] & masks[d][1]
                    arg[j] = x
                    arg[j + s] = y
                i += s * 2

    def layer(self, data, bits, lgs):
        if self.variant not in ['mceliece348864', 'mceliece348864f']:
            raise NotImplementedError('The `layer` function is only applicable to mceliece348864 and its f variant.')
        index = 0
        s = 1 << lgs
        i = 0
        while i < 64:
            for j in range(i, i + s):
                d = data[j] ^ data[j + s]
                d &= bits[index]
                index += 1
                data[j] ^= d
                data[j + s] ^= d
            i += s * 2

    def layer_in(self, data, bits, lgs):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            raise NotImplementedError('The `layer_in` function is not applicable to mceliece348864 and its f variant')
        index = 0
        s = 1 << lgs
        i = 0
        while i < 64:
            for j in range(i, i + s):
                d = data[0][j] ^ data[0][j + s]
                d &= bits[index]
                index += 1
                data[0][j] ^= d
                data[0][j + s] ^= d
                d = data[1][j] ^ data[1][j + s]
                d &= bits[index]
                index += 1
                data[1][j] ^= d
                data[1][j + s] ^= d
            i += s * 2

    def layer_ex(self, data, bits, lgs):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            raise NotImplementedError('The `layer_ex` function is not applicable to mceliece348864 and its f variants')
        data0_idx = 0
        data1_idx = 32
        s = 1 << lgs
        if s == 64:
            for j in range(64):
                d = data[0][j] ^ data[1][j]
                d &= bits[data0_idx]
                data0_idx += 1
                data[0][j] ^= d
                data[1][j] ^= d
        else:
            i = 0
            while i < 64:
                for j in range(i, i + s):
                    d = data[0][j] ^ data[0][j + s]
                    d &= bits[data0_idx]
                    data0_idx += 1
                    data[0][j] ^= d
                    data[0][j + s] ^= d
                    d = data[1][j] ^ data[1][j + s]
                    d &= bits[data1_idx]
                    data1_idx += 1
                    data[1][j] ^= d
                    data[1][j + s] ^= d
                i += s * 2

    def apply_benes(self, r, bits, rev):
        if self.variant in ['mceliece348864', 'mceliece348864f']:
            self._apply_benes_348864(r, bits, rev)
        else:
            self._apply_benes_other(r, bits, rev)

    def _apply_benes_348864(self, r, bits, rev):
        bs = [0] * 64
        cond = [0] * 64
        if rev == 0:
            for i in range(64):
                start = i * 8
                end = start + 8
                bs[i] = int.from_bytes(r[start:end], byteorder='little')
            self.transpose_64x64_inplace(bs)
            for low in range(6):
                for i in range(64):
                    start = low * 256 + i * 4
                    end = start + 4
                    cond[i] = int.from_bytes(bits[start:end], byteorder='little') & 4294967295
                self.transpose_64x64_inplace(cond)
                self.layer(bs, cond, low)
            self.transpose_64x64_inplace(bs)
            for low in range(6):
                for i in range(32):
                    start = (low + 6) * 256 + i * 8
                    end = start + 8
                    cond[i] = int.from_bytes(bits[start:end], byteorder='little')
                self.layer(bs, cond[:32], low)
            for low in reversed(range(5)):
                for i in range(32):
                    start = (4 - low + 6 + 6) * 256 + i * 8
                    end = start + 8
                    cond[i] = int.from_bytes(bits[start:end], byteorder='little')
                self.layer(bs, cond[:32], low)
            self.transpose_64x64_inplace(bs)
            for low in reversed(range(6)):
                for i in range(64):
                    start = (5 - low + 6 + 6 + 5) * 256 + i * 4
                    end = start + 4
                    cond[i] = int.from_bytes(bits[start:end], byteorder='little') & 4294967295
                self.transpose_64x64_inplace(cond)
                self.layer(bs, cond, low)
            self.transpose_64x64_inplace(bs)
            for i in range(64):
                start = i * 8
                end = start + 8
                r[start:end] = bs[i].to_bytes(8, byteorder='little')
        else:
            for i in range(64):
                start = i * 8
                end = start + 8
                bs[i] = int.from_bytes(r[start:end], byteorder='little')
            self.transpose_64x64_inplace(bs)
            for low in range(6):
                start_base = (2 * self.GFBITS - 2) * 256 - low * 256
                for i in range(64):
                    start = start_base + i * 4
                    end = start + 4
                    cond[i] = int.from_bytes(bits[start:end], byteorder='little') & 4294967295
                self.transpose_64x64_inplace(cond)
                self.layer(bs, cond, low)
            self.transpose_64x64_inplace(bs)
            for low in range(6):
                start_base = (2 * self.GFBITS - 2 - 6) * 256 - low * 256
                for i in range(32):
                    start = start_base + i * 8
                    end = start + 8
                    cond[i] = int.from_bytes(bits[start:end], byteorder='little')
                self.layer(bs, cond[:32], low)
            for low in reversed(range(5)):
                start_base = (2 * self.GFBITS - 2 - 6 - 6) * 256 - (4 - low) * 256
                for i in range(32):
                    start = start_base + i * 8
                    end = start + 8
                    cond[i] = int.from_bytes(bits[start:end], byteorder='little')
                self.layer(bs, cond[:32], low)
            self.transpose_64x64_inplace(bs)
            for low in reversed(range(6)):
                start_base = (2 * self.GFBITS - 2 - 6 - 6 - 5) * 256 - (5 - low) * 256
                for i in range(64):
                    start = start_base + i * 4
                    end = start + 4
                    cond[i] = int.from_bytes(bits[start:end], byteorder='little') & 4294967295
                self.transpose_64x64_inplace(cond)
                self.layer(bs, cond, low)
            self.transpose_64x64_inplace(bs)
            for i in range(64):
                start = i * 8
                end = start + 8
                r[start:end] = bs[i].to_bytes(8, byteorder='little')

    def _apply_benes_other(self, r, bits, rev):
        r_int_v = [[0] * 64 for _ in range(2)]
        r_int_h = [[0] * 64 for _ in range(2)]
        b_int_v = [0] * 64
        b_int_h = [0] * 64
        calc_index = 0 if rev == 0 else 12288
        for i in range(64):
            start = i * 16
            end = start + 16
            chunk = r[start:end]
            r_int_v[0][i] = int.from_bytes(chunk[:8], byteorder='little')
            r_int_v[1][i] = int.from_bytes(chunk[8:], byteorder='little')
        self.transpose(r_int_h[0], r_int_v[0])
        self.transpose(r_int_h[1], r_int_v[1])
        for iter in range(7):
            start = calc_index
            end = start + 512
            chunk = bits[start:end]
            for i in range(64):
                b_start = i * 8
                b_end = b_start + 8
                b_int_v[i] = int.from_bytes(chunk[b_start:b_end], byteorder='little')
            if rev == 0:
                calc_index += 512
            else:
                calc_index -= 512
            self.transpose(b_int_h, b_int_v)
            self.layer_ex(r_int_h, b_int_h, iter)
        self.transpose(r_int_v[0], r_int_h[0])
        self.transpose(r_int_v[1], r_int_h[1])
        for iter in range(6):
            start = calc_index
            end = start + 512
            chunk = bits[start:end]
            for i in range(64):
                b_start = i * 8
                b_end = b_start + 8
                b_int_v[i] = int.from_bytes(chunk[b_start:b_end], byteorder='little')
            if rev == 0:
                calc_index += 512
            else:
                calc_index -= 512
            self.layer_in(r_int_v, b_int_v, iter)
        for iter in reversed(range(5)):
            start = calc_index
            end = start + 512
            chunk = bits[start:end]
            for i in range(64):
                b_start = i * 8
                b_end = b_start + 8
                b_int_v[i] = int.from_bytes(chunk[b_start:b_end], byteorder='little')
            if rev == 0:
                calc_index += 512
            else:
                calc_index -= 512
            self.layer_in(r_int_v, b_int_v, iter)
        self.transpose(r_int_h[0], r_int_v[0])
        self.transpose(r_int_h[1], r_int_v[1])
        for iter in reversed(range(7)):
            start = calc_index
            end = start + 512
            chunk = bits[start:end]
            for i in range(64):
                b_start = i * 8
                b_end = b_start + 8
                b_int_v[i] = int.from_bytes(chunk[b_start:b_end], byteorder='little')
            if rev == 0 or iter == 0:
                calc_index += 512
            else:
                calc_index -= 512
            self.transpose(b_int_h, b_int_v)
            self.layer_ex(r_int_h, b_int_h, iter)
        self.transpose(r_int_v[0], r_int_h[0])
        self.transpose(r_int_v[1], r_int_h[1])
        for i in range(64):
            start = i * 16
            end = start + 16
            r[start:start + 8] = r_int_v[0][i].to_bytes(8, byteorder='little')
            r[start + 8:end] = r_int_v[1][i].to_bytes(8, byteorder='little')

    def support_gen(self, s, c):
        l = [[0] * ((1 << self.GFBITS) // 8) for _ in range(self.GFBITS)]
        for i in range(1 << self.GFBITS):
            a = self.bitrev(i)
            for j in range(self.GFBITS):
                bit = a >> j & 1
                pos = i % 8
                byte_idx = i // 8
                l[j][byte_idx] |= bit << pos
        for layer_data in l:
            self.apply_benes(layer_data, c, 0)
        for i in range(self.SYS_N):
            s[i] = 0
            for j in reversed(range(self.GFBITS)):
                s[i] <<= 1
                byte_idx = i // 8
                pos = i % 8
                bit = l[j][byte_idx] >> pos & 1
                s[i] |= bit

    def decrypt(self, e, sk, c):
        r = bytearray(self.SYS_N // 8)
        r[:self.SYND_BYTES] = c[:self.SYND_BYTES]
        r[self.SYND_BYTES:] = b'\x00' * (len(r) - self.SYND_BYTES)
        g = [0] * (self.SYS_T + 1)
        l = [0] * self.SYS_N
        s = [0] * (self.SYS_T * 2)
        s_cmp = [0] * (self.SYS_T * 2)
        locator = [0] * (self.SYS_T + 1)
        images = [0] * self.SYS_N
        for i in range(self.SYS_T):
            start = i * 2
            end = start + 2
            g[i] = self.load_gf(sk[start:end])
        g[self.SYS_T] = 1
        self.support_gen(l, sk[self.IRR_BYTES:self.IRR_BYTES + self.COND_BYTES])
        self.synd(s, g, l, r)
        self.bm(locator, s)
        self.root(images, locator, l)
        e[:] = b'\x00' * len(e)
        w = 0
        for i in range(self.SYS_N):
            t = self.gf_iszero(images[i]) & 1
            byte_idx = i // 8
            pos = i % 8
            e[byte_idx] |= t << pos
            w += t
        self.synd(s_cmp, g, l, e)
        check = w ^ self.SYS_T
        for i in range(self.SYS_T * 2):
            check |= s[i] ^ s_cmp[i]
        check = check - 1 >> 15
        return (check ^ 1) & 1

    def int32_sort(self, arr):
        arr.sort(key=lambda x: self.int32(x))
        return arr

    def controlbits_layer(self, p, cb, s, n):
        stride = 1 << s
        index = 0
        for i in range(0, n, stride * 2):
            for j in range(i, i + stride):
                if j + stride >= len(p):
                    continue
                cb_byte = index // 8
                cb_bit = index % 8
                if cb_byte >= len(cb):
                    m = 0
                else:
                    m = cb[cb_byte] >> cb_bit & 1
                m = -m
                d = p[j] ^ p[j + stride]
                d &= m
                p[j] ^= d
                p[j + stride] ^= d
                index += 1

    def int32(self, x):
        x = x & 4294967295
        if x & 2147483648:
            return x - 4294967296
        return x

    def uint32(self, x):
        return x & 4294967295

    def cbrecursion(self, out, pos, step, pi_offset, w, n, temp, aux):
        if w == 1:
            if pi_offset == 0:
                first = aux[0]
            else:
                first = temp[pi_offset]
            bit = first & 1
            byte_idx = pos // 8
            bit_idx = pos & 7
            out[byte_idx] ^= bit << bit_idx & 255
            return
        for x in range(n):
            if pi_offset == 0:
                perm = aux[pi_offset + x // 2]
            else:
                perm = temp[pi_offset + x // 2]
            perm = self.uint32(perm)
            low = perm & 65535
            high = perm >> 16 & 65535
            if x % 2 == 0:
                temp[x] = self.int32((low ^ 1) << 16 | high)
            else:
                temp[x] = self.int32((high ^ 1) << 16 | low)
        temp[:n] = self.int32_sort(temp[:n])
        for x in range(n):
            ax = self.uint32(temp[x])
            px = ax & 65535
            cx = px
            if x < cx:
                cx = x
            temp[n + x] = self.int32(px << 16 | cx)
        for x in range(n):
            temp[x] = self.int32(self.uint32(temp[x]) << 16 | x)
        temp[:n] = self.int32_sort(temp[:n])
        for x in range(n):
            left_part = self.uint32(temp[x]) << 16
            right_part = self.uint32(temp[n + x]) >> 16
            temp[x] = self.int32(left_part + right_part)
        temp[:n] = self.int32_sort(temp[:n])
        if w <= 10:
            for x in range(n):
                left_part = (self.uint32(temp[x]) & 65535) << 10
                right_part = self.uint32(temp[n + x]) & 1023
                temp[n + x] = self.int32(left_part | right_part)
            for _ in range(1, w - 1):
                for x in range(n):
                    left_part = (self.uint32(temp[n + x]) & 16777212 << 8) << 6
                    temp[x] = self.int32(left_part | x)
                temp[:n] = self.int32_sort(temp[:n])
                for x in range(n):
                    left_part = self.uint32(temp[x]) << 20
                    temp[x] = self.int32(left_part | self.uint32(temp[n + x]))
                temp[:n] = self.int32_sort(temp[:n])
                for x in range(n):
                    ppcpx = self.uint32(temp[x]) & 1048575
                    ppcx = self.uint32(temp[x]) & 1047552 | self.uint32(temp[n + x]) & 1023
                    if ppcpx < ppcx:
                        ppcx = ppcpx
                    temp[n + x] = self.int32(ppcx)
            for x in range(n):
                temp[n + x] = self.int32(self.uint32(temp[n + x]) & 1023)
        else:
            for x in range(n):
                left_part = self.uint32(temp[x]) << 16
                right_part = self.uint32(temp[n + x]) & 65535
                temp[n + x] = self.int32(left_part | right_part)
            for i in range(1, w - 1):
                for x in range(n):
                    left_part = self.uint32(temp[n + x]) & 65535 << 16
                    temp[x] = self.int32(left_part | x)
                temp[:n] = self.int32_sort(temp[:n])
                for x in range(n):
                    left_part = self.uint32(temp[x]) << 16
                    right_part = self.uint32(temp[n + x]) & 65535
                    temp[x] = self.int32(left_part | right_part)
                if i < w - 2:
                    for x in range(n):
                        left_part = self.uint32(temp[x]) & 65535 << 16
                        right_part = self.uint32(temp[n + x]) >> 16
                        temp[n + x] = self.int32(left_part | right_part)
                    temp[n:2 * n] = self.int32_sort(temp[n:2 * n])
                    for x in range(n):
                        left_part = self.uint32(temp[n + x]) << 16
                        right_part = self.uint32(temp[x]) & 65535
                        temp[n + x] = self.int32(left_part | right_part)
                temp[:n] = self.int32_sort(temp[:n])
                for x in range(n):
                    cpx_left = self.uint32(temp[n + x]) & 65535 << 16
                    cpx_right = self.uint32(temp[x]) & 65535
                    cpx = self.int32(cpx_left | cpx_right)
                    if cpx < temp[n + x]:
                        temp[n + x] = cpx
            for x in range(n):
                temp[n + x] = self.int32(self.uint32(temp[n + x]) & 65535)
        for x in range(n):
            if pi_offset == 0:
                perm = aux[pi_offset + x // 2]
            else:
                perm = temp[pi_offset + x // 2]
            perm = self.uint32(perm)
            if x % 2 == 0:
                temp[x] = self.int32(((perm & 65535) << 16) + x)
            else:
                temp[x] = self.int32((perm & 65535 << 16) + x)
        temp[:n] = self.int32_sort(temp[:n])
        for j in range(n // 2):
            x = 2 * j
            fj = self.uint32(temp[n + x]) & 1
            fx = x + fj
            fx1 = fx ^ 1
            out[pos // 8] ^= fj << (pos & 7) & 255
            pos += step
            temp[n + x] = self.int32(self.uint32(temp[x]) << 16 | fx)
            temp[n + x + 1] = self.int32(self.uint32(temp[x + 1]) << 16 | fx1)
        temp[n:2 * n] = self.int32_sort(temp[n:2 * n])
        pos += (2 * w - 3) * step * (n // 2)
        for k in range(n // 2):
            y = 2 * k
            lk = self.uint32(temp[n + y]) & 1
            ly = y + lk
            ly1 = ly ^ 1
            out[pos // 8] ^= lk << (pos & 7) & 255
            pos += step
            temp[y] = self.int32(ly << 16 | self.uint32(temp[n + y]) & 65535)
            temp[y + 1] = self.int32(ly1 << 16 | self.uint32(temp[n + y + 1]) & 65535)
        temp[:n] = self.int32_sort(temp[:n])
        pos -= (2 * w - 2) * step * (n // 2)
        for j in range(n // 2):
            if j % 2 == 0:
                idx1 = n + n // 4 + j // 2
                idx2 = n + n // 4 + (j + n // 2) // 2
                temp[idx1] = self.int32(self.uint32(temp[idx1]) & 65535 << 16 | (self.uint32(temp[2 * j]) & 65535) >> 1)
                temp[idx2] = self.int32(self.uint32(temp[idx2]) & 65535 << 16 | (self.uint32(temp[2 * j + 1]) & 65535) >> 1)
            else:
                idx1 = n + n // 4 + j // 2
                idx2 = n + n // 4 + (j + n // 2) // 2
                temp[idx1] = self.int32(self.uint32(temp[idx1]) & 65535 | (self.uint32(temp[2 * j]) & 65534) << 15)
                temp[idx2] = self.int32(self.uint32(temp[idx2]) & 65535 | (self.uint32(temp[2 * j + 1]) & 65534) << 15)
        self.cbrecursion(out, pos, step * 2, n + n // 4, w - 1, n // 2, temp, aux)
        self.cbrecursion(out, pos + step, step * 2, n + n // 2, w - 1, n // 2, temp, aux)

    def controlbitsfrompermutation(self, out, pi, w, n):
        assert n == 1 << w, f'n must be 2 to the power of {w}'
        assert len(pi) == n, f'The length of pi must be {n}'
        expected_out_len = ((2 * w - 1) * n // 2 + 7) // 8
        assert len(out) >= expected_out_len, f'The length of out must be at least {expected_out_len}'
        temp_size = 2 * (1 << self.GFBITS)
        temp = [0] * temp_size
        pi_as_i32 = [0] * (1 << self.GFBITS - 1)
        for i in range(1 << self.GFBITS - 1):
            pi_as_i32[i] = pi[2 * i] | pi[2 * i + 1] << 16
        sub = out
        diff = 1
        while diff != 0:
            for i in range(len(sub)):
                sub[i] = 0
            self.cbrecursion(sub, 0, 1, 0, w, n, temp, pi_as_i32)
            pi_test = list(range(n))
            for i in range(w):
                self.controlbits_layer(pi_test, sub, i, n)
                sub = sub[n >> 4:]
            for i in reversed(range(w - 1)):
                self.controlbits_layer(pi_test, sub, i, n)
                sub = sub[n >> 4:]
            diff = 0
            for i in range(n):
                diff |= pi[i] ^ pi_test[i]
            if diff != 0:
                sub = out

class CryptoBytes:
    CRYPTO_BYTES = 32

    @classmethod
    def get_public_key_bytes(cls, variant):
        variants = {'mceliece348864': 261120, 'mceliece348864f': 261120, 'mceliece460896': 524160, 'mceliece460896f': 524160, 'mceliece6688128': 1044992, 'mceliece6688128f': 1044992, 'mceliece6960119': 1047319, 'mceliece6960119f': 1047319, 'mceliece8192128': 1357824, 'mceliece8192128f': 1357824}
        return variants.get(variant, 0)

    @classmethod
    def get_secret_key_bytes(cls, variant):
        variants = {'mceliece348864': 6492, 'mceliece348864f': 6492, 'mceliece460896': 13608, 'mceliece460896f': 13608, 'mceliece6688128': 13932, 'mceliece6688128f': 13932, 'mceliece6960119': 13948, 'mceliece6960119f': 13948, 'mceliece8192128': 14120, 'mceliece8192128f': 14120}
        return variants.get(variant, 0)

    @classmethod
    def get_ciphertext_bytes(cls, variant):
        variants = {'mceliece348864': 96, 'mceliece348864f': 96, 'mceliece460896': 156, 'mceliece460896f': 156, 'mceliece6688128': 208, 'mceliece6688128f': 208, 'mceliece6960119': 194, 'mceliece6960119f': 194, 'mceliece8192128': 208, 'mceliece8192128f': 208}
        return variants.get(variant, 0)

class PublicKey:
    def __init__(self, variant, data):
        self.variant = variant
        expected_length = CryptoBytes.get_public_key_bytes(variant)
        if len(data) != expected_length:
            raise ValueError(f'Public key length mismatch variant {variant}: expected {expected_length}, actual {len(data)}')
        self.data = data

    def as_bytes(self):
        return self.data

    def __repr__(self):
        return f'PublicKey(variant={self.variant}, length={len(self.data)})'

class SecretKey:
    def __init__(self, variant, data):
        self.variant = variant
        expected_length = CryptoBytes.get_secret_key_bytes(variant)
        if len(data) != expected_length:
            raise ValueError(f'Private key length mismatch variant {variant}: expected {expected_length}, actual {len(data)}')
        self.data = data

    def as_bytes(self):
        return self.data

    def __repr__(self):
        return f'SecretKey(variant={self.variant}, length={len(self.data)})'

class Ciphertext:
    def __init__(self, variant, data):
        self.variant = variant
        expected_length = CryptoBytes.get_ciphertext_bytes(variant)
        if len(data) != expected_length:
            raise ValueError(f'Ciphertext length mismatch variant: {expected_length}, actual {len(data)}')
        self.data = data

    def as_bytes(self):
        return self.data

    @classmethod
    def from_bytes(cls, variant, data):
        return cls(variant, data)

    def __repr__(self):
        return f'Ciphertext(variant={self.variant}, length={len(self.data)})'

class SharedSecret:
    def __init__(self, data):
        if len(data) != CryptoBytes.CRYPTO_BYTES:
            raise ValueError(f'SharedSecret length mismatch variant: expected {CryptoBytes.CRYPTO_BYTES}, actual {len(data)}')
        self.data = data

    def as_bytes(self):
        return self.data

    def __repr__(self):
        return 'SharedSecret(redacted)'

class ClassicMcElieceKEM:
    def __init__(self, variant):
        self.variant = variant
        self.cme = ClassicMcEliece(variant)
        self.CRYPTO_BYTES = CryptoBytes.CRYPTO_BYTES
        self.CRYPTO_PUBLICKEYBYTES = self.cme.CRYPTO_PUBLICKEYBYTES
        self.CRYPTO_SECRETKEYBYTES = self.cme.CRYPTO_SECRETKEYBYTES
        self.CRYPTO_CIPHERTEXTBYTES = self.cme.CRYPTO_CIPHERTEXTBYTES
        self.SYS_N = self.cme.SYS_N
        self.SYND_BYTES = self.cme.SYND_BYTES
        self.IRR_BYTES = self.cme.IRR_BYTES
        self.COND_BYTES = self.cme.COND_BYTES
        self.is_6960119 = variant in ['mceliece6960119', 'mceliece6960119f']
        if self.is_6960119:
            self.PK_NCOLS = self.cme.PK_NCOLS
            self.PK_NROWS = self.cme.PK_NROWS
            self.PK_ROW_BYTES = self.cme.PK_ROW_BYTES

    def _check_pk_padding(self, pk):
        if not self.is_6960119:
            return 0
        b = 0
        for i in range(self.PK_NROWS):
            pos = i * self.PK_ROW_BYTES + self.PK_ROW_BYTES - 1
            if pos < len(pk):
                b |= pk[pos]
        b >>= self.PK_NCOLS % 8
        b = b - 1 & 255
        b >>= 7
        b = b - 1 & 255
        return b

    def _check_c_padding(self, c):
        if not self.is_6960119:
            return 0
        if len(c) < self.SYND_BYTES:
            return 0
        b = c[self.SYND_BYTES - 1] >> self.PK_NROWS % 8
        b = b - 1 & 255
        b >>= 7
        b = b - 1 & 255
        return b

    def keypair(self, rng=None):
        if rng is None:
            rng = os.urandom
        pk_bytes = bytearray(self.CRYPTO_PUBLICKEYBYTES)
        sk_bytes = bytearray(self.CRYPTO_SECRETKEYBYTES)
        seed = bytearray(33)
        seed[0] = 64
        seed[1:] = rng(32)
        S_BASE = 32 + 8 + self.IRR_BYTES + self.COND_BYTES
        SEED_LENGTH = self.SYS_N // 8 + (1 << self.cme.GFBITS) * 4 + self.cme.SYS_T * 2
        IRR_POLYS_LENGTH = self.SYS_N // 8 + (1 << self.cme.GFBITS) * 4
        PERM_LENGTH = self.SYS_N // 8
        f = [0] * self.cme.SYS_T
        irr = [0] * self.cme.SYS_T
        perm = [0] * (1 << self.cme.GFBITS)
        pi = [0] * (1 << self.cme.GFBITS)
        pivots = 0
        while True:
            shake = hashlib.shake_256()
            shake.update(seed)
            r = bytearray(shake.digest(SEED_LENGTH + 32))
            sk_bytes[:32] = seed[1:]
            seed[1:] = r[-32:]
            poly_data = r[IRR_POLYS_LENGTH:IRR_POLYS_LENGTH + self.cme.SYS_T * 2]
            for i in range(self.cme.SYS_T):
                f[i] = self.cme.load_gf(poly_data[i * 2:(i + 1) * 2])
            if self.cme.genpoly_gen(irr, f) != 0:
                continue
            for i in range(self.cme.SYS_T):
                sk_bytes[40 + i * 2:40 + (i + 1) * 2] = self.cme.store_gf(irr[i])
            perm_data = r[PERM_LENGTH:PERM_LENGTH + (1 << self.cme.GFBITS) * 4]
            for i in range(1 << self.cme.GFBITS):
                perm[i] = int.from_bytes(perm_data[i * 4:(i + 1) * 4], byteorder='little')
            pk_gen_result = -1
            if self.variant.endswith('f'):
                pk_gen_result = self.cme.pk_gen(pk_bytes, sk_bytes[40:40 + self.IRR_BYTES], perm, pi, [pivots])
            else:
                pk_gen_result = self.cme.pk_gen(pk_bytes, sk_bytes[40:40 + self.IRR_BYTES], perm, pi)
            if pk_gen_result != 0:
                continue
            cond_bytes = bytearray(self.COND_BYTES)
            self.cme.controlbitsfrompermutation(cond_bytes, pi, self.cme.GFBITS, 1 << self.cme.GFBITS)
            sk_bytes[40 + self.IRR_BYTES:40 + self.IRR_BYTES + self.COND_BYTES] = cond_bytes
            sk_bytes[S_BASE:S_BASE + self.SYS_N // 8] = r[:self.SYS_N // 8]
            if not self.variant.endswith('f'):
                pivots = 4294967295
            sk_bytes[32:40] = pivots.to_bytes(8, byteorder='little')
            break
        return (PublicKey(self.variant, bytes(pk_bytes)), SecretKey(self.variant, bytes(sk_bytes)))

    def encapsulate(self, pk, rng=None):
        if rng is None:
            rng = os.urandom
        if pk.variant != self.variant:
            raise ValueError(f'Public key variant mismatch: expected {self.variant}, got {pk.variant}')
        c_bytes = bytearray(self.CRYPTO_CIPHERTEXTBYTES)
        e = bytearray(self.SYS_N // 8)
        one_ec = bytearray(1 + self.SYS_N // 8 + self.SYND_BYTES)
        one_ec[0] = 1
        padding_ok = 0
        if self.is_6960119:
            padding_ok = self._check_pk_padding(pk.as_bytes())
        self.cme.encrypt(c_bytes, pk.as_bytes(), e, rng)
        one_ec[1:1 + self.SYS_N // 8] = e
        one_ec[1 + self.SYS_N // 8:1 + self.SYS_N // 8 + self.SYND_BYTES] = c_bytes[:self.SYND_BYTES]
        shake = hashlib.shake_256()
        shake.update(one_ec)
        key = bytearray(shake.digest(self.CRYPTO_BYTES))
        if self.is_6960119:
            mask = (padding_ok ^ 255) & 255
            for i in range(self.SYND_BYTES):
                c_bytes[i] &= mask
            for i in range(self.CRYPTO_BYTES):
                key[i] &= mask
        return (Ciphertext(self.variant, bytes(c_bytes)), SharedSecret(bytes(key)))

    def decapsulate(self, c, sk):
        if c.variant != self.variant:
            raise ValueError(f'Ciphertext variant mismatch: expected {self.variant}, got {c.variant}')
        if sk.variant != self.variant:
            raise ValueError(f'Private key variant mismatch: expected {self.variant}, got {sk.variant}')
        e = bytearray(self.SYS_N // 8)
        preimage = bytearray(1 + self.SYS_N // 8 + self.SYND_BYTES)
        padding_ok = 0
        if self.is_6960119:
            padding_ok = self._check_c_padding(c.as_bytes())
        sk_data = sk.as_bytes()
        ret_decrypt = self.cme.decrypt(e, sk_data[40:40 + self.IRR_BYTES + self.COND_BYTES], c.as_bytes()[:self.SYND_BYTES])
        m = ret_decrypt - 1 & 65535
        m >>= 8
        preimage[0] = (m & 1).to_bytes(1, byteorder='little')[0]
        s_start = 40 + self.IRR_BYTES + self.COND_BYTES
        s = sk_data[s_start:s_start + self.SYS_N // 8]
        for i in range(self.SYS_N // 8):
            preimage[1 + i] = ~m & s[i] | m & e[i]
        preimage[1 + self.SYS_N // 8:1 + self.SYS_N // 8 + self.SYND_BYTES] = c.as_bytes()[:self.SYND_BYTES]
        shake = hashlib.shake_256()
        shake.update(preimage)
        key = bytearray(shake.digest(self.CRYPTO_BYTES))
        if self.is_6960119:
            mask = padding_ok & 255
            for i in range(self.CRYPTO_BYTES):
                key[i] |= mask
        return SharedSecret(bytes(key))

def keypair(variant, rng=None):
    kem = ClassicMcElieceKEM(variant)
    return kem.keypair(rng)

def encapsulate(variant, pk, rng=None):
    kem = ClassicMcElieceKEM(variant)
    return kem.encapsulate(pk, rng)

def decapsulate(variant, c, sk):
    kem = ClassicMcElieceKEM(variant)
    return kem.decapsulate(c, sk)
