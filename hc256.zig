// Copyright 2021 Quentin K
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const std = @import("std");

const Table = [1024]u32;

const buffer_size = 16 * 4;

pub const Hc256 = struct {
    ptable: Table,
    qtable: Table,
    buffer: [buffer_size]u8 = [_]u8{0} ** buffer_size,
    ctr: usize = 0,
    ptr: usize = 0,

    /// Initialize the cipher with the key and iv
    pub fn init(
        key: [32]u8,
        iv: [32]u8,
    ) Hc256 {
        var cipher = Hc256{
            .ptable = undefined,
            .qtable = undefined,
        };
        var w: [2560]u32 = undefined;

        var i: u32 = 0;
        while (i < 8) : (i += 1) {
            w[i] = @as(u32, key[i * 4]) | (@as(u32, key[(i * 4) + 1]) << 8) | (@as(u32, key[(i * 4) + 2]) << 16) | (@as(u32, key[(i * 4) + 3]) << 24);
            w[i + 8] = @as(u32, iv[i * 4]) | (@as(u32, iv[(i * 4) + 1]) << 8) | (@as(u32, iv[(i * 4) + 2]) << 16) | (@as(u32, iv[(i * 4) + 3]) << 24);
        }

        i = 16;
        while (i < 2560) : (i += 1) w[i] = f2(w[i - 2]) +% w[i - 7] +% f1(w[i - 15]) +% w[i - 16] +% i;

        std.mem.copy(u32, &cipher.ptable, w[512..(512 + 1024)]);
        std.mem.copy(u32, &cipher.qtable, w[1536..(1536 + 1024)]);

        i = 0;
        while (i < 4096) : (i += 16) _ = cipher.genWord16();

        return cipher;
    }

    /// Applies the keystream from the cipher to the given bytes in place
    pub fn applyStream(self: *Hc256, data: []u8) void {
        for (data) |_, i| {
            defer self.ptr = (self.ptr + 1) % buffer_size;
            if (self.ptr == 0) self.buffer = @bitCast([buffer_size]u8, self.genWord16());
            data[i] ^= self.buffer[self.ptr];
        }
    }

    /// Generates the next word from the cipher
    pub fn genWord16(self: *Hc256) [16]u32 {
        defer self.ctr = (self.ctr + 16) & 2047;
        if (self.ctr < 1024) {
            self.ptable[(self.ctr + 0) & 1023] = self.ptable[(self.ctr + 0) & 1023] +% self.ptable[((self.ctr + 0) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 0) -% 3) & 1023], self.ptable[((self.ctr + 0) -% 1023) & 1023]);
            self.ptable[(self.ctr + 1) & 1023] = self.ptable[(self.ctr + 1) & 1023] +% self.ptable[((self.ctr + 1) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 1) -% 3) & 1023], self.ptable[((self.ctr + 1) -% 1023) & 1023]);
            self.ptable[(self.ctr + 2) & 1023] = self.ptable[(self.ctr + 2) & 1023] +% self.ptable[((self.ctr + 2) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 2) -% 3) & 1023], self.ptable[((self.ctr + 2) -% 1023) & 1023]);
            self.ptable[(self.ctr + 3) & 1023] = self.ptable[(self.ctr + 3) & 1023] +% self.ptable[((self.ctr + 3) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 3) -% 3) & 1023], self.ptable[((self.ctr + 3) -% 1023) & 1023]);
            self.ptable[(self.ctr + 4) & 1023] = self.ptable[(self.ctr + 4) & 1023] +% self.ptable[((self.ctr + 4) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 4) -% 3) & 1023], self.ptable[((self.ctr + 4) -% 1023) & 1023]);
            self.ptable[(self.ctr + 5) & 1023] = self.ptable[(self.ctr + 5) & 1023] +% self.ptable[((self.ctr + 5) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 5) -% 3) & 1023], self.ptable[((self.ctr + 5) -% 1023) & 1023]);
            self.ptable[(self.ctr + 6) & 1023] = self.ptable[(self.ctr + 6) & 1023] +% self.ptable[((self.ctr + 6) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 6) -% 3) & 1023], self.ptable[((self.ctr + 6) -% 1023) & 1023]);
            self.ptable[(self.ctr + 7) & 1023] = self.ptable[(self.ctr + 7) & 1023] +% self.ptable[((self.ctr + 7) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 7) -% 3) & 1023], self.ptable[((self.ctr + 7) -% 1023) & 1023]);
            self.ptable[(self.ctr + 8) & 1023] = self.ptable[(self.ctr + 8) & 1023] +% self.ptable[((self.ctr + 8) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 8) -% 3) & 1023], self.ptable[((self.ctr + 8) -% 1023) & 1023]);
            self.ptable[(self.ctr + 9) & 1023] = self.ptable[(self.ctr + 9) & 1023] +% self.ptable[((self.ctr + 9) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 9) -% 3) & 1023], self.ptable[((self.ctr + 9) -% 1023) & 1023]);
            self.ptable[(self.ctr + 10) & 1023] = self.ptable[(self.ctr + 10) & 1023] +% self.ptable[((self.ctr + 10) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 10) -% 3) & 1023], self.ptable[((self.ctr + 10) -% 1023) & 1023]);
            self.ptable[(self.ctr + 11) & 1023] = self.ptable[(self.ctr + 11) & 1023] +% self.ptable[((self.ctr + 11) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 11) -% 3) & 1023], self.ptable[((self.ctr + 11) -% 1023) & 1023]);
            self.ptable[(self.ctr + 12) & 1023] = self.ptable[(self.ctr + 12) & 1023] +% self.ptable[((self.ctr + 12) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 12) -% 3) & 1023], self.ptable[((self.ctr + 12) -% 1023) & 1023]);
            self.ptable[(self.ctr + 13) & 1023] = self.ptable[(self.ctr + 13) & 1023] +% self.ptable[((self.ctr + 13) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 13) -% 3) & 1023], self.ptable[((self.ctr + 13) -% 1023) & 1023]);
            self.ptable[(self.ctr + 14) & 1023] = self.ptable[(self.ctr + 14) & 1023] +% self.ptable[((self.ctr + 14) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 14) -% 3) & 1023], self.ptable[((self.ctr + 14) -% 1023) & 1023]);
            self.ptable[(self.ctr + 15) & 1023] = self.ptable[(self.ctr + 15) & 1023] +% self.ptable[((self.ctr + 15) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + 15) -% 3) & 1023], self.ptable[((self.ctr + 15) -% 1023) & 1023]);
            return [16]u32{
                self.h1(self.ptable[((self.ctr + 0) -% 12) & 1023]) ^ self.ptable[(self.ctr + 0) & 1023],
                self.h1(self.ptable[((self.ctr + 1) -% 12) & 1023]) ^ self.ptable[(self.ctr + 1) & 1023],
                self.h1(self.ptable[((self.ctr + 2) -% 12) & 1023]) ^ self.ptable[(self.ctr + 2) & 1023],
                self.h1(self.ptable[((self.ctr + 3) -% 12) & 1023]) ^ self.ptable[(self.ctr + 3) & 1023],
                self.h1(self.ptable[((self.ctr + 4) -% 12) & 1023]) ^ self.ptable[(self.ctr + 4) & 1023],
                self.h1(self.ptable[((self.ctr + 5) -% 12) & 1023]) ^ self.ptable[(self.ctr + 5) & 1023],
                self.h1(self.ptable[((self.ctr + 6) -% 12) & 1023]) ^ self.ptable[(self.ctr + 6) & 1023],
                self.h1(self.ptable[((self.ctr + 7) -% 12) & 1023]) ^ self.ptable[(self.ctr + 7) & 1023],
                self.h1(self.ptable[((self.ctr + 8) -% 12) & 1023]) ^ self.ptable[(self.ctr + 8) & 1023],
                self.h1(self.ptable[((self.ctr + 9) -% 12) & 1023]) ^ self.ptable[(self.ctr + 9) & 1023],
                self.h1(self.ptable[((self.ctr + 10) -% 12) & 1023]) ^ self.ptable[(self.ctr + 10) & 1023],
                self.h1(self.ptable[((self.ctr + 11) -% 12) & 1023]) ^ self.ptable[(self.ctr + 11) & 1023],
                self.h1(self.ptable[((self.ctr + 12) -% 12) & 1023]) ^ self.ptable[(self.ctr + 12) & 1023],
                self.h1(self.ptable[((self.ctr + 13) -% 12) & 1023]) ^ self.ptable[(self.ctr + 13) & 1023],
                self.h1(self.ptable[((self.ctr + 14) -% 12) & 1023]) ^ self.ptable[(self.ctr + 14) & 1023],
                self.h1(self.ptable[((self.ctr + 15) -% 12) & 1023]) ^ self.ptable[(self.ctr + 15) & 1023],
            };
        } else {
            self.qtable[(self.ctr + 0) & 1023] = self.qtable[(self.ctr + 0) & 1023] +% self.qtable[((self.ctr + 0) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 0) -% 3) & 1023], self.qtable[((self.ctr + 0) -% 1023) & 1023]);
            self.qtable[(self.ctr + 1) & 1023] = self.qtable[(self.ctr + 1) & 1023] +% self.qtable[((self.ctr + 1) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 1) -% 3) & 1023], self.qtable[((self.ctr + 1) -% 1023) & 1023]);
            self.qtable[(self.ctr + 2) & 1023] = self.qtable[(self.ctr + 2) & 1023] +% self.qtable[((self.ctr + 2) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 2) -% 3) & 1023], self.qtable[((self.ctr + 2) -% 1023) & 1023]);
            self.qtable[(self.ctr + 3) & 1023] = self.qtable[(self.ctr + 3) & 1023] +% self.qtable[((self.ctr + 3) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 3) -% 3) & 1023], self.qtable[((self.ctr + 3) -% 1023) & 1023]);
            self.qtable[(self.ctr + 4) & 1023] = self.qtable[(self.ctr + 4) & 1023] +% self.qtable[((self.ctr + 4) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 4) -% 3) & 1023], self.qtable[((self.ctr + 4) -% 1023) & 1023]);
            self.qtable[(self.ctr + 5) & 1023] = self.qtable[(self.ctr + 5) & 1023] +% self.qtable[((self.ctr + 5) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 5) -% 3) & 1023], self.qtable[((self.ctr + 5) -% 1023) & 1023]);
            self.qtable[(self.ctr + 6) & 1023] = self.qtable[(self.ctr + 6) & 1023] +% self.qtable[((self.ctr + 6) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 6) -% 3) & 1023], self.qtable[((self.ctr + 6) -% 1023) & 1023]);
            self.qtable[(self.ctr + 7) & 1023] = self.qtable[(self.ctr + 7) & 1023] +% self.qtable[((self.ctr + 7) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 7) -% 3) & 1023], self.qtable[((self.ctr + 7) -% 1023) & 1023]);
            self.qtable[(self.ctr + 8) & 1023] = self.qtable[(self.ctr + 8) & 1023] +% self.qtable[((self.ctr + 8) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 8) -% 3) & 1023], self.qtable[((self.ctr + 8) -% 1023) & 1023]);
            self.qtable[(self.ctr + 9) & 1023] = self.qtable[(self.ctr + 9) & 1023] +% self.qtable[((self.ctr + 9) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 9) -% 3) & 1023], self.qtable[((self.ctr + 9) -% 1023) & 1023]);
            self.qtable[(self.ctr + 10) & 1023] = self.qtable[(self.ctr + 10) & 1023] +% self.qtable[((self.ctr + 10) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 10) -% 3) & 1023], self.qtable[((self.ctr + 10) -% 1023) & 1023]);
            self.qtable[(self.ctr + 11) & 1023] = self.qtable[(self.ctr + 11) & 1023] +% self.qtable[((self.ctr + 11) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 11) -% 3) & 1023], self.qtable[((self.ctr + 11) -% 1023) & 1023]);
            self.qtable[(self.ctr + 12) & 1023] = self.qtable[(self.ctr + 12) & 1023] +% self.qtable[((self.ctr + 12) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 12) -% 3) & 1023], self.qtable[((self.ctr + 12) -% 1023) & 1023]);
            self.qtable[(self.ctr + 13) & 1023] = self.qtable[(self.ctr + 13) & 1023] +% self.qtable[((self.ctr + 13) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 13) -% 3) & 1023], self.qtable[((self.ctr + 13) -% 1023) & 1023]);
            self.qtable[(self.ctr + 14) & 1023] = self.qtable[(self.ctr + 14) & 1023] +% self.qtable[((self.ctr + 14) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 14) -% 3) & 1023], self.qtable[((self.ctr + 14) -% 1023) & 1023]);
            self.qtable[(self.ctr + 15) & 1023] = self.qtable[(self.ctr + 15) & 1023] +% self.qtable[((self.ctr + 15) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + 15) -% 3) & 1023], self.qtable[((self.ctr + 15) -% 1023) & 1023]);
            return [16]u32{
                self.h1(self.qtable[((self.ctr + 0) -% 12) & 1023]) ^ self.qtable[(self.ctr + 0) & 1023],
                self.h1(self.qtable[((self.ctr + 1) -% 12) & 1023]) ^ self.qtable[(self.ctr + 1) & 1023],
                self.h1(self.qtable[((self.ctr + 2) -% 12) & 1023]) ^ self.qtable[(self.ctr + 2) & 1023],
                self.h1(self.qtable[((self.ctr + 3) -% 12) & 1023]) ^ self.qtable[(self.ctr + 3) & 1023],
                self.h1(self.qtable[((self.ctr + 4) -% 12) & 1023]) ^ self.qtable[(self.ctr + 4) & 1023],
                self.h1(self.qtable[((self.ctr + 5) -% 12) & 1023]) ^ self.qtable[(self.ctr + 5) & 1023],
                self.h1(self.qtable[((self.ctr + 6) -% 12) & 1023]) ^ self.qtable[(self.ctr + 6) & 1023],
                self.h1(self.qtable[((self.ctr + 7) -% 12) & 1023]) ^ self.qtable[(self.ctr + 7) & 1023],
                self.h1(self.qtable[((self.ctr + 8) -% 12) & 1023]) ^ self.qtable[(self.ctr + 8) & 1023],
                self.h1(self.qtable[((self.ctr + 9) -% 12) & 1023]) ^ self.qtable[(self.ctr + 9) & 1023],
                self.h1(self.qtable[((self.ctr + 10) -% 12) & 1023]) ^ self.qtable[(self.ctr + 10) & 1023],
                self.h1(self.qtable[((self.ctr + 11) -% 12) & 1023]) ^ self.qtable[(self.ctr + 11) & 1023],
                self.h1(self.qtable[((self.ctr + 12) -% 12) & 1023]) ^ self.qtable[(self.ctr + 12) & 1023],
                self.h1(self.qtable[((self.ctr + 13) -% 12) & 1023]) ^ self.qtable[(self.ctr + 13) & 1023],
                self.h1(self.qtable[((self.ctr + 14) -% 12) & 1023]) ^ self.qtable[(self.ctr + 14) & 1023],
                self.h1(self.qtable[((self.ctr + 15) -% 12) & 1023]) ^ self.qtable[(self.ctr + 15) & 1023],
            };
        }
    }

    pub fn random(self: *Hc256) std.rand.Random {
        return std.rand.Random.init(self, applyStream);
    }

    fn h1(self: *Hc256, x: u32) u32 {
        return self.qtable[x & 255] +% self.qtable[256 + ((x >> 8) & 255)] +% self.qtable[512 + ((x >> 16) & 255)] +% self.qtable[768 + ((x >> 24) & 255)];
    }

    fn h2(self: *Hc256, x: u32) u32 {
        return self.ptable[x & 255] +% self.ptable[256 + ((x >> 8) & 255)] +% self.ptable[512 + ((x >> 16) & 255)] +% self.ptable[768 + ((x >> 24) & 255)];
    }

    fn g1(self: *Hc256, x: u32, y: u32) u32 {
        return (((x >> 10) | (x << (32 - 10))) ^ ((y >> 23) | (y << (32 - 23)))) +% self.qtable[(x ^ y) & 1023];
    }

    fn g2(self: *Hc256, x: u32, y: u32) u32 {
        return (((x >> 10) | (x << (32 - 10))) ^ ((y >> 23) | (y << (32 - 23)))) +% self.ptable[(x ^ y) & 1023];
    }
};

fn f1(x: u32) u32 {
    return ((x >> 7) | (x << (32 - 7))) ^ ((x >> 18) | (x << (32 - 18))) ^ (x >> 3);
}

fn f2(x: u32) u32 {
    return ((x >> 17) | (x << (32 - 17))) ^ ((x >> 19) | (x << (32 - 19))) ^ (x >> 10);
}
