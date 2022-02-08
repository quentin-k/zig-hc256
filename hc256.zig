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

const BufferSize = 4;

pub const Hc256 = struct {
    ptable: Table,
    qtable: Table,
    buffer: [BufferSize]u8 = [_]u8{0} ** BufferSize,
    buffered: bool,
    ctr: usize = 0,

    /// Initialize the cipher with the key and iv
    pub fn init(key: [32]u8, iv: [32]u8, buffered: bool) Hc256 {
        var cipher = Hc256{
            .ptable = undefined,
            .qtable = undefined,
            .buffered = buffered,
        };
        var w: [2560]u32 = undefined;

        var i: u32 = 0;
        while (i < 8) : (i += 1) {
            w[i] = @as(u32, key[i * 4]) | (@as(u32, key[(i * 4) + 1]) << 8) | (@as(u32, key[(i * 4) + 2]) << 16) | (@as(u32, key[(i * 4) + 3]) << 24);
            w[i + 8] = @as(u32, iv[i * 4]) | (@as(u32, iv[(i * 4) + 1]) << 8) | (@as(u32, iv[(i * 4) + 2]) << 16) | (@as(u32, iv[(i * 4) + 3]) << 24);
        }

        i = 16;
        while (i < 2560) : (i += 1) w[i] = f2(w[i - 2]) +% w[i - 7] +% f1(w[i - 15]) +% w[i - 16] +% i;

        i = 0;
        while (i < 1024) : (i += 1) {
            cipher.ptable[i] = w[i + 512];
            cipher.qtable[i] = w[i + 1536];
        }

        i = 0;

        while (i < 4096) : (i += 1) _ = cipher.genWord();

        if (buffered) cipher.buffer = [4]u8{ 0, 0, 0, 0 };

        return cipher;
    }

    /// Applies the keystream from the cipher to the given bytes in place
    pub fn applyStream(self: *Hc256, data: []u8) void {
        const buf_size = @as(usize, self.buffer[0]);

        // Handle initial buffering
        const dlen = if (self.buffered) blk: {
            var i: usize = 0;
            const buf_start = 4 - buf_size;

            if (data.len <= buf_size) {
                while (i < data.len) : (i += 1) {
                    data[i] ^= self.buffer[buf_start + i];
                    self.buffer[buf_start + i] = 0;
                }

                self.buffer[0] = @intCast(u8, (data.len - buf_size));
                return;
            } else {
                while (i < buf_size) : (i += 1) {
                    data[i] ^= self.buffer[buf_start + i];
                    self.buffer[buf_start + i] = 0;
                }

                self.buffer[0] = 0;
            }

            break :blk data.len - buf_size;
        } else data.len;

        var i: usize = 0;

        while (i < (dlen / 4)) : (i += 1) {
            var word = @bitCast([4]u8, self.genWord());

            data[(i * 4) + buf_size] ^= word[0];
            data[((i * 4) + buf_size) + 1] ^= word[1];
            data[((i * 4) + buf_size) + 2] ^= word[2];
            data[((i * 4) + buf_size) + 3] ^= word[3];
        }

        switch (dlen % 4) {
            1 => {
                var word = @bitCast([4]u8, self.genWord());

                data[(i * 4) + buf_size] ^= word[0];
                self.buffer = [4]u8{ 3, word[1], word[2], word[3] };
            },
            2 => {
                var word = @bitCast([4]u8, self.genWord());

                data[(i * 4) + buf_size] ^= word[0];
                data[((i * 4) + buf_size) + 1] ^= word[1];

                self.buffer = [4]u8{ 2, 0, word[2], word[3] };
            },
            3 => {
                var word = @bitCast([4]u8, self.genWord());

                data[(i * 4) + buf_size] ^= word[0];
                data[((i * 4) + buf_size) + 1] ^= word[1];
                data[((i * 4) + buf_size) + 2] ^= word[2];

                self.buffer = [4]u8{ 1, 0, 0, word[3] };
            },
            else => {}, // This will always be zeroes if buffered
        }
    }

    /// Generates the next word from the cipher
    pub fn genWord(self: *Hc256) u32 {
        defer self.ctr = (self.ctr + 1) & 2047;
        if (self.ctr < 1024) {
            self.ptable[self.ctr & 1023] = self.ptable[self.ctr & 1023] +% self.ptable[(self.ctr -% 10) & 1023] +% self.g1(self.ptable[(self.ctr -% 3) & 1023], self.ptable[(self.ctr -% 1023) & 1023]);
            return self.h1(self.ptable[(self.ctr -% 12) & 1023]) ^ self.ptable[self.ctr & 1023];
        } else {
            self.qtable[self.ctr & 1023] = self.qtable[self.ctr & 1023] +% self.qtable[(self.ctr -% 10) & 1023] +% self.g2(self.qtable[(self.ctr -% 3) & 1023], self.qtable[(self.ctr -% 1023) & 1023]);
            return self.h1(self.qtable[(self.ctr -% 12) & 1023]) ^ self.qtable[self.ctr & 1023];
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
