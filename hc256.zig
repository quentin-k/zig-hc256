// Copyright 2021-2022 Quentin K
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
    pub fn init(key: [32]u8, iv: [32]u8) Hc256 {
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
        while (i < 4096) : (i += 16) _ = @call(
            .{ .modifier = .always_inline },
            genWord16,
            .{&cipher},
        );

        return cipher;
    }

    /// Applies the keystream from the cipher to the given bytes in place
    pub fn applyStream(self: *Hc256, data: []u8) void {
        var i: usize = 0;
        if (self.ptr != 0) {
            const remaining = buffer_size - self.ptr;
            const stop = @minimum(remaining, data.len);
            while (i < stop) : (i += 1) {
                data[i] ^= self.buffer[self.ptr];
                self.ptr += 1;
            }
            if (i == data.len) return;
        }
        while (i + buffer_size <= data.len) : (i += buffer_size) {
            self.genWord16();
            comptime var j: usize = 0;
            inline while (j < buffer_size) : (j += 1) data[i + j] ^= self.buffer[j];
        }
        if (i != data.len) {
            self.genWord16();
            while (i < data.len) : (i += 1) {
                data[i] ^= self.buffer[self.ptr + i];
            }
            self.ptr += data.len & (buffer_size - 1);
        }
    }

    /// Generates the next word from the cipher
    inline fn genWord16(self: *Hc256) void {
        defer self.ctr = (self.ctr + 16) & 2047;
        var output = @ptrCast([*]align(1) u32, &self.buffer);
        if (self.ctr < 1024) {
            comptime var i: usize = 0;
            inline while (i < 16) : (i += 1) {
                self.ptable[(self.ctr + i) & 1023] +%= self.ptable[((self.ctr + i) -% 10) & 1023] +% self.g1(self.ptable[((self.ctr + i) -% 3) & 1023], self.ptable[((self.ctr + i) -% 1023) & 1023]);
                output[i] = self.h1(self.ptable[((self.ctr + i) -% 12) & 1023]) ^ self.ptable[(self.ctr + i) & 1023];
            }
        } else {
            comptime var i: usize = 0;
            inline while (i < 16) : (i += 1) {
                self.qtable[(self.ctr + i) & 1023] +%= self.qtable[((self.ctr + i) -% 10) & 1023] +% self.g2(self.qtable[((self.ctr + i) -% 3) & 1023], self.qtable[((self.ctr + i) -% 1023) & 1023]);
                output[i] = self.h2(self.qtable[((self.ctr + i) -% 12) & 1023]) ^ self.qtable[(self.ctr + i) & 1023];
            }
        }
    }

    pub fn random(self: *Hc256) std.rand.Random {
        return std.rand.Random.init(self, getRandom);
    }

    fn getRandom(self: *Hc256, data: []u8) void {
        std.mem.set(u8, data, 0);
        @call(
            .{ .modifier = .always_inline },
            applyStream,
            .{&self},
        );
    }

    inline fn h1(self: *Hc256, x: u32) u32 {
        return self.qtable[x & 255] +% self.qtable[256 + ((x >> 8) & 255)] +% self.qtable[512 + ((x >> 16) & 255)] +% self.qtable[768 + ((x >> 24) & 255)];
    }

    inline fn h2(self: *Hc256, x: u32) u32 {
        return self.ptable[x & 255] +% self.ptable[256 + ((x >> 8) & 255)] +% self.ptable[512 + ((x >> 16) & 255)] +% self.ptable[768 + ((x >> 24) & 255)];
    }

    inline fn g1(self: *Hc256, x: u32, y: u32) u32 {
        return (rotr(x, 10) ^ rotr(y, 23)) +% self.qtable[(x ^ y) & 1023];
    }

    inline fn g2(self: *Hc256, x: u32, y: u32) u32 {
        return (rotr(x, 10) ^ rotr(y, 23)) +% self.ptable[(x ^ y) & 1023];
    }
};

inline fn f1(x: u32) u32 {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline fn f2(x: u32) u32 {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

inline fn rotr(a: u32, b: u32) u32 {
    return (a >> @intCast(u5, b)) | (a << @intCast(u5, 32 - b));
}
