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

const words = 16;
const buffer_size = words * 4;

pub const Hc256 = struct {
    ptable: Table,
    qtable: Table,
    buffer: [buffer_size]u8 align(4) = [_]u8{0} ** buffer_size,
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
        while (i < 4096) : (i += words) cipher.genWords();

        return cipher;
    }

    /// Applies the keystream from the cipher to the given bytes in place
    pub fn applyStream(self: *Hc256, data: []u8) void {
        // Set the initial counter
        var i: usize = 0;
        //var data_words = @ptrCast([*]align(1) u32, data);
        //var wi: usize = 0;

        // Use the leftover data in the buffer if it hasn't been used
        if (self.ptr != 0) {
            defer self.ptr &= buffer_size - 1;
            const remaining = buffer_size - self.ptr;
            const stop = @minimum(remaining, data.len);
            const end = stop == data.len;
            while (i < stop) : (i += 1) data[i] ^= self.buffer[self.ptr + i];
            if (end) {
                self.ptr += i;
                return;
            } else {
                self.ptr = 0;
            }
        }

        // Encrypt the full blocks of data
        while (i + buffer_size <= data.len) : (i += buffer_size) {
            self.genWords();
            comptime var j: usize = 0;
            inline while (j < buffer_size) : (j += 1) data[i + j] ^= self.buffer[j];
        }

        // Encrypt the leftover data
        if (i != data.len) {
            self.genWords();
            while (i < data.len) : (i += 1) {
                defer self.ptr += 1;
                data[i] ^= self.buffer[self.ptr];
            }
        }
    }

    /// Generates the next word from the cipher
    pub inline fn genWords(self: *Hc256) void {
        // Update the counter
        defer self.ctr = (self.ctr + words) & 2047;

        // cast the buffer as an array of u32
        var output = @ptrCast([*]u32, &self.buffer);
        if (self.ctr < 1024) {
            comptime var i: usize = 0;
            inline while (i < words) : (i += 1) {
                const w0 = (self.ctr + i) & 1023;
                const w10 = (self.ctr + i -% 10) & 1023;
                const w3 = (self.ctr + i -% 3) & 1023;
                const w1023 = (self.ctr + i + 1) & 1023;
                const w12 = (self.ctr + i -% 12) & 1023;
                self.ptable[w0] +%= self.ptable[w10] +% self.g1(self.ptable[w3], self.ptable[w1023]);
                output[i] = self.h1(self.ptable[w12]) ^ self.ptable[w0];
            }
        } else {
            comptime var i: usize = 0;
            inline while (i < words) : (i += 1) {
                const w0 = (self.ctr + i) & 1023;
                const w10 = (self.ctr + i -% 10) & 1023;
                const w3 = (self.ctr + i -% 3) & 1023;
                const w1023 = (self.ctr + i + 1) & 1023;
                const w12 = (self.ctr + i -% 12) & 1023;
                self.qtable[w0] +%= self.qtable[w10] +% self.g2(self.qtable[w3], self.qtable[w1023]);
                output[i] = self.h2(self.qtable[w12]) ^ self.qtable[w0];
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
