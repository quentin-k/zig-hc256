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
pub const buffer_size = words * 4;
const native_words = buffer_size / @sizeOf(usize);

pub const Hc256 = struct {
    ptable: Table align(@sizeOf(usize)),
    qtable: Table align(@sizeOf(usize)),
    buffer: [buffer_size]u8 align(@sizeOf(usize)) = [_]u8{0} ** buffer_size,
    ctr: usize = 0,
    ptr: usize = 0,

    /// Initialize the cipher with the key and iv
    pub fn init(key: [32]u8, iv: [32]u8) Hc256 {
        var cipher = Hc256{
            .ptable = undefined,
            .qtable = undefined,
        };
        var w: [2560]u32 = undefined;

        var i: u32 = 16;
        comptime var j = 0;
        inline while (j < 8) : (j += 1) {
            w[j] = @as(u32, key[j * 4]) | (@as(u32, key[(j * 4) + 1]) << 8) | (@as(u32, key[(j * 4) + 2]) << 16) | (@as(u32, key[(j * 4) + 3]) << 24);
            w[j + 8] = @as(u32, iv[j * 4]) | (@as(u32, iv[(j * 4) + 1]) << 8) | (@as(u32, iv[(j * 4) + 2]) << 16) | (@as(u32, iv[(j * 4) + 3]) << 24);
        }

        while (i < 2560) : (i += 1) w[i] = f2(w[i - 2]) +% w[i - 7] +% f1(w[i - 15]) +% w[i - 16] +% i;

        std.mem.copy(u32, &cipher.ptable, w[512..(512 + 1024)]);
        std.mem.copy(u32, &cipher.qtable, w[1536..(1536 + 1024)]);

        i = 0;
        while (i < 4096) : (i += words) cipher.update();

        return cipher;
    }

    /// Applies the keystream from the cipher to the given bytes in place
    pub fn applyStream(self: *Hc256, data: []u8) void {
        var i: usize = 0;
        var data_words = @ptrCast([*]align(1) usize, data);

        // Apply the leftover buffer
        if (self.ptr != 0) {
            // Mask the pointer
            defer self.ptr &= buffer_size - 1;

            // Determine the stop values
            const stop = @minimum(buffer_size - self.ptr, data.len);
            const full_words = stop / @sizeOf(usize);

            // Apply the full words leftover
            const buf_words = @ptrCast([*]align(1) usize, self.buffer[self.ptr..]);
            var j: usize = 0;
            while (j < full_words) : (j += 1)
                data_words[j] ^= buf_words[j];

            // update i & self.ptr
            const bytes_written = full_words * @sizeOf(usize);
            i += bytes_written;
            self.ptr += bytes_written;

            // Apply the remaining bytes
            while (i < stop) : ({
                i += 1;
                self.ptr += 1;
            }) data[i] ^= self.buffer[self.ptr];
            if (i == data.len) return else data_words = @ptrCast([*]align(1) usize, data[i..]);
        }

        var wi: usize = 0;

        // Apply full buffers to the stream
        const full_blocks = (data.len - i) / buffer_size;
        var fi: usize = 0;
        while (fi < full_blocks) : (fi += 1) {
            // Update the buffer words
            self.genWords();
            const buffer_words = @ptrCast([*]align(1) usize, &self.buffer);

            // Apply the buffer to the data
            comptime var j = 0;
            inline while (j < native_words) : (j += 1)
                data_words[wi + j] ^= buffer_words[j];

            wi += native_words;
        }

        i += wi * @sizeOf(usize);

        if (i < data.len) {
            // Generate the leftover words
            self.genWords();
            const buffer_words = @ptrCast([*]align(1) usize, &self.buffer);

            // Apply the stream to the remaining full words
            const leftover_words = (data.len - i) / @sizeOf(usize);
            var j: usize = 0;
            while (j < leftover_words) : (j += 1)
                data_words[wi + j] ^= buffer_words[j];

            // Update self.ptr and the index then apply the remaining bytes
            self.ptr += leftover_words * @sizeOf(usize);
            i += leftover_words * @sizeOf(usize);
            while (i < data.len) : ({
                i += 1;
                self.ptr += 1;
            }) data[i] ^= self.buffer[self.ptr];
        }
    }

    /// Applies the keystream to full blocks of data, returns the bytes encrypted. ***WARNING*** This function does not work with partial buffers.
    pub fn applyStreamFast(self: *Hc256, data: []u8) usize {
        var i: usize = 0;
        const len = data.len / buffer_size;
        var data_words = @ptrCast([*]align(1) usize, data);
        var buffer = @ptrCast([*]usize, &self.buffer);

        while (i < len) : (i += 1) {
            self.genWords();
            comptime var j = 0;
            inline while (j < native_words) : (j += 1) data_words[(i * native_words) + j] ^= buffer[j];
        }
        return i * buffer_size;
    }

    /// Generates the next word from the cipher
    pub inline fn genWords(self: *Hc256) void {
        // Update the counter
        defer self.ctr = (self.ctr + words) & 2047;
        const a = self.ctr & 1023;
        const b = (self.ctr -% 16) & 1023;
        const c = (self.ctr + 16) & 1023;

        const a1 = a + 1;
        const a2 = a + 2;
        const a3 = a + 3;
        const a4 = a + 4;
        const a5 = a + 5;
        const a6 = a + 6;
        const a7 = a + 7;
        const a8 = a + 8;
        const a9 = a + 9;
        const a10 = a + 10;
        const a11 = a + 11;
        const a12 = a + 12;
        const a13 = a + 13;
        const a14 = a + 14;
        const a15 = a + 15;
        const b4 = b + 4;
        const b5 = b + 5;
        const b6 = b + 6;
        const b7 = b + 7;
        const b8 = b + 8;
        const b9 = b + 9;
        const b10 = b + 10;
        const b11 = b + 11;
        const b12 = b + 12;
        const b13 = b + 13;
        const b14 = b + 14;
        const b15 = b + 15;

        // cast the buffer as an array of u32
        var output = @ptrCast([*]u32, &self.buffer);

        if (self.ctr < 1024) {
            self.stepP(a, b6, b13, a1, b4, &output[0]);
            self.stepP(a1, b7, b14, a2, b5, &output[1]);
            self.stepP(a2, b8, b15, a3, b6, &output[2]);
            self.stepP(a3, b9, a, a4, b7, &output[3]);
            self.stepP(a4, b10, a1, a5, b8, &output[4]);
            self.stepP(a5, b11, a2, a6, b9, &output[5]);
            self.stepP(a6, b12, a3, a7, b10, &output[6]);
            self.stepP(a7, b13, a4, a8, b11, &output[7]);
            self.stepP(a8, b14, a5, a9, b12, &output[8]);
            self.stepP(a9, b15, a6, a10, b13, &output[9]);
            self.stepP(a10, a, a7, a11, b14, &output[10]);
            self.stepP(a11, a1, a8, a12, b15, &output[11]);
            self.stepP(a12, a2, a9, a13, a, &output[12]);
            self.stepP(a13, a3, a10, a14, a1, &output[13]);
            self.stepP(a14, a4, a11, a15, a2, &output[14]);
            self.stepP(a15, a5, a12, c, a3, &output[15]);
        } else {
            self.stepQ(a, b6, b13, a1, b4, &output[0]);
            self.stepQ(a1, b7, b14, a2, b5, &output[1]);
            self.stepQ(a2, b8, b15, a3, b6, &output[2]);
            self.stepQ(a3, b9, a, a4, b7, &output[3]);
            self.stepQ(a4, b10, a1, a5, b8, &output[4]);
            self.stepQ(a5, b11, a2, a6, b9, &output[5]);
            self.stepQ(a6, b12, a3, a7, b10, &output[6]);
            self.stepQ(a7, b13, a4, a8, b11, &output[7]);
            self.stepQ(a8, b14, a5, a9, b12, &output[8]);
            self.stepQ(a9, b15, a6, a10, b13, &output[9]);
            self.stepQ(a10, a, a7, a11, b14, &output[10]);
            self.stepQ(a11, a1, a8, a12, b15, &output[11]);
            self.stepQ(a12, a2, a9, a13, a, &output[12]);
            self.stepQ(a13, a3, a10, a14, a1, &output[13]);
            self.stepQ(a14, a4, a11, a15, a2, &output[14]);
            self.stepQ(a15, a5, a12, c, a3, &output[15]);
        }
    }

    inline fn update(self: *Hc256) void {
        // Update the counter
        defer self.ctr = (self.ctr + words) & 2047;
        const a = self.ctr & 1023;
        const b = (self.ctr -% 16) & 1023;
        const c = (self.ctr + 16) & 1023;

        const a1 = a + 1;
        const a2 = a + 2;
        const a3 = a + 3;
        const a4 = a + 4;
        const a5 = a + 5;
        const a6 = a + 6;
        const a7 = a + 7;
        const a8 = a + 8;
        const a9 = a + 9;
        const a10 = a + 10;
        const a11 = a + 11;
        const a12 = a + 12;
        const a13 = a + 13;
        const a14 = a + 14;
        const a15 = a + 15;
        const b6 = b + 6;
        const b7 = b + 7;
        const b8 = b + 8;
        const b9 = b + 9;
        const b10 = b + 10;
        const b11 = b + 11;
        const b12 = b + 12;
        const b13 = b + 13;
        const b14 = b + 14;
        const b15 = b + 15;

        if (self.ctr < 1024) {
            self.updateP(a, b6, b13, a1);
            self.updateP(a1, b7, b14, a2);
            self.updateP(a2, b8, b15, a3);
            self.updateP(a3, b9, a, a4);
            self.updateP(a4, b10, a1, a5);
            self.updateP(a5, b11, a2, a6);
            self.updateP(a6, b12, a3, a7);
            self.updateP(a7, b13, a4, a8);
            self.updateP(a8, b14, a5, a9);
            self.updateP(a9, b15, a6, a10);
            self.updateP(a10, a, a7, a11);
            self.updateP(a11, a1, a8, a12);
            self.updateP(a12, a2, a9, a13);
            self.updateP(a13, a3, a10, a14);
            self.updateP(a14, a4, a11, a15);
            self.updateP(a15, a5, a12, c);
        } else {
            self.updateQ(a, b6, b13, a1);
            self.updateQ(a1, b7, b14, a2);
            self.updateQ(a2, b8, b15, a3);
            self.updateQ(a3, b9, a, a4);
            self.updateQ(a4, b10, a1, a5);
            self.updateQ(a5, b11, a2, a6);
            self.updateQ(a6, b12, a3, a7);
            self.updateQ(a7, b13, a4, a8);
            self.updateQ(a8, b14, a5, a9);
            self.updateQ(a9, b15, a6, a10);
            self.updateQ(a10, a, a7, a11);
            self.updateQ(a11, a1, a8, a12);
            self.updateQ(a12, a2, a9, a13);
            self.updateQ(a13, a3, a10, a14);
            self.updateQ(a14, a4, a11, a15);
            self.updateQ(a15, a5, a12, c);
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

    inline fn stepP(self: *Hc256, w0: usize, w10: usize, w3: usize, w1023: usize, w12: usize, output: *u32) void {
        self.ptable[w0] +%= self.ptable[w10] +% self.g1(self.ptable[w3], self.ptable[w1023]);
        output.* = self.h1(self.ptable[w12]) ^ self.ptable[w0];
    }

    inline fn stepQ(self: *Hc256, w0: usize, w10: usize, w3: usize, w1023: usize, w12: usize, output: *u32) void {
        self.qtable[w0] +%= self.qtable[w10] +% self.g2(self.qtable[w3], self.qtable[w1023]);
        output.* = self.h2(self.qtable[w12]) ^ self.qtable[w0];
    }

    inline fn updateP(self: *Hc256, w0: usize, w10: usize, w3: usize, w1023: usize) void {
        self.ptable[w0] +%= self.ptable[w10] +% self.g1(self.ptable[w3], self.ptable[w1023]);
    }

    inline fn updateQ(self: *Hc256, w0: usize, w10: usize, w3: usize, w1023: usize) void {
        self.qtable[w0] +%= self.qtable[w10] +% self.g2(self.qtable[w3], self.qtable[w1023]);
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
