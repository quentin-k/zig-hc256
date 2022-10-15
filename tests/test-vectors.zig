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

const hc256 = @import("hc256");
const Hc256 = hc256.Hc256;
const std = @import("std");
const testing = std.testing;

test "Vector 1" {
    const key = [32]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const iv = [32]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    var data = [32]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const expected = [32]u8{
        0x5b, 0x07, 0x89, 0x85, 0xd8, 0xf6, 0xf3, 0x0d,
        0x42, 0xc5, 0xc0, 0x2f, 0xa6, 0xb6, 0x79, 0x51,
        0x53, 0xf0, 0x65, 0x34, 0x80, 0x1f, 0x89, 0xf2,
        0x4e, 0x74, 0x24, 0x8b, 0x72, 0x0b, 0x48, 0x18,
    };

    var cipher = Hc256.init(key, iv);

    cipher.applyStream(data[0..]);

    var i: usize = 0;

    while (i < 32) : (i += 1) try testing.expectEqual(expected[i], data[i]);
}

test "Vector 2" {
    const key = [32]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const iv = [32]u8{
        1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    var data = [32]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const expected = [32]u8{
        0xaf, 0xe2, 0xa2, 0xbf, 0x4f, 0x17, 0xce, 0xe9,
        0xfe, 0xc2, 0x05, 0x8b, 0xd1, 0xb1, 0x8b, 0xb1,
        0x5f, 0xc0, 0x42, 0xee, 0x71, 0x2b, 0x31, 0x01,
        0xdd, 0x50, 0x1f, 0xc6, 0x0b, 0x08, 0x2a, 0x50,
    };

    var cipher = Hc256.init(key, iv);

    cipher.applyStream(data[0..13]);
    cipher.applyStream(data[13..]);

    var i: usize = 0;

    while (i < 14) : (i += 1) try testing.expectEqual(expected[i], data[i]);
}

test "Vector 3" {
    const key = [32]u8{
        0x55, 0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0,
    };
    const iv = [32]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    var data = [32]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const expected = [32]u8{
        0x1c, 0x40, 0x4a, 0xfe, 0x4f, 0xe2, 0x5f, 0xed,
        0x95, 0x8f, 0x9a, 0xd1, 0xae, 0x36, 0xc0, 0x6f,
        0x88, 0xa6, 0x5a, 0x3c, 0xc0, 0xab, 0xe2, 0x23,
        0xae, 0xb3, 0x90, 0x2f, 0x42, 0x0e, 0xd3, 0xa8,
    };

    var cipher = Hc256.init(key, iv);

    cipher.applyStream(data[0..]);

    var i: usize = 0;

    while (i < 32) : (i += 1) try testing.expectEqual(expected[i], data[i]);
}
