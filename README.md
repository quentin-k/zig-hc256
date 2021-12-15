# Zig Hc256

An implementation of the hc-256 cipher in zig.

## License

Apache 2.0

## Usage

1. initialize the cipher with a key and iv
2. use the `apply_stream` method on a slice of `u8`s to encrypt/decrypt the data

The test vectors file (`/tests/test-vectors.zig`) shows examples on how to use the library.