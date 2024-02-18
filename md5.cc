#include "md5.h"

MD5::MD5() {
        state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;

    count[0] = 0;
    count[1] = 0;
}

std::string MD5::hash(const std::string& message) {
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;

    count[0] = 0;
    count[1] = 0;
    update(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());

    uint8_t digest[MD5_HASH_SIZE];
    final(digest);

    std::stringstream ss;
    for (uint32_t i = 0; i < MD5_HASH_SIZE; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return ss.str();
}

void MD5::transform(const uint8_t block[MD5_BLOCK_SIZE]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];

    decode(block, x, 64);

    for (uint32_t i = 0; i < 64; ++i) {
        uint32_t f, g;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | (~d));
            g = (7 * i) % 16;
        }

        uint32_t temp = d;
        d = c;
        c = b;
        b = b + leftrotate((a + f + K[i] + x[g]), S[i]);
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset(x, 0, sizeof(x));
}

void MD5::update(const uint8_t* input, size_t length) {
    uint32_t i, index, partLen;

    index = (count[0] >> 3) & 0x3F;

    if ((count[0] += length << 3) < (length << 3)) {
        count[1]++;
    }
    count[1] += (length >> 29);

    partLen = 64 - index;

    if (length >= partLen) {
        memcpy(&buffer[index], input, partLen);
        transform(buffer);
        for (i = partLen; i + 63 < length; i += 64) {
            transform(&input[i]);
        }
        index = 0;
    } else {
        i = 0;
    }

    memcpy(&buffer[index], &input[i], length - i);
}

void MD5::final(uint8_t digest[MD5_HASH_SIZE]) {
    uint8_t bits[8];
    uint32_t index, padLen;

    encode(count, bits, 8);

    index = (count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    update(PADDING, padLen);

    update(bits, 8);

    encode(state, digest, 16);
}

void MD5::encode(const uint32_t* input, uint8_t* output, size_t length) {
    for (size_t i = 0, j = 0; j < length; ++i, j += 4) {
        output[j] = input[i] & 0xFF;
        output[j + 1] = (input[i] >> 8) & 0xFF;
        output[j + 2] = (input[i] >> 16) & 0xFF;
        output[j + 3] = (input[i] >> 24) & 0xFF;
    }
}

void MD5::decode(const uint8_t* input, uint32_t* output, size_t length) {
    for (size_t i = 0, j = 0; j < length; ++i, j += 4) {
        output[i] = input[j] | (input[j + 1] << 8) | (input[j + 2] << 16) | (input[j + 3] << 24);
    }
}