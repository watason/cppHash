#include <iostream>
#include <string>
#include <array>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <openssl/sha.h>
#include <bitset>

namespace sha
{
    struct sha256
    {
    };
    template <typename Tag>
    class Hash;
    template <>
    class Hash<sha256>
    {
    public:
        std::string seed;
        std::vector<uint8_t> messages;
        size_t N;
        static constexpr size_t BLOCK_SIZE = 64;
        static constexpr std::array<unsigned int, 64> K = {
            0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
            0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
            0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
            0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
            0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
            0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
            0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
            0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
            0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
            0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
            0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
            0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
            0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
            0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
            0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
            0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};
        std::array<unsigned int, 8> H = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                         0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    public:
        unsigned int Rot(unsigned int v, int n)
        {
            return (v << n) | (v >> (32 - n));
        }
        unsigned int Shr(unsigned int v, int n)
        {
            return (v >> n);
        }
        unsigned int Sigma0(unsigned int x)
        {
            return Rot(x, 30) ^ Rot(x, 19) ^ Rot(x, 10);
        }
        unsigned int Sigma1(unsigned int x)
        {
            return Rot(x, 26) ^ Rot(x, 21) ^ Rot(x, 7);
        }
        unsigned int sigma0(unsigned int x)
        {
            return Rot(x, 25) ^ Rot(x, 14) ^ Shr(x, 3);
        }
        unsigned int sigma1(unsigned int x)
        {
            return Rot(x, 15) ^ Rot(x, 13) ^ Shr(x, 10);
        }
        unsigned int Ch(unsigned int x, unsigned int y, unsigned int z)
        {
            return (x & y) ^ (~x & z);
        }
        unsigned int Maj(unsigned int x, unsigned int y, unsigned int z)
        {
            return (x & y) ^ (y & z) ^ (x & z);
        }
        auto padding(const std::string &input)
        {
            size_t size = input.size();
            size_t padding_size = ((size + 9 + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
            std::vector<uint8_t> ret(padding_size);
            for (int i = 0; i < size; i++)
            {
                ret[i] = static_cast<uint8_t>(input[i]);
            }
            ret[size] = 0x80;
            size *= 8;
            ret[padding_size - 4] = static_cast<unsigned int>(size >> 24) & 0xff;
            ret[padding_size - 3] = static_cast<unsigned int>(size >> 16) & 0xff;
            ret[padding_size - 2] = static_cast<unsigned int>(size >> 8) & 0xff;
            ret[padding_size - 1] = static_cast<unsigned int>(size) & 0xff;
            return ret;
        }
        unsigned int loadMessge(const std::vector<uint8_t> &arr, int index)
        {
            unsigned int load{};
            load |= static_cast<unsigned int>(arr[index]) << 24;
            load |= static_cast<unsigned int>(arr[index + 1]) << 16;
            load |= static_cast<unsigned int>(arr[index + 2]) << 8;
            load |= static_cast<unsigned int>(arr[index + 3]);
            return load;
        }
        Hash(const std::string &str) : seed(str), messages(padding(str)) {}
        auto operator()()
        {
            size_t size = messages.size();
            for (int num = 0; num < size; num += 64)
            {
                unsigned int T1{}, T2{}, s0{}, s1{};
                std::array<unsigned int, 16> X;
                std::array<unsigned int, 8> arr;
                for (int i = 0; i < 8; ++i)
                {
                    arr[i] = H[i];
                }
                auto &[a, b, c, d, e, f, g, h] = arr;
                int t;
                for (t = 0; t < 16; ++t)
                {
                    T1 = X[t] = loadMessge(messages, t * 4);
                    T1 += h + Sigma1(e) + Ch(e, f, g) + K[t];
                    T2 = Sigma0(a) + Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + T1;
                    d = c;
                    c = b;
                    b = a;
                    a = T1 + T2;
                }
                for (; t < 64; ++t)
                {
                    s0 = X[(t + 1) & 0x0f];
                    s0 = sigma0(s0);
                    s1 = X[(t + 14) & 0x0f];
                    s1 = sigma1(s1);

                    T1 = X[t & 0xf] += s0 + s1 + X[(t + 9) & 0xf];
                    T1 += h + Sigma1(e) + Ch(e, f, g) + K[t];
                    T2 = Sigma0(a) + Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + T1;
                    d = c;
                    c = b;
                    b = a;
                    a = T1 + T2;
                }

                for (int i = 0; i < 8; ++i)
                {
                    H[i] += arr[i];
                }
            }
            return std::make_pair(seed, H);
        }
        static Hash createHash(const std::string &str)
        {
            Hash ret(str);
            return ret;
        }
    };

}
int main()
{
    std::string message = "helloworld ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    {
        auto start = std::chrono::system_clock::now();

        unsigned char digest[SHA256_DIGEST_LENGTH];

        SHA256_CTX sha_ctx;
        SHA256_Init(&sha_ctx);                                    // コンテキストを初期化
        SHA256_Update(&sha_ctx, message.c_str(), message.size()); // message を入力にする
        SHA256_Final(digest, &sha_ctx);                           // digest に出力

        for (int i = 0; i < sizeof(digest); ++i)
        {
            std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(digest[i]);
            // printf("%x", digest[i]);
        }
        std::cout << std::endl;
        // 処理
        auto end = std::chrono::system_clock::now();
        double elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        std::cout << elapsed << " micro second " << std::endl;
    }

    {

        auto start = std::chrono::system_clock::now();
        using namespace sha;
        auto hash = Hash<sha256>::createHash(message);
        auto [seed, hashArray] = hash();
        // std::cout << "seed is " << seed << std::endl;

        for (int i = 0; i < hashArray.size(); ++i)
        {
            std::cout << std::hex << hashArray[i];
        }
        std::cout << std::endl;

        auto end = std::chrono::system_clock::now();
        double elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        std::cout << elapsed << " micro second " << std::endl;
    }
    return 0;
}