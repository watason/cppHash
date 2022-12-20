#include "Hash.hpp"
#include <openssl/sha.h>

int main()
{
    std::string message = "helloworld";
    {
        auto start = std::chrono::system_clock::now();

        unsigned char digest[SHA256_DIGEST_LENGTH];

        SHA256_CTX sha_ctx;
        SHA256_Init(&sha_ctx);                                    // コンテキストを初期化
        SHA256_Update(&sha_ctx, message.c_str(), message.size()); // message を入力にする
        SHA256_Final(digest, &sha_ctx);                           // digest に出力

        auto end = std::chrono::system_clock::now();
        double elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        std::cout << elapsed << " nano seconds " << std::endl;
        for (int i = 0; i < sizeof(digest); ++i)
        {
            std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(digest[i]);
            // printf("%x", digest[i]);
        }
        std::cout << std::endl;
        // 処理
    }
    {

        auto start = std::chrono::system_clock::now();
        using namespace sha;
        auto hash = Hash<sha256>::createHash(message);
        auto [seed, hashArray] = hash();
        // std::cout << "seed is " << seed << std::endl;

        auto end = std::chrono::system_clock::now();
        double elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        std::cout << elapsed << " nano seconds " << std::endl;
        for (int i = 0; i < hashArray.size(); ++i)
        {
            std::cout << std::hex << hashArray[i];
        }
        std::cout << std::endl;
    }
    return 0;
}