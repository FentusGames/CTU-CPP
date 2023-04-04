#pragma once

#include "CtuCore.h"

namespace ctu {
	namespace security {
        void PrintRSAKeys(EVP_PKEY* pkey) {
            // Print private key
            BIO* privBIO = BIO_new_fp(stdout, BIO_NOCLOSE);
            if (PEM_write_bio_PrivateKey(privBIO, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                EVP_PKEY_free(pkey);
                BIO_free_all(privBIO);
            }

            BIO_free_all(privBIO);

            // Print public key
            BIO* pubBIO = BIO_new_fp(stdout, BIO_NOCLOSE);
            if (PEM_write_bio_PUBKEY(pubBIO, pkey) != 1) {
                EVP_PKEY_free(pkey);
                BIO_free_all(pubBIO);
            }

            BIO_free_all(pubBIO);
        }

        void PrintPrivateRSAKey(EVP_PKEY* pkey) {
            // Print private key
            BIO* privBIO = BIO_new_fp(stdout, BIO_NOCLOSE);
            if (PEM_write_bio_PrivateKey(privBIO, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                EVP_PKEY_free(pkey);
                BIO_free_all(privBIO);
            }

            BIO_free_all(privBIO);
        }

        void PrintPublicRSAKey(EVP_PKEY* pkey) {
            // Print public key
            BIO* pubBIO = BIO_new_fp(stdout, BIO_NOCLOSE);
            if (PEM_write_bio_PUBKEY(pubBIO, pkey) != 1) {
                EVP_PKEY_free(pkey);
                BIO_free_all(pubBIO);
            }

            BIO_free_all(pubBIO);
        }

        EVP_PKEY* GenerateRSAKey(int keyLength)
        {
            EVP_PKEY* pkey = nullptr;
            EVP_PKEY_CTX* ctx = nullptr;

            // Create context for RSA key generation
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

            if (!ctx) {
                return nullptr;
            }

            // Initialize key generation parameters
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return nullptr;
            }

            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keyLength) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return nullptr;
            }

            // Generate key pair
            if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return nullptr;
            }

            // Clean up
            EVP_PKEY_CTX_free(ctx);
            return pkey;
        }

        std::string SignMessage(const std::string& message, EVP_PKEY* privateKey) {
            // Create a new context for signing
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();

            // Initialize the context for SHA-256
            if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privateKey) <= 0) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            // Update the context with the message to be signed
            if (EVP_DigestSignUpdate(ctx, message.c_str(), message.length()) <= 0) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            // Get the length of the signature
            size_t signatureLength;
            if (EVP_DigestSignFinal(ctx, nullptr, &signatureLength) <= 0) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            // Allocate a buffer for the signature
            std::vector<unsigned char> signature(signatureLength);

            // Sign the message and store the signature in the buffer
            if (EVP_DigestSignFinal(ctx, &signature[0], &signatureLength) <= 0) {
                EVP_MD_CTX_free(ctx);
                return "";
            }

            // Clean up
            EVP_MD_CTX_free(ctx);

            // Convert the signature to a string and return it
            return std::string(reinterpret_cast<const char*>(&signature[0]), signatureLength);
        }

        bool VerifyMessage(const std::string& message, const std::string& signature, EVP_PKEY* publicKey) {
            // Create a new context for verification
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();

            // Initialize the context for SHA-256
            if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, publicKey) <= 0) {
                EVP_MD_CTX_free(ctx);
                return false;
            }

            // Update the context with the message to be verified
            if (EVP_DigestVerifyUpdate(ctx, message.c_str(), message.length()) <= 0) {
                EVP_MD_CTX_free(ctx);
                return false;
            }

            // Verify the signature
            int result = EVP_DigestVerifyFinal(ctx, (const unsigned char*)signature.c_str(), signature.length());
            EVP_MD_CTX_free(ctx);

            return (result == 1);
        }

        // Function to generate AES key of length key_len bits
        std::string GenerateAESKey(int key_len) {
            unsigned char* aes_key = new unsigned char[key_len / 8];

            // Generate a cryptographically secure pseudo-random number as the key
            RAND_bytes(aes_key, key_len / 8);

            // Convert key to hex format and return as a string
            std::string hex_key;
            char hex_buffer[3];
            for (int i = 0; i < key_len / 8; i++) {
                sprintf_s(hex_buffer, "%02x", aes_key[i]);
                hex_key += hex_buffer;
            }

            delete[] aes_key; // Deallocate memory allocated by new[]

            return hex_key;
        }

        EVP_PKEY* GetPublicRSAKey(EVP_PKEY* pkey) {
            // Write public key to memory buffer
            BIO* pubBIO = BIO_new(BIO_s_mem());
            if (PEM_write_bio_PUBKEY(pubBIO, pkey) != 1) {
                EVP_PKEY_free(pkey);
                BIO_free_all(pubBIO);
                return nullptr;
            }

            // Get the memory buffer as a string
            BUF_MEM* pubBuffer;
            BIO_get_mem_ptr(pubBIO, &pubBuffer);

            // Create a new EVP_PKEY object from the public key string
            EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(BIO_new_mem_buf(pubBuffer->data, pubBuffer->length), nullptr, nullptr, nullptr);

            BIO_free_all(pubBIO);
            return publicKey;
        }

        EVP_PKEY* GetPrivateRSAKey(EVP_PKEY* pkey) {
            // Write private key to memory buffer
            BIO* privBIO = BIO_new(BIO_s_mem());
            if (PEM_write_bio_PrivateKey(privBIO, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                EVP_PKEY_free(pkey);
                BIO_free_all(privBIO);
                return nullptr;
            }

            // Get the memory buffer as a string
            BUF_MEM* privBuffer;
            BIO_get_mem_ptr(privBIO, &privBuffer);

            // Create a new EVP_PKEY object from the private key string
            EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(BIO_new_mem_buf(privBuffer->data, privBuffer->length), nullptr, nullptr, nullptr);

            BIO_free_all(privBIO);
            return privateKey;
        }

        std::string EncryptWithPublicKey(EVP_PKEY* public_key, const std::string& aes_key) {
            // Set up encryption context with public key
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);
            if (!ctx) {
                return "";
            }

            if (EVP_PKEY_encrypt_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            // Allocate space for encrypted AES key
            size_t outlen = 0;
            if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (const unsigned char*)aes_key.c_str(), aes_key.length()) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            std::vector<unsigned char> encrypted_key(outlen);

            // Encrypt AES key with public key
            if (EVP_PKEY_encrypt(ctx, encrypted_key.data(), &outlen, (const unsigned char*)aes_key.c_str(), aes_key.length()) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            EVP_PKEY_CTX_free(ctx);

            // Convert encrypted key to hex format
            std::string hex_key;
            char hex_buffer[3];

            for (int i = 0; i < encrypted_key.size(); i++) {
                sprintf_s(hex_buffer, "%02x", encrypted_key[i]);
                hex_key += hex_buffer;
            }

            return hex_key;
        }

        std::string DecryptWithPrivateKey(EVP_PKEY* private_key, const std::string& encrypted_aes) {
            // Convert encrypted key from hex format to binary format
            std::vector<unsigned char> encrypted_key;
            for (size_t i = 0; i < encrypted_aes.length(); i += 2) {
                unsigned char byte = (unsigned char)std::stoi(encrypted_aes.substr(i, 2), nullptr, 16);
                encrypted_key.push_back(byte);
            }

            // Set up decryption context with private key
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
            if (!ctx) {
                return "";
            }
            if (EVP_PKEY_decrypt_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            // Allocate space for decrypted AES key
            size_t outlen = 0;
            if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, encrypted_key.data(), encrypted_key.size()) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return "";
            }
            std::vector<unsigned char> decrypted_key(outlen);

            // Decrypt AES key with private key
            if (EVP_PKEY_decrypt(ctx, decrypted_key.data(), &outlen, encrypted_key.data(), encrypted_key.size()) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            EVP_PKEY_CTX_free(ctx);

            // Convert decrypted key to std::string format
            std::string aes_key(decrypted_key.begin(), decrypted_key.end());

            return aes_key;
        }
	}
}