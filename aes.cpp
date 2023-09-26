#include <iostream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

using namespace std;

/* AES key and IV (128-bit) */
static const unsigned char aes_iv[] = "1234567890abcdef";
const int AES_KEY_SIZE = 16;

/* Function to derive AES key using EVP-based key derivation */
bool derive_aes_key(const unsigned char* shared_secret, int shared_secret_len, unsigned char* aes_key) {
    
    memset(aes_key, 0, AES_KEY_SIZE);
    if (shared_secret_len < AES_KEY_SIZE) {
        cerr << "Shared secret is shorter than key size" << endl;
        return false;
    }

    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len = EVP_MAX_MD_SIZE;

    /* Use HMAC to derive a pseudorandom key (PRK) from the shared secret */
    if (HMAC(EVP_sha256(), shared_secret, shared_secret_len, NULL, 0, prk, &prk_len) == NULL) {
        cerr << "Error generating key from seed" << endl;
        return false;
    }

    /* If PRK is shorter than AES key size, hash PRK until it reaches the desired length */
    while (prk_len < AES_KEY_SIZE) {
        if (HMAC(EVP_sha256(), shared_secret, shared_secret_len, prk, prk_len, prk, &prk_len) == NULL) {
            cerr << "Error generating key from seed" << endl;
            return false;
        }
    }

    /* Use PRK as the AES key */
    memcpy(aes_key, prk, AES_KEY_SIZE);
    return true;
}

/* Encrypt using AES-CBC 128-bit */
string aes_cbc_encrypt(const string input, unsigned char* aes_key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char ciphertext[input.length() + AES_BLOCK_SIZE];

    /* Create a new EVP_CIPHER_CTX */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Failed to create an EVP_CIPHER_CTX." << endl;
        return "";
    }

    /* Initialize the AES encryption context */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv) != 1) {
        cerr << "Failed to initialize AES encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    /* Perform AES encryption in an update step */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)input.c_str(), input.length()) != 1) {
        cerr << "AES encryption update failed." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    /* Finalize AES encryption */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        cerr << "AES encryption finalization failed." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    /* Free the EVP_CIPHER_CTX */
    EVP_CIPHER_CTX_free(ctx);

    return string(reinterpret_cast<char *>(ciphertext), ciphertext_len);
}

/* Decrypt AES-CBC 128-bit ciphertext */
string aes_cbc_decrypt(const string &ciphertext, unsigned char* aes_key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char plaintext[ciphertext.length()];

    /* Create a new EVP_CIPHER_CTX */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Failed to create an EVP_CIPHER_CTX." << endl;
        return "";
    }

    /* Initialize the AES decryption context */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv) != 1) {
        cerr << "Failed to initialize AES decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    /* Perform AES decryption in an update step */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, (unsigned char *)ciphertext.c_str(), ciphertext.length()) != 1) {
        cerr << "AES decryption update failed." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    /* Finalize AES decryption */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        cerr << "AES decryption finalization failed." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    /* Free the EVP_CIPHER_CTX */
    EVP_CIPHER_CTX_free(ctx);

    return string(reinterpret_cast<char *>(plaintext), plaintext_len);
}


/* Add PKCS#7 padding to the input data */
string add_pkcs7_padding(const string &input, int block_size) {
    int padding_len = block_size - (input.length() % block_size);
    char padding_byte = static_cast<char>(padding_len);
    return input + string(padding_len, padding_byte);
}

/* Remove PKCS#7 padding from the padded input */
string remove_pkcs7_padding(const string &padded_input) {
    if (padded_input.empty()) {
        cerr << "Input for padding removal is empty." << endl;
        return "";
    }

    char padding_byte = padded_input[padded_input.length() - 1];
    int padding_len = static_cast<int>(padding_byte);

    /* Check if padding is valid */
    if (padding_len < 1 || padding_len > AES_BLOCK_SIZE || padded_input.length() < padding_len) {
        cerr << "Invalid PKCS#7 padding detected." << endl;
        return "";
    }

    for (int i = 1; i <= padding_len; ++i) {
        if (padded_input[padded_input.length() - i] != padding_byte) {
            cerr << "Invalid PKCS#7 padding detected." << endl;
            return "";
        }
    }

    return padded_input.substr(0, padded_input.length() - padding_len);
}

unsigned int generate_nonce() {

    /* Seed the random number generator */
    RAND_poll();

    /* Generate a random number */
    unsigned char randomness[4]; // Change the size according to your needs
    if (RAND_bytes(randomness, sizeof(randomness)) != 1) {
        cerr << "Error generating random number." << endl;
        return 1;
    }

    /* Convert the random data to an integer */
    unsigned int random_number;
    memcpy(&random_number, randomness, sizeof(random_number));


    RAND_cleanup();

    return random_number;
}


