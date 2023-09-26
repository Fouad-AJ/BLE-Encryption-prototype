#include <stdio.h>
#include <openssl/ecdh.h>
#include "util.cpp"

#define CURVE_NAME NID_X9_62_prime256v1

void print_public_key(const EC_KEY *key) {
    const EC_POINT *key_public = EC_KEY_get0_public_key(key);

    /* Extract X and Y coordinates for public key */
    BIGNUM *key_x = BN_new();
    BIGNUM *key_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key), key_public, key_x, key_y, NULL);

    printf("Public Key (X, Y):\n");
    printf("X: %s\n", BN_bn2hex(key_x));
    printf("Y: %s\n", BN_bn2hex(key_y));

    BN_free(key_x);
    BN_free(key_y);
}

EC_KEY *generate_ec_key(void) {
    /* Create an EC key object */
    EC_KEY *ec_key;

    /* Initialize the key with a specific elliptic curve */
    if (NULL == (ec_key = EC_KEY_new_by_curve_name(CURVE_NAME))) {
        printf("Failed to initialize the elliptic curve key\n");
        return NULL;
    }

    /* Generate a key pair using the selected elliptic curve */
    if (1 != EC_KEY_generate_key(ec_key)) {
        printf("Failed to generate the key pair\n");
        return NULL;
    }

    return ec_key;
}


unsigned char *derive_shared_secret(const EC_KEY *own_key, const EC_POINT *peer_public_key,
                                    size_t *secret_length) {

    int curve_degree;
    unsigned char *shared_secret;

    /* Get the degree of the elliptic curve associated with own_key */
    curve_degree = EC_GROUP_get_degree(EC_KEY_get0_group(own_key));
    /* Calculate the length of the shared secret in bytes */
    *secret_length = (curve_degree + 7) / 8;

    /* Allocate memory for the shared secret */
    if (NULL == (shared_secret = (unsigned char *)OPENSSL_malloc(*secret_length))) {
        printf("Failed to allocate memory for the shared secret");
        return NULL;
    }

    /* Derive the shared secret using ECDH */
    *secret_length = ECDH_compute_key(shared_secret, *secret_length,
                                      peer_public_key, own_key, NULL);

    /* Check if the secret derivation was successful */
    if (*secret_length <= 0) {
        OPENSSL_free(shared_secret);
        return NULL;
    }
    return shared_secret;
}

string serialize_public_key_to_pem(EC_KEY *key) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(bio, key);
    BUF_MEM *bufPtr;
    BIO_get_mem_ptr(bio, &bufPtr);
    std::string pem_key(bufPtr->data, bufPtr->length);
    BIO_free(bio);
    return pem_key;
}

EC_KEY *deserialize_pem_to_public_key(const std::string &pem_data) {
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, pem_data.c_str(), pem_data.length());
    EC_KEY *public_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return public_key;
}


unsigned char* perform_ECDH_exchange(int fd, size_t *shared_secret_length) {

    EC_KEY *own_key = generate_ec_key();

    /* Serialize and send own public key */
    string own_public_key_pem = serialize_public_key_to_pem(own_key);
    long bytes_sent = socket_send(fd, own_public_key_pem.c_str(), own_public_key_pem.length(), 0);

    /* Receive and deserialize peer's public key */
    char received_key_pem[1024]; 
    ssize_t bytes_received = socket_recv(fd, received_key_pem, sizeof(received_key_pem), 0);
    EC_KEY *deserialized_public_key = deserialize_pem_to_public_key(received_key_pem);
    
    /* Derive the shared secret */
    unsigned char *shared_secret = derive_shared_secret(own_key, EC_KEY_get0_public_key(deserialized_public_key), shared_secret_length);

    /* Print the derived shared secret */
    cout << "\nShared Secret (ECDH): ";
    for (int i = 0; i < *shared_secret_length; i++)
        printf("%x", shared_secret[i]);
    cout << "\n\n" << string(85,'=') << endl; 
    return shared_secret;
}
