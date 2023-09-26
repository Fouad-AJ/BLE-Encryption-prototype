#include <string.h>
#include <openssl/pem.h>
#include <sys/socket.h>
#include <sstream>
#include <vector>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include<netdb.h>
#include "aes.cpp"
#include "AdManager.cpp"


#define HANDSHAKE_OK "OK!"
#define HANDSHAKE_FAILED "FAILED!"

/* Wrapper around send API */
int socket_send(int fd, const void *buffer, size_t len, int flags) {
    return send(fd, buffer, len, flags);
}

/* Wrapper around recv API */
int socket_recv(int fd, void *buffer, size_t len, int flags) {
    return recv(fd, buffer, len, flags);
}

void pad_encrypt_send(int fd, string data, unsigned char *aes_key) {
    string padded_data = add_pkcs7_padding(data, AES_BLOCK_SIZE);
    string ciphertext = aes_cbc_encrypt(padded_data, aes_key);
    socket_send(fd, ciphertext.c_str(), ciphertext.length(), 0);
}

string receive_decrypt_unpad(int fd, unsigned char *aes_key) {
    char ciphertext[1024];
    memset(ciphertext, 0, sizeof ciphertext);
    socket_recv(fd, ciphertext, sizeof ciphertext, 0);
    string plain_text_padded = aes_cbc_decrypt(ciphertext, aes_key);
    return remove_pkcs7_padding(plain_text_padded);
}

int client_nonce_handshake(int fd, unsigned char *aes_key) {
      /* Send nonce */
    string response;
    unsigned long nonce = generate_nonce();
    cout << "\nNonce: " << nonce << endl;
    pad_encrypt_send(fd, to_string(nonce), aes_key);

    /* Receive nonce-1 */
    string nonce_1 = receive_decrypt_unpad(fd, aes_key); 
    cout << "Nonce-1: " << nonce_1 << endl;

    if(stol(nonce_1) == nonce-1) {
        socket_send(fd, HANDSHAKE_OK, sizeof HANDSHAKE_OK, 0);
        return 0;
    }  

    socket_send(fd, HANDSHAKE_FAILED, sizeof HANDSHAKE_FAILED, 0);
    return 1;
}

int server_nonce_handshake(int fd, unsigned char *aes_key) {

    /* Receive nonce */
    string nonce = receive_decrypt_unpad(fd, aes_key); 
    cout << "\nNonce: " << nonce << endl;

    /* return nonce-1 */
    pad_encrypt_send(fd, to_string((stol(nonce))-1), aes_key);

    /* Receive response */
    char response[32];
    memset(response, 0, sizeof response);
    socket_recv(fd, response, sizeof response, 0);
    cout << response << endl;

    return strncmp(HANDSHAKE_OK, response, sizeof HANDSHAKE_OK);
}

void display_advertisement1(string input) {
    istringstream iss(input);
    vector<string> lines;
    string line;

    while (getline(iss, line, '\n')) {
        lines.push_back(line);
    }

    cout << "Price: $" << lines.at(0) << endl;
    cout << "Category: " << lines.at(1) << endl;
    cout << "Title: " << lines.at(2) << endl;
    cout << "================================" << endl;
}
