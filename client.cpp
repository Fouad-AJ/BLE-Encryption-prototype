#include "ecdh.cpp"

int connect_to_server(char* server_ip, int port) {
    
    /* setup a socket */
    struct hostent* host = gethostbyname(server_ip); 
    sockaddr_in sendSockAddr;   
    bzero((char*)&sendSockAddr, sizeof(sendSockAddr)); 
    sendSockAddr.sin_family = AF_INET; 
    sendSockAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
    sendSockAddr.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    
    /* try to connect */
    int status = connect(fd, (sockaddr*) &sendSockAddr, sizeof(sendSockAddr));
    status < 0 ? 
    cout<<"Error connecting to socket!"<<endl : cout << "Connected to the server!" << endl;
    cout << "\n===================================" << endl;

    return fd;
}

int main(int argc, char *argv[])
{
    
    if(argc != 3) {
        cerr << "Usage: ip_address port" << endl; exit(0); 
    } 

    int fd = connect_to_server(argv[1], atoi(argv[2]));

    /* Do ECDH shared secret exchange*/
    size_t shared_secret_length;
	unsigned char* shared_secret = perform_ECDH_exchange(fd, &shared_secret_length);

    /* Derive AES 128-bit key from shared secret */
    unsigned char aes_key[AES_KEY_SIZE];
    derive_aes_key(shared_secret, shared_secret_length, aes_key);

    /* Do the nonce handshake to confirm encryption/decryption works both ways */
    int result = client_nonce_handshake(fd, aes_key);
    if (result != 0) {
        cout << "Failed to establish a secure channel" << endl;
        cout << result << endl;
        close(fd);
        exit(1);
    }
    
    cout << "=======================" << endl;

    while (1) {

        /* Receive and decrypt data */
        string data = receive_decrypt_unpad(fd, aes_key);

        /* Display */
        display_advertisement1(data);
    }

    close(fd);
    cout << "Connection closed" << endl;
    
    return 0;    
}