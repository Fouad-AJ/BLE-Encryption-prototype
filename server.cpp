#include "ecdh.cpp"

int accept_connection(int socket_fd) {
    sockaddr_in new_socket_addr;
    socklen_t new_socket_addr_size = sizeof(new_socket_addr);
    
    int new_fd = accept(socket_fd, (sockaddr *)&new_socket_addr, &new_socket_addr_size);
    if(new_fd < 0) {
        cerr << "Error accepting request from client!" << endl;
        exit(1);
    }
    cout << "Connected with client!" << endl;
    cout << "\n===================================" << endl;
    return new_fd;
}

vector<int> open_connection(int port) {

    vector<int> fd_vector;

    /* setup a socket */
    sockaddr_in server_addr;
    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
 
    /* open socket */
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd < 0) {
        cerr << "Error establishing the server socket" << endl;
        exit(0);
    }

    /* bind the socket */
    int bind_status = bind(socket_fd, (struct sockaddr*) &server_addr, sizeof(server_addr));
    if(bind_status < 0) {
        cerr << "Error binding socket to local address" << endl;
        exit(0);
    }
    cout << "Waiting for a client to connect..." << endl;
    
    /* listen to up to 3 */
    listen(socket_fd, 3);

    fd_vector.push_back(accept_connection(socket_fd));
    fd_vector.push_back(socket_fd);
    return fd_vector;
}

/* close all socket connections */
void close_connections(vector<int> fd_vector) {
    for(int i = 0; i<fd_vector.size(); i++)
        close(fd_vector[i]);
    cout << "Connection closed..." << endl;
}

int main(int argc, char *argv[])
{
    if(argc != 2) {
        cerr << "Usage: port" << endl;
        exit(0);
    }
    srand(time(0));

    vector<int> fd_vector = open_connection(atoi(argv[1]));
    
    /* Do ECDH shared secret exchange*/
    size_t shared_secret_length;
	unsigned char* shared_secret = perform_ECDH_exchange(fd_vector[0], &shared_secret_length);

    /* Derive AES 128-bit key from shared secret */
    unsigned char aes_key[AES_KEY_SIZE];
    derive_aes_key(shared_secret, shared_secret_length, aes_key);
    
    /* Do the nonce handshake to confirm encryption/decryption works both ways */
    int result = server_nonce_handshake(fd_vector[0], aes_key);
    if (result != 0) {
        cout << "Failed to establish a secure channel" << endl;
        close_connections(fd_vector);
        exit(1);
    }

    cout << "=======================" << endl;

    /* Start advertising */
    Advertisement_Manager AdManager;
    while (1) {

        /* Generate and display advertisement before sending */
        string data = AdManager.generate_advertisement1();
        display_advertisement1(data);

        /* Encrypt and send advertisement */
        pad_encrypt_send(fd_vector[0], data, aes_key);

        sleep(4);
    }

    close_connections(fd_vector);
    return 0;   
}