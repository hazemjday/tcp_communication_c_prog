#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>


#define MAX_CLIENTS 2


//pour le cryptage

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}



void *receive_messages(void *arg) {
    int client_socket = *((int *)arg);
    char buffer[1284];
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int recv_bytes = recv(client_socket, buffer, sizeof(buffer), 0);
        if (recv_bytes <= 0) {
            break;
        }
        printf("%s\n", buffer);
    }
    return NULL;
}

int main() {
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5000);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return 1;
    }
//nom unique
    char client_id[256];
     char result[]="done";
      char servermsg[254];

while (1) {
    printf("Entrer votre nom: ");
    fgets(client_id, sizeof(client_id), stdin);
    client_id[strcspn(client_id, "\n")] = 0; 

    if (send(client_socket, client_id, strlen(client_id), 0) < 0) {
        perror("send");
        return 1;
    }

    // Recevoir la réponse du serveur
    int recv_bytes = recv(client_socket, servermsg, sizeof(servermsg), 0);
    if (recv_bytes <= 0) {
        perror("recv");
        return 1;
    }
    servermsg[recv_bytes] = '\0'; // Assurez-vous que la chaîne est bien terminée

    if (strcmp("done", servermsg) == 0) {
        break;
    } else {
        printf("\n Nom existant. Essayez un autre.\n");
    }
}

    pthread_t tid;
    pthread_create(&tid, NULL, receive_messages, &client_socket);
    
      unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";

    char message[1284];
    while (1) {
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = 0; 
       
        unsigned char ciphertext[1284];
        int ciphertext_len = encrypt((unsigned char *)message, strlen(message), key, iv, ciphertext);
        
        if (send(client_socket, ciphertext, ciphertext_len, 0) < 0) {
            perror("send");
            break;
        }
    }

    close(client_socket);
    return 0;
}

