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


typedef struct {
    int socket;
    char name[256];
} Client;

Client clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

//encrypter les message 
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}



void *handle_client(void *arg) {

  int client_socket = *((int *)arg);
    if (client_count < MAX_CLIENTS) {
      
        char client_id[256];
        //unicite des noms
  
char result[] = "exist";
char result2[] = "done";

int ind;
while (1) {
    ind = 0;
    int recv_bytes = recv(client_socket, client_id, sizeof(client_id), 0);
    if (recv_bytes <= 0) {
        close(client_socket);
        pthread_exit(NULL);
    }

    client_id[recv_bytes] = '\0'; // Assurez-vous que la chaîne est bien terminée

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (strcmp(clients[i].name, client_id) == 0) {
            send(client_socket, result, strlen(result), 0);
            ind++;
            break;
        }
    }

    if (ind == 0) {
        send(client_socket, result2, strlen(result2), 0);
        break;
    }
}


//remplir le tableau
        pthread_mutex_lock(&clients_mutex);
        clients[client_count].socket = client_socket;
        strcpy(clients[client_count].name, client_id);
        client_count++;
        pthread_mutex_unlock(&clients_mutex);
        
           unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        unsigned char *iv = (unsigned char *)"0123456789012345";

        char buffer[1024];
        char msg[1284]; // buffer + client_id
   int recv_bytes;
        while (1) {
            memset(buffer, 0, sizeof(buffer));
            recv_bytes = recv(client_socket, buffer, sizeof(buffer), 0);

            if (recv_bytes <= 0) {
                break;
            }
            
               unsigned char decryptedtext[1024];
            int decryptedtext_len = decrypt((unsigned char *)buffer, recv_bytes, key, iv, decryptedtext);
            decryptedtext[decryptedtext_len] = '\0';

            // Préparer le message avec l'identifiant du client
            snprintf(msg, sizeof(msg), "%s: %s", client_id, decryptedtext);

            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < client_count; i++) {
                if (clients[i].socket != client_socket) {
                    send(clients[i].socket, msg, strlen(msg), 0);
                }
            }
            pthread_mutex_unlock(&clients_mutex);
        }

        close(client_socket);
        pthread_mutex_lock(&clients_mutex);
        client_count--;
        pthread_mutex_unlock(&clients_mutex);
    } else {
    
                 char full_msg[] = "Server is full\n";
            send(client_socket, full_msg, strlen(full_msg), 0);
            close(client_socket);

    }

    return NULL;
}

int main() {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5000);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_socket, MAX_CLIENTS);
           
           
    while (1) {
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket < 0) {
            perror("accept");
            continue;
        }
      
           pthread_t tid;
            pthread_create(&tid, NULL, handle_client, &client_socket)   ;
        
    }

    close(server_socket);
    return 0;
}


