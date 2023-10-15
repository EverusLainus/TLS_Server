#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include "openssl/x509.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"

#include <poll.h>


int get_listener(){

    //get addr
    int rv;
    struct addrinfo  hints, *getaddrinfo_res, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    rv = getaddrinfo(NULL, "44333", &hints, &getaddrinfo_res);
    if(rv != 0){
        printf("error: getaddrinfo\n");
    }

    //socket & bind
    int socket_res;
    //returns a socket descriptor
    int bind_res;
    for(p=getaddrinfo_res; p != NULL; p=p->ai_next){
        socket_res= socket(p->ai_family, p->ai_socktype, 0);
        printf("resuts from socket is %d \n", socket_res);
        if(socket_res==-1){
            perror("socket");
            continue;           
        }

        bind_res = bind(socket_res, p->ai_addr, p->ai_addrlen);
        printf("resuts from bind is %d \n", bind_res);
        if(bind_res==-1){
            perror("bind");
            continue;
        }
        break;
    }
    if(p==NULL){
        perror("failed to bind");
    }

    //listen
    int listen_res;
    listen_res= listen(socket_res, 10);
    if(listen_res==-1){
        perror("listen");
        return -1;
    }
    return socket_res;
}


void add_to_pdfs( struct pollfd *pfds[], int newfd, int *fd_count, int *fd_size){
    //not enough storage
    if(*fd_count == *fd_size){
        *fd_size *= 2;

        *pfds = realloc( *pfds, sizeof (** pfds) * (*fd_size));

    }
    (*pfds)[*fd_count].fd = newfd;
    (*pfds)[*fd_count].events=POLLIN;
}

SSL_CTX *create_context(){
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if(ctx == 0){
        perror("SSL_CTX_new");
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx){
   int use_cert = SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
   if(use_cert <= 0){
    perror("use_cert");
   }

    int use_key = SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);
   if(use_key <= 0){
    perror("use_key");
   }    
}

int main(){

SSL_library_init();
OpenSSL_add_all_algorithms();

    //ssl
    SSL_CTX *ctx;

 //get server fd
    int server_fd;
    server_fd = get_listener();

    signal(SIGPIPE, SIG_IGN);

    //poll
    int fd_count =0; //what do i do with you
    int fd_size = 5;
    //allocate fd_size times size of single pfds
    struct pollfd *pfds = malloc( sizeof * pfds * fd_size);

    pfds[0].fd= server_fd;
    pfds[0].events= POLLIN;   
    fd_count =1;

//create context
    ctx =   create_context();

//configure files
    configure_context(ctx);

//accept and write
    while(1){

        //get the number of active fds
        int poll_count = poll(pfds, fd_count, 2500);

        //if the is none active
        if(poll_count==-1){
            perror("poll_count");
            return 1;
        }

        int client_fd =0;
        struct sockaddr_storage their_addr;
        

        int ssl_accept;
        SSL *ssl;
        ssl = SSL_new(ctx);

       //run through existing connection
        for(int i=0; i<fd_count; i++){
                if(pfds[i].fd == server_fd){
                    int newfd;
                    socklen_t addr_size = sizeof their_addr;
                    newfd = accept(server_fd, (struct sockaddr *)&their_addr, &addr_size);
                    if(newfd == -1){
                        perror("accept");
                        return -1;
                    }
                    //create new ssl; connect with newfd; accept_Ssl
                    SSL_set_fd(ssl, newfd);             
                    ssl_accept = SSL_accept(ssl);

                    if(ssl_accept<=0){
                        perror("ssl_accept");
                        return -1;
                    }
                    else{
                        add_to_pdfs(&pfds, newfd, &fd_count, &fd_size);
                        char reply[] = "To God be the Glory!"; 
                        SSL_write(ssl, reply, strlen(reply));
                    }                  
                }
            } //END for loop                  
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }// END while loop
    close(server_fd);
    SSL_CTX_free(ctx);
}

/*
compile using:
$(CC) $(CFLAGS) source_file.c -o output_file -lssl -lcrypto -I/path/to/openssl/include -L/path/to/openssl/library -L/path/to/libressl/library -I/path/to/libressl/include

* make certificate and save it it the same folder as source file.

curl -k -v --http0.9 https://IP:PORT
*/