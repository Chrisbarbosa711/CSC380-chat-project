//SUBMISSION FOLDER VERSION
#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <getopt.h>
#include <gmp.h>
#include "dh.h"
#include "keys.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;
static unsigned char* SS = NULL;


static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

//compute the MAC for the messages
unsigned char* computeMAC(unsigned char* data, int data_len, unsigned char* key, unsigned char* mac_out){
  unsigned int mac_len = SHA256_DIGEST_LENGTH;
  
  if(HMAC(EVP_sha256(), key, 32, data, data_len, mac_out, &mac_len) == NULL){
    error("HMAC calculation error");
  }
  
  return mac_out;
}

int encryption(unsigned char* pt, int pt_len, unsigned char* key, unsigned char* IV, unsigned char* ct){
  EVP_CIPHER_CTX *ctx;
  int len, ct_len;
  
  printf("encrypting message\n");
  if(!(ctx = EVP_CIPHER_CTX_new())){
    error("ciphertext creation error");
  }
  
  if(IV == NULL){
    if(RAND_bytes(IV, EVP_MAX_IV_LENGTH) != 1){
      error("error generating IV");
    }
  }
  
  
  if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, IV) != 1){
    error("aes encryption error");
  }
  else if(EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1){
    error("encryption update error");
  }
  else{
    ct_len = len;
  }
  
  if(EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1){
    error("encryption error");
  }
  else{
    ct_len += len;
  }
  
  EVP_CIPHER_CTX_free(ctx);
  return ct_len;
}

int decryption(unsigned char* ct, int ct_len, unsigned char* key, unsigned char* IV, unsigned char* pt){
  EVP_CIPHER_CTX *ctx;
  int len, pt_len;
  //for testing
  printf("decrypting message\n");
  
  if(!(ctx = EVP_CIPHER_CTX_new())){
    error("ciphertext creation error");
  }
  else if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, IV) != 1){
    error("aes decryption error");
  }
  else if(EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1){
    error("decryption update error");
  }
  else{  
    pt_len = len;
  }
  if(EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1){
    ERR_print_errors_fp(stderr);
    error("decryption error"); 
  }
  else{
    pt_len += len;
  }
  
  EVP_CIPHER_CTX_free(ctx);
  
  return pt_len;
}

static void sendMessage(GtkWidget* w, gpointer data)
{
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;   /* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	//size_t len = g_utf8_strlen(message,-1);
	size_t len = strlen(message);
	//ADDED FOR ENC/DEC stuff
	unsigned char ct[1024];
	unsigned char IV[EVP_MAX_IV_LENGTH];
	int ct_len = encryption((unsigned char*)message, len, SS, IV, ct);
	
	//compute MAC on ct so we do MAC(ENC)
	unsigned char mac[SHA256_DIGEST_LENGTH];
	computeMAC(ct, ct_len, SS, mac);
	
	unsigned char message_with_IV_and_MAC[ct_len + EVP_MAX_IV_LENGTH + SHA256_DIGEST_LENGTH];
	//copy each of the message, and MAC, etc correctly
	//using the following offsets
	memcpy(message_with_IV_and_MAC, IV, EVP_MAX_IV_LENGTH);
	memcpy(message_with_IV_and_MAC + EVP_MAX_IV_LENGTH, ct, ct_len);
	memcpy(message_with_IV_and_MAC + EVP_MAX_IV_LENGTH + ct_len, mac, SHA256_DIGEST_LENGTH); 
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */
	ssize_t nbytes;
	if ((nbytes = send(sockfd, message_with_IV_and_MAC, ct_len + EVP_MAX_IV_LENGTH + SHA256_DIGEST_LENGTH, 0)) == -1)
		error("send failed");

	tsappend(message, NULL, 1);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);
}

//the following are for sending are receiving the keys over the
//socket for the handshake
//the message_type is used to tag the sends so that the listening 
//thread knows what they are supposed to read for what value
static void sendKeyOverSocket(int sockfd, int message_type, mpz_t key){
  
  int message_type_net = htonl(message_type);
  if(send(sockfd, &message_type_net, sizeof(message_type_net), 0) < 0){
    perror("failed to send message type");
    return;
  }
  
  char* key_str = mpz_get_str(NULL, 10, key);
  int key_len = strlen(key_str);
  if((send(sockfd, &key_len, sizeof(int), 0)) < 0){
    error("failed to send key length");
  }
  
  if((send(sockfd, key_str, key_len, 0)) < 0){
    error("failed to send key data");
  }
  free(key_str);
}

static void receiveKeyOverSocket(int sockfd, mpz_t key){
  int message_type_net;
  
  if(recv(sockfd, &message_type_net, sizeof(message_type_net), 0) <= 0){
    perror("failed to receive message type");
    return;
  }
  
  int key_len;
  if(recv(sockfd, &key_len, sizeof(int), 0) <= 0){
    perror("failed to recieve key length");
    return;
  }
  
  char* key_str = (char*)malloc(key_len + 1);
  if(recv(sockfd, key_str, key_len, 0) <= 0){
    perror("failed to receive key data");
    free(key_str);
    return;
  }
  key_str[key_len] = '\0';
  
  if(mpz_set_str(key, key_str, 10) != 0){
    fprintf(stderr, "failed to convert key string to mpz_t");
    free(key_str);
    return;
  }
  
  free(key_str);
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	
	//must create a flag us to tell which thread we are currently in
	//in order to differentiate who we create the keys for
	//etc.
	
	int listener_fl = 0;
	
	if(argc > 1 && strcmp(argv[1], "-l") == 0){
	  listener_fl = 1;
	}
	
	if (isclient) {
		initClientNet(hostname,port);
	} 
	else {
		initServerNet(port);
	}
	
	if(listener_fl){
	  printf("client connection initiated...\n");
	  NEWZ(sk_c); //client private key
	  NEWZ(Ckey);
	  dhGen(sk_c, Ckey);
	  //for testing
	  //printf("Ckey: ");
	  //gmp_printf("%d\n", Ckey);
	  printf("send CKey\n");
	  sendKeyOverSocket(sockfd, 1, Ckey);
	  
	  
	  //store the recieved key
	  mpz_t Skey;
	  mpz_init(Skey);
	  printf("receive Skey\n");
	  receiveKeyOverSocket(sockfd, Skey);
	  //gmp_printf("%d\n", Skey); for testing
	  
	  
	  //client ephemeral key
	  NEWZ(pk_c);
	  NEWZ(CephKey);
	  dhGen(pk_c, CephKey);
	  //for testing
	  //printf("CephKey: ");
	  //gmp_printf("%d\n", CephKey);
	  printf("send CephKey\n");
	  sendKeyOverSocket(sockfd, 2, CephKey);
	  
	  
	  mpz_t SephKey;
	  mpz_init(SephKey);
	  printf("receive SephKey\n");
	  receiveKeyOverSocket(sockfd, SephKey);
	  //gmp_printf("%d\n", SephKey); for testing 
	  
	  //now 3dh stuff
	  unsigned char keybuf[32];
	  size_t buflen = 32;
	  
	  dh3Final(sk_c, Ckey, pk_c, CephKey, Skey, SephKey, keybuf, buflen);
	  
	  SS = malloc(buflen);
	  memcpy(SS, keybuf, buflen);
	  
	   //for testing
	  //printf("SS in client\n");
	  //for(size_t i = 0; i < buflen; i++){
	    //printf("%02x ", SS[i]);
	  //}
	  //printf("\n");
	}
	else{
	  printf("server connection initiated...\n");
	  NEWZ(sk_s); //server private key
	  NEWZ(Skey);
	  dhGen(sk_s, Skey);
	  //for testing
	  //printf("Skey: ");
	  //gmp_printf("%d\n", Skey);
	  printf("send SKey\n");
	  sendKeyOverSocket(sockfd, 1, Skey);
	  
	  
	  //receive the key from the client
	  //logic is the same as prior
	  mpz_t Ckey;
	  mpz_init(Ckey);
	  printf("receive CKey\n");
	  receiveKeyOverSocket(sockfd, Ckey);
	  //gmp_printf("%d\n", Ckey);
	  
	  //server ephemeral key
	  NEWZ(pk_s);
	  NEWZ(SephKey);
	  dhGen(pk_s, SephKey);
	  //printf("SephKey: ");
	  //gmp_printf("%d\n", SephKey);
	  printf("send SephKey\n");
	  sendKeyOverSocket(sockfd, 2, SephKey);
	  
	  
	  //receive client ephemeral key
	  mpz_t CephKey;
	  mpz_init(CephKey);
	  printf("receive CephKey\n");
	  receiveKeyOverSocket(sockfd, CephKey);
	  //gmp_printf("%d\n", CephKey);
	  
	  
	  //now 3dh stuff
	  unsigned char keybuf[32];
	  size_t buflen = 32;
	  
	  dh3Final(sk_s, Skey, pk_s, SephKey, Ckey, CephKey, keybuf, buflen);
	  
	  SS = malloc(buflen);
	  memcpy(SS, keybuf, buflen);
	  
	  //for testing
	  //printf("SS global\n");
	  //for(size_t i = 0; i < buflen; i++){
	    //printf("%02x ", SS[i]);
	  //}
	  //printf("\n");
	  
	}
	
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{
	size_t maxlen = 1024;
	unsigned char ct[maxlen]; /* might add \n and \0 */
	ssize_t nbytes;
	unsigned char IV[EVP_MAX_IV_LENGTH];
	
	while (1) {
		if ((nbytes = recv(sockfd, ct, maxlen, 0)) == -1)
			error("recv failed");
			
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}
		
		memcpy(IV, ct, EVP_MAX_IV_LENGTH);
		
		int ct_len = nbytes - EVP_MAX_IV_LENGTH - SHA256_DIGEST_LENGTH;
		unsigned char* nct = ct + EVP_MAX_IV_LENGTH;
		
		
		unsigned char received_mac[SHA256_DIGEST_LENGTH];
		
		memcpy(received_mac, ct + ct_len + EVP_MAX_IV_LENGTH, SHA256_DIGEST_LENGTH);
		//for testing
		//printf("received MAC: ");
		//for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
		  //printf("%02x", received_mac[i]);
		//}
		//printf("\n");
		
		//compute MAC of the received ct
		unsigned char mac[SHA256_DIGEST_LENGTH];
		computeMAC(nct, ct_len, SS, mac);
		//for testing
		//printf("computed MAC: ");
		//for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
		  //printf("%02x", mac[i]);
		//}
		//printf("\n");
		
		//verify the mac
		//this was not working for some reason even though they were the same
		if(memcmp(mac, received_mac, SHA256_DIGEST_LENGTH) != 0){
		  fprintf(stderr, "MAC verification failed(possible tampering");
		  continue;//ignore the message and move on
		}
		
		//decrypt ct
		unsigned char pt[maxlen];
		//was nbytes - EVP_MAX_IV_LENGTH
	        int pt_len = decryption(nct, ct_len, SS, IV, pt);
		//int pt_len = decryption(ct, nbytes, SS, IV, pt);
		pt[pt_len] = 0;
		
		char* msg = malloc(pt_len +1);
		memcpy(msg, pt, pt_len +1);
		
		g_main_context_invoke(NULL,shownewmessage,(gpointer)msg);
	}
	return 0;
}
