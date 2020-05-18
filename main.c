#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
//openssl libraries
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// debug variables
#define DBG_NONE 0x00 // no debug
#define DBG_ENTEXIT 0x01 // entry/exit to fxn
#define DBG_LIB 0x02 // before/after call to lib fxn
#define DBG_SYSCALL 0x04 // before/after call to syscall
#define DBG_ARGS 0x10 // print args before calling fxn
#define DBG_RET	0x20 // print retval before return from fxn 

// debug function shortcuts
#define NORM_FXN 1
#define LIB_FXN 2
#define SYS_FXN 4

// version string of the program
#define VERSION_STRING "filesec v1.0.7" // current version of the program

// flags that are set by parsing cmd line args
static int dbg_flags = DBG_NONE;

// debug functions here
#define DBG_PRINT_ENTER(func, type, fmt, ...) \
  if (dbg_flags & (DBG_ENTEXIT | DBG_LIB | DBG_SYSCALL) & type) { \
    if (!(dbg_flags & DBG_ARGS)) \
      fprintf(stderr, "entered function %s\n", func); \
    else { \
      fprintf(stderr, "entered function %s with args: (", func); \
	    fprintf(stderr, fmt, __VA_ARGS__); \
      fprintf(stderr, "%s", ")\n"); \
    } \
  }

#define DBG_PRINT_EXIT(func, type, retVal, error) \
  if (dbg_flags & (DBG_ENTEXIT | DBG_LIB | DBG_SYSCALL) & type) { \
    if (!(dbg_flags & DBG_RET)) \
      fprintf(stderr, "exiting function %s\n", func); \
    else { \
      fprintf(stderr, "exiting function %s with return value: (%d)", \
              func, \
              retVal);  \
      if (error == -1) { \
        fprintf(stderr, "%s", " and error: \n"); \
        perror(func); \
      } \
      else \
        printf("\n"); \
    } \
  }


// macro for when incorrect flags are passed
#define PRINT_USAGE_AND_EXIT_FAILURE() \
  print_usage(); \
  return -1;

// function that prints the usage prompt for the program
int print_usage(){
  DBG_PRINT_ENTER(__func__, NORM_FXN, "%s", "null");
  printf("usage: filesec [-devh] [-D DBGVAL] [-p PASSFILE] infile outfile\n\
          -d: specify to the program to decrypt infile to outfile\n\
          -e: specify to the program to encrypt infile to outfile\n\
          -v: print the program version\n\
          -h: display the help string\n\
          -D DBGVAL: set the dbg_flags to DBGVAL (values and their functions below)\n\
            - 0x00- no debug info printed\n\
            - 0x01- entry and exit for program functions\n\
            - 0x02- entry and exit for libc functions\n\
            - 0x04- entry and exit to syscall functions\n\
            - 0x10- print args to specified functions\n\
            - 0x20- print return values and any errors to specified functions\n\
          -p PASSFILE: provide the password using a file that has a password in it\n\
          infile: file to encrypt/decrypt\n\
          outfile: file that will contain encryption/decryption\n");
  DBG_PRINT_EXIT(__func__, NORM_FXN, 0, 0);
  return 0;
}

// encrypt function
// function inspiration drawn from openssl.org wiki page
// returns -1 upon error
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, 
            unsigned char *iv, unsigned char *ciphertext) {

  DBG_PRINT_ENTER(__func__, NORM_FXN, 
                  "plaintext: %s, plaintext_len: %d, key: %s, iv: %s, ciphertext: %s",
                  "plaintext", plaintext_len, key, iv, ciphertext);
 
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  int retVal = 0;

  // create and initialize the context
  DBG_PRINT_ENTER("EVP_CIPHER_CTX_new", LIB_FXN, "%s", "null");
  if (!(ctx = EVP_CIPHER_CTX_new())){
    DBG_PRINT_EXIT("EVP_CIPHER_CTX_new", LIB_FXN, 0, -1);
    return -1;
  }
  DBG_PRINT_EXIT("EVP_CIPHER_CTX_new", LIB_FXN, 0, 0);

  // initialize the encryption operation
  DBG_PRINT_ENTER("EVP_EncryptInit_ex", LIB_FXN, "ctx: %s, type: %s, impl: %s, key: %s, iv: %s", 
                  "struct ctx", "EVP_aes_256_ctr()", "NULL", key, iv);
  retVal = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
  if (retVal != 1){
    DBG_PRINT_EXIT("EVP_EncryptInit_ex", LIB_FXN, retVal, -1);
    return -1;
  }
  DBG_PRINT_EXIT("EVP_EncryptInit_ex", LIB_FXN, retVal, 0);

  // provide the message to be encrypted and obtain the encrypted output
  DBG_PRINT_ENTER("EVP_EncryptUpdate", LIB_FXN, "ctx: %s, out: %s, outl: %d, in: %s, inl: %d",
                  "struct ctx", ciphertext, len, "plaintext", plaintext_len);
  retVal = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
  if (retVal != 1){
    DBG_PRINT_EXIT("EVP_EncryptUpdate", LIB_FXN, retVal, -1);
    return -1;
  }
  DBG_PRINT_EXIT("EVP_EncryptUpdate", LIB_FXN, retVal, 0);
  ciphertext_len = len;

  // finalize the encryption
  DBG_PRINT_ENTER("EVP_EncryptFinal_ex", LIB_FXN, "ctx: %s, out: %s, outl: %d",
                  "struct ctx", ciphertext + len, len);
  retVal = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  if (retVal != 1){
    DBG_PRINT_EXIT("EVP_EncryptFinal_ex", LIB_FXN, retVal, -1);
    return -1;
  }
  DBG_PRINT_EXIT("EVP_EncryptFinal_ex", LIB_FXN, retVal, 0);
  ciphertext_len += len;

  // cleanup
  DBG_PRINT_ENTER("EVP_CIPHER_CTX_free", LIB_FXN, "ctx: %s", "struct ctx");
  EVP_CIPHER_CTX_free(ctx);
  DBG_PRINT_EXIT("EVP_CIPHER_CTX_free", LIB_FXN, 0, 0);

  DBG_PRINT_EXIT(__func__, NORM_FXN, ciphertext_len, ciphertext_len);
  return ciphertext_len;
}

// decrypt function
// function inspiration drawn from openssl.org wiki page
// returns -1 upon error;
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    
  DBG_PRINT_ENTER(__func__, NORM_FXN,
                  "ciphertext: %s, ciphertext_len: %d, key: %s, iv: %s, plaintext: %s",
                  "ciphertext", ciphertext_len, key, iv, plaintext);

  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int retVal = 0;

  // create and initialize the context
  DBG_PRINT_ENTER("EVP_CIPHER_CTX_new", LIB_FXN, "%s", "null");
  if (!(ctx = EVP_CIPHER_CTX_new())){
    DBG_PRINT_EXIT("EVP_CIPHER_CTX_new", LIB_FXN, 0, -1);
    return -1;
  }
  DBG_PRINT_EXIT("EVP_CIPHER_CTX_new", LIB_FXN, 0, 0);

  // initialize the decryption operation
  DBG_PRINT_ENTER("EVP_DecryptInit_ex", LIB_FXN, "ctx: %s, type: %s, impl: %s, key: %s, iv: %s",
                  "struct ctx", "EVP_aes_256_ctr()", "NULL", key, iv);
  retVal = EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
  if (retVal != 1){
    DBG_PRINT_EXIT("EVP_DecryptInit_ex", LIB_FXN, retVal, -1);
    return -1;
  }
  DBG_PRINT_EXIT("EVP_DecryptInit_ex", LIB_FXN, retVal, 0);

  // provide the message to be decrypted and obtain the decrypted output
  DBG_PRINT_ENTER("EVP_DecryptUpdate", LIB_FXN, "ctx: %s, out: %s, outl: %d, in: %s, inl: %d",
                  "struct ctx", plaintext, len, "ciphertext", ciphertext_len);
  retVal = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
  if (retVal != 1){
    DBG_PRINT_EXIT("EVP_DecryptUpdate", LIB_FXN, retVal, -1);
    return -1;
  }
  DBG_PRINT_EXIT("EVP_DecryptUpdate", LIB_FXN, retVal, 0);
  plaintext_len = len;

  // finalize the decryption
  DBG_PRINT_ENTER("EVP_DecryptFinal_ex", LIB_FXN, "ctx: %s, outm: %s, outl: %d",
                  "struct ctx", plaintext + len, len);
  retVal = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  if (retVal != 1){
    DBG_PRINT_EXIT("EVP_DecryptFinal_ex", LIB_FXN, retVal, -1);
    return -1;
  } 
  DBG_PRINT_EXIT("EVP_DecryptFinal_ex", LIB_FXN, retVal, 0);
  plaintext_len += len;

  // cleanup
  DBG_PRINT_ENTER("EVP_CIPHER_CTX_free", LIB_FXN, "ctx: %s", "struct ctx");
  EVP_CIPHER_CTX_free(ctx);
  DBG_PRINT_EXIT("EVP_CIPHER_CTX_free", LIB_FXN, 0, 0);

  DBG_PRINT_EXIT(__func__, NORM_FXN, plaintext_len, plaintext_len);
  return plaintext_len;
}

// main function, runs the program
int main(int argc, char **argv) {
 
  DBG_PRINT_ENTER(__func__, NORM_FXN, "argc: %d, argv: %s", argc, "argv");

  // part 1: process all flags, then check for their validity
  int opt = 0;
  int opt_p = 0; int opt_D = 0; int opt_i = 0;
  int opt_d = 0; int opt_e = 0; int opt_v = 0;
  //char *opt_p_arg = NULL; // file containing password
  char *infile, *outfile;
  char *passFile = NULL;
  int injectedError = -1;
  int numOfArgs = argc - 1;

  //part 1a: process all flags
  // USAGE: filesec [-devh] [-D DBGVAL] [-p PASSFILE] infile outfile
  DBG_PRINT_ENTER("getopt", LIB_FXN, "argc: %d, argv: %s, optstring: %s", argc, "argv", "hvedip:D:");
  while ((opt = getopt(argc, argv, "hvedip:D:")) != -1) {
    switch (opt) {
      case 'd':
        opt_d++;
        numOfArgs--;
        break;
      case 'e':
        opt_e++;
        numOfArgs--;
        break;
      case 'v':
        opt_v++;
        numOfArgs--;
        break;
      case 'h':
        print_usage(); // print usage string
        exit(EXIT_SUCCESS);
        break;
      case 'D':
        opt_D++;
        DBG_PRINT_ENTER("sscanf", LIB_FXN, "str: %s, format: %%i, int: %d", optarg, dbg_flags);
        if (sscanf(optarg, "%i", &dbg_flags) != 1){
          DBG_PRINT_EXIT("sscanf", LIB_FXN, 0, -1);
          PRINT_USAGE_AND_EXIT_FAILURE();
        }
        DBG_PRINT_EXIT("sscanf", LIB_FXN, 1, 0);
        numOfArgs = numOfArgs - 2;
        break;
      case 'p':
        opt_p++;
        if (optarg == NULL){
          PRINT_USAGE_AND_EXIT_FAILURE();
        }
        passFile = optarg;
        numOfArgs = numOfArgs - 2;
        break;
      case 'i':
        opt_i++;
        injectedError = 1;
        numOfArgs--;
        break;
      default:
        PRINT_USAGE_AND_EXIT_FAILURE();
    }
  }
  DBG_PRINT_EXIT("getopt", LIB_FXN, -1, 0);

  // part 1b: check the validity of the flags
  if (numOfArgs != 2) { // user did not specify and infile or an outfile
    PRINT_USAGE_AND_EXIT_FAILURE();
  }
  if (opt_d > 1 || opt_e > 1) { // cannot specify -d or -e more than once
    PRINT_USAGE_AND_EXIT_FAILURE(); // print usage so that user knows -d or -e can only be used once
  }
  if (opt_d == 0 && opt_e == 0) { // must specify -d or -e
    PRINT_USAGE_AND_EXIT_FAILURE();
  }
  if (opt_d != 0 && opt_e != 0) { // can't specify both -d and -e
    PRINT_USAGE_AND_EXIT_FAILURE();
  }
  if (opt_p > 1 || opt_D > 1 || opt_i > 1) { // cannot specify -p, -D, or -i more than once
    PRINT_USAGE_AND_EXIT_FAILURE();
  }

  // part 2: main program
  // part 2a: prep work
  // program variables
  DBG_PRINT_ENTER("getpagesize", SYS_FXN, "%s", "null");
  int pagesize = getpagesize();
  DBG_PRINT_EXIT("getpagesize", SYS_FXN, pagesize, 0);
  int bufsize = pagesize;
  void *buf = NULL;
  unsigned char cryptText[pagesize];
  int fd1 = -1; 
  int fd2 = -1; 
  int retVal = 0;
  int tempOutfileExists = 0;
  char *tempOutfile = "tempOutfile";

  // set the infile and the outfile from the arguments
  infile = argv[optind];
  outfile = argv[optind+1];

  // print the version string if -v was specified
  if (opt_v > 0){
    printf("%s\n", VERSION_STRING);
  }

  // 1. allocate a buffer
  DBG_PRINT_ENTER("malloc", LIB_FXN, "size: %d", bufsize);
  buf = (void *)malloc(bufsize);
  if (buf == NULL) {
    DBG_PRINT_EXIT("malloc", LIB_FXN, 0, -1);
    perror("malloc");
    retVal = -1;
    goto out;
  }
  DBG_PRINT_EXIT("malloc", LIB_FXN, 0, 0);

  // 2. open infile
  if (infile[0] == '-'){ // check if user specified to use stdin
    fd1 = STDIN_FILENO;
  }
  else{ // if user specified a specific file for infile
    DBG_PRINT_ENTER("open", SYS_FXN, "pathname: %s, flags: %d", infile, O_RDONLY);
    fd1 = open(infile, O_RDONLY);
    if (fd1 < 0) {
      DBG_PRINT_EXIT("open", SYS_FXN, fd1, -1);
      perror("infile");
      retVal = -1;
      goto out;
    }
    DBG_PRINT_EXIT("open", SYS_FXN, fd1, 0);
  }

  // 3. open outfile
  struct stat sb;
  if (outfile[0] == '-'){ // check if user specified to use stdout
    fd2 = STDOUT_FILENO;
  }
  else{ // if user specified a specific file for outfile
    DBG_PRINT_ENTER("access", SYS_FXN, "pathname: %s, mode: %d", outfile, F_OK);
    if (access(outfile, F_OK) == 0) { // check if the file exists
      DBG_PRINT_EXIT("access", SYS_FXN, 0, 0);
      DBG_PRINT_ENTER("stat", SYS_FXN, "pathname: %s, statbuf: %s", outfile, "sb");
      if (stat(outfile, &sb) < 0) { // get the permissions from the file
        DBG_PRINT_EXIT("stat", SYS_FXN, -1, -1);
        perror("stat");
        retVal = -1;
        goto out;
      }
      DBG_PRINT_EXIT("stat", SYS_FXN, 0, 0);
    }
    else{
      DBG_PRINT_EXIT("access", SYS_FXN, 0, 0);
      sb.st_mode = 0600;
    }
    // open a new outfile and assign it permissions of the original
    DBG_PRINT_ENTER("open", SYS_FXN, "pathname: %s, flags: %d, mode: %s", tempOutfile, 
                    O_WRONLY | O_CREAT | O_APPEND, "mode");
    fd2 = open(tempOutfile, O_WRONLY | O_CREAT | O_APPEND, sb.st_mode & 0777);
    if (fd2 < 0) {
      DBG_PRINT_EXIT("open", SYS_FXN, fd2, -1);
      perror("outfile");
      retVal = -1;
      goto out;
    }
    else{
      DBG_PRINT_EXIT("open", SYS_FXN, fd2, 0);
      tempOutfileExists = 1;
    }
  }

  // 4. retrieve password from specified file, if no file specified then ask user
  if (passFile != NULL) { // if user specified a file
    // open the file
    int readChars = -1;
    DBG_PRINT_ENTER("open", SYS_FXN, "pathname: %s, flags: %d", passFile, O_RDONLY);
    int passFileFD = open(passFile, O_RDONLY);
    if (passFileFD < 0){
      DBG_PRINT_EXIT("open", SYS_FXN, passFileFD, -1);
      perror("passFile");
      retVal = -1;
      goto out;
    }
    DBG_PRINT_EXIT("open", SYS_FXN, passFileFD, 0);
    // read from the file
    DBG_PRINT_ENTER("read", SYS_FXN, "fd: %d, buf: %s, count: %d", passFileFD, "buf", bufsize);
    if ((readChars = read(passFileFD, buf, bufsize)) < 0){
      DBG_PRINT_EXIT("read", SYS_FXN, readChars, -1);
      close(passFileFD);
      perror("read");
      retVal = -1;
      goto out;
    }
    DBG_PRINT_EXIT("read", SYS_FXN, readChars, -1);
    DBG_PRINT_ENTER("close", SYS_FXN, "fd: %d", passFileFD);
    close(passFileFD);
    DBG_PRINT_EXIT("close", SYS_FXN, 0, 0);
    // set last \n to a null terminator
    char *pointerToBuf = (char *)buf;
    for (int i = 0; i < readChars; i++){
      if (pointerToBuf[i] == '\n')
        pointerToBuf[i] = '\0';
    }
  }
  else { // if user didn't specify a file with a password
    if (infile[0] == '-'){ // check if user specified to use stdin
      printf("program only accepts stdin if -p argument was provided\n");
      PRINT_USAGE_AND_EXIT_FAILURE();
    }
    DBG_PRINT_ENTER("getpass", LIB_FXN, "prompt: %s", "Input password: ");
    buf = (void *)getpass("Input password: ");
    DBG_PRINT_EXIT("getpass", LIB_FXN, 0, 0);
  }

  // 5. generate the 256-bit hash using the SHA256 hashing function
  DBG_PRINT_ENTER("SHA256", LIB_FXN, "d: %s, n: %s, md: 0", (char *)buf, "strlen((char *)buf)");
  DBG_PRINT_ENTER("strlen", LIB_FXN, "s: %s", (char *)buf);
  unsigned char *key = SHA256((unsigned char *)buf, strlen((char *)buf), 0);
  DBG_PRINT_EXIT("strlen", LIB_FXN, 0, 0);
  DBG_PRINT_EXIT("SHA256", LIB_FXN, 0, 0);

  //part 2b: main program
  // store the SHA256 hash of the encryption key in the outfile
  if (opt_e == 1) { // encrypt
    DBG_PRINT_ENTER("strlen", LIB_FXN, "s: %s", (char *)key);
    int keyLen = strlen((char *)key);
    DBG_PRINT_EXIT("strlen", LIB_FXN, keyLen, 0);;
    DBG_PRINT_ENTER("write", SYS_FXN, "fd: %d, buf: %s, count: %d", fd2, "buf", keyLen);
    if (write(fd2, key, keyLen) < 0){
      DBG_PRINT_EXIT("write", SYS_FXN, -1, -1);
      perror("writeKey");
      retVal = -1;
      goto out;
    }
    DBG_PRINT_EXIT("write", SYS_FXN, keyLen, 0);
  }
  else { // decrypt
    DBG_PRINT_ENTER("read", SYS_FXN, "fd: %d, buf: buf, count: %d", fd1, 32);
    if (read(fd1, buf, 32) < 32){
      DBG_PRINT_EXIT("read", SYS_FXN, -1, -1);
      perror("readKey");
      retVal = -1;
      goto out;
    }
    DBG_PRINT_EXIT("read", SYS_FXN, 0, 0);
    DBG_PRINT_ENTER("strcmp", LIB_FXN, "s1: %s, s2: %s", (char *)key, (char *)buf);
    if (buf != NULL && strcmp((char *)key, (char *)buf) != 0){
      DBG_PRINT_EXIT("strcmp", LIB_FXN, -1, -1);
      printf("incorrect password provided\n");
      retVal = -1;
      goto out;
    }
    DBG_PRINT_EXIT("strcmp", LIB_FXN, 0, 0);
  }

  // read/write loop
  int readVal = -1;
  int text_len;
  unsigned char *iv = (unsigned char *)"0";
  DBG_PRINT_ENTER("read", SYS_FXN, "fd: %d, buf: buf, count: %d", fd1, bufsize);
  while ((readVal = read(fd1, buf, bufsize)) != 0){
    if (injectedError == 0 || readVal < 0){
      DBG_PRINT_EXIT("read", SYS_FXN, -1, -1);
      perror("read");
      retVal = -1;
      goto out;
    }
    DBG_PRINT_EXIT("read", SYS_FXN, 0, 0);
    if (opt_d == 1) { // decrypt
      text_len = decrypt((unsigned char *)buf, readVal, key, iv, cryptText);
      if (text_len < 0) {
        perror("decrypt");
        retVal = -1;
        goto out;
      }
    }
    else { // encrypt
      text_len = encrypt((unsigned char *)buf, readVal, key, iv, cryptText);
      if (text_len < 0) {
        perror("encrypt");
        retVal = -1;
        goto out;
      }
    }
    DBG_PRINT_ENTER("write", SYS_FXN, "fd: %d, buf: buf, count: %d", fd2, text_len);
    if (write(fd2, cryptText, text_len) < 0){
      DBG_PRINT_EXIT("write", SYS_FXN, -1, -1);
      perror("write");
      retVal = -1;
      goto out;
    }
    DBG_PRINT_EXIT("write", SYS_FXN, 0, 0);
    injectedError--;
  }
  DBG_PRINT_EXIT("read", SYS_FXN, 0, 0);

  //part 2c: cleanup
  // If read/write loop succeeds, rename temp file to outfile
  DBG_PRINT_ENTER("rename", SYS_FXN, "oldpath: %s, newpath: %s", tempOutfile, outfile);
  if (rename(tempOutfile, outfile) < 0){
    DBG_PRINT_EXIT("rename", SYS_FXN, -1, -1);
    perror("rename");
    retVal = -1;
    goto out;
  }
  else{
    DBG_PRINT_EXIT("rename", SYS_FXN, 0, 0);
    tempOutfileExists = 0;
  }

out:
  // delete temporary outfile if it exists
  if (tempOutfileExists == 1){
    DBG_PRINT_ENTER("unlink", SYS_FXN, "pathname: %s", tempOutfile);
    unlink(tempOutfile);
    DBG_PRINT_EXIT("unlink", SYS_FXN, 0, 0);
  }
  // close fd2
  if (fd2 >= 0){
    DBG_PRINT_ENTER("open", SYS_FXN, "fd: %d", fd2);
    close(fd2);
    DBG_PRINT_EXIT("open", SYS_FXN, 0, 0);
  }
  // close fd1
  if (fd1 >= 0){
    DBG_PRINT_ENTER("open", SYS_FXN, "fd: %d", fd1);
    close(fd1);
    DBG_PRINT_EXIT("open", SYS_FXN, 0, 0);
  }
  // free buf
  if (buf != NULL){
    DBG_PRINT_ENTER("free", LIB_FXN, "ptr: %s", "void pointer");
    free(buf);
    DBG_PRINT_EXIT("free", LIB_FXN, 0, 0);
  }

  DBG_PRINT_EXIT(__func__, NORM_FXN, retVal, retVal);
  return retVal;
}
