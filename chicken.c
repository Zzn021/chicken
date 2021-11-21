////////////////////////////////////////////////////////////////////////
// COMP1521 21T3 --- Assignment 2: `chicken', a simple file archiver
// <https://www.cse.unsw.edu.au/~cs1521/21T3/assignments/ass2/index.html>
//
// Written by YOUR-NAME-HERE (z5369232) on 22-11-2021.
//
// 2021-11-08   v1.1    Team COMP1521 <cs1521 at cse.unsw.edu.au>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <math.h>

#include "chicken.h"


// ADD ANY extra #defines HERE
#define FIRST_EGG 0
#define LAST_EGG -1

#define PATH_LENGTH 0
#define CONTENT_LENGTH 1

#define DEFAULT 0
#define ADVANCED 1

#define DEFAULT_PERM 0755

#define FALSE 0
#define TRUE 1

#define THIS_DIR "."
#define PARENT_DIR ".."
#define DIRECTORY 'd'
#define MAGIC 'c'

// Position in .egg file
#define FORMAT 1
#define PERM 3
#define PERM_DIR 2
#define PATH 12

#define PERM_LEN 9
#define PATH_LEN 2
#define CONT_LEN 6

#define FMT_6 0x36
#define FMT_7 0x37
#define FMT_8 0x38

#define BIT 8

// ADD YOUR FUNCTION PROTOTYPES HERE
uint64_t dump_everything(char *dirpath, FILE *write_stream, int format, 
                         uint64_t current_egg );
uint64_t get_len(FILE *read_stream, uint64_t current_egg, int mode);
uint64_t next_egg(FILE *read_stream, uint64_t current_egg);
uint64_t dump(char *pathname, FILE *write_stream,
              int format, uint64_t current_egg, int mode);
uint64_t dumpPath(char *pathname, FILE *write_stream,
                  int format, uint64_t current_egg);
uint64_t fmt_len(int format, uint64_t cont_len);

uint8_t get_hash(FILE *read_stream, uint64_t current_egg, int mode);

char *get_path(FILE *read_stream, uint64_t current_egg);

int get_format(FILE *read_stream, uint64_t current_egg);
int is_dir(FILE *read_stream, uint64_t current_egg);

void print_detail(FILE *read_stream, uint64_t current_egg, int mode);
void update_hash(FILE *read_stream, uint8_t *hash);
void check(FILE *read_stream, uint64_t current_egg, int mode);
void change_perm(FILE *read_stream, char *path, uint64_t current_egg);
void copy_content(FILE *read_stream, FILE *write_stream, int format, uint64_t current_egg, int mode);

// print the files & directories stored in egg_pathname (subset 0)
//
// if long_listing is non-zero then file/directory permissions, 
// formats & sizes are also printed (subset 0)

void list_egg(char *egg_pathname, int long_listing) {
    /**
     * List the egglet in the .egg file. Long listing: detail of the egglet(permission,
     * format, size).
     * 
     * ARGUMENTS:
     * (char *) egg_pathname: the given path of the .egg file.
     * (int) long_listing: indicates whether or not prints the detail.
     */

    // Set the mode if we wants to print detail.
    int mode = PATH_LENGTH;
    if (long_listing) {
        mode = CONTENT_LENGTH;
    }

    // Open the file descriptor
    FILE *read_stream = fopen(egg_pathname, "r");
    if (read_stream == NULL) {
        perror(egg_pathname);
        exit(1);
    }

    // Prints the egglet until the last egglet is reached
    uint64_t current_egg = FIRST_EGG;
    while (current_egg != LAST_EGG) {
        // Check the hash and magic number
        check(read_stream, current_egg, ADVANCED);
        print_detail(read_stream, current_egg, mode);
        putchar('\n');

        current_egg = next_egg(read_stream, current_egg);
    }

    fclose(read_stream);
}


// check the files & directories stored in egg_pathname (subset 1)
//
// prints the files & directories stored in egg_pathname with a message
// either, indicating the hash byte is correct, or
// indicating the hash byte is incorrect, what the incorrect value is 
// and the correct value would be

void check_egg(char *egg_pathname) {
    /**
     * check the egglet in the .egg file are stored correctly.
     * 
     * ARGUMENTS:
     * (char *) egg_pathname: the given path of the .egg file.
     */

    // Open the file descriptor
    FILE *read_stream = fopen(egg_pathname, "r");
    if (read_stream == NULL) {
        perror(egg_pathname);
        exit(1);
    }

    // Check the egglets until the last egglet is reached.
    uint64_t current_egg = FIRST_EGG;
    while (current_egg != LAST_EGG) {
        check(read_stream, current_egg, DEFAULT);

        current_egg = next_egg(read_stream, current_egg);
    }

    fclose(read_stream);
}


// extract the files/directories stored in egg_pathname (subset 2 & 3)

void extract_egg(char *egg_pathname) {
    /**
     * Extract files from the given .egg file
     * 
     * ARGUMENTS:
     * (char *) egg_pathname: given .egg file. 
     */
    
    // Open the file descriptor
    FILE *read_stream = fopen(egg_pathname, "r");
    if (read_stream == NULL) {
        perror(egg_pathname);
        exit(1);
    }

    // Extract the egglets until the last egglet is reached.
    uint64_t current_egg = FIRST_EGG;
    while (current_egg != LAST_EGG) {
        // Get the pathname of the egglet.
        char *path = get_path(read_stream, current_egg);

        // Check magic number and hash before extracting.
        check(read_stream, current_egg, ADVANCED);

        // Create a directory if the egglet is a dir, else extract.
        if (is_dir(read_stream, current_egg)) {
            printf("Creating directory: %s\n", path);

            DIR *d = opendir(path);
            // Create a directory if the directory does not exist.
            if (d == NULL) {
                mkdir(path, DEFAULT_PERM);
            } else {
                closedir(d);
            }
        } else {
            // Open the file descriptor to write
            FILE *write_stream = fopen(path, "w");
            if (write_stream == NULL) {
                perror(path);
                exit(1);
            }

            // Extract the file.
            printf("Extracting: %s\n", path);
            int format = get_format(read_stream, current_egg);
            copy_content(read_stream, write_stream, format, current_egg, DEFAULT); 
            fclose(write_stream);  
        }

        // Change the permission of the file/dir
        change_perm(read_stream, path, current_egg);
        free(path);
        current_egg = next_egg(read_stream, current_egg);
    }

}


// create egg_pathname containing the files or directories 
// specified in pathnames (subset 3)
//
// if append is zero egg_pathname should be over-written if it exists
// if append is non-zero egglets should be instead appended 
// to egg_pathname if it exists
//
// format specifies the egglet format to use, it must be one 
// EGGLET_FMT_6,EGGLET_FMT_7 or EGGLET_FMT_8

void create_egg(char *egg_pathname, int append, int format,
                int n_pathnames, char *pathnames[n_pathnames]) {
    /**
     *  Create a .egg file under the given format and the given mode(append).
     * 
     * ARGUMENTS:
     * (char *) egg_pathname: the pathname of the .egg file.
     * (int) append: whether append to the .egg file.
     * (int) format: required format.
     * (int) n_pathnames: how many file included.
     * (char *) pathnames[n_pathnames]: pathname of each file
     */
    
    // Get the flag. 
    char *flag = "w+";
    if (append) {
        flag = "a+";
    } 

    // Open the file descriptor of the .egg file.
    FILE *write_stream = fopen(egg_pathname, flag);
    if (write_stream == NULL) {
        perror(egg_pathname);
        exit(1);
    }

    // If we are appending set the file descriptor,
    // and also the current_egg.
    uint64_t current_egg = FIRST_EGG;
    if (append) {
        fseek(write_stream, 0, SEEK_END);
        current_egg = ftell(write_stream);
    }
    
    // Dump each file to the .egg file.
    for (int i = 0; i < n_pathnames; i++) {
        current_egg = dumpPath(pathnames[i], write_stream, format, current_egg);
    }
}


// ADD YOUR EXTRA FUNCTIONS HERE

uint64_t get_len(FILE *read_stream, uint64_t current_egg, int mode) {
    /**
     * get the length of the pathname or content.
     * 
     * ARGUMENTS:
     * (FILE) *read_stream: the open egg file to read.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * (int) mode: PATH_LENGTH or CONTENT_LENGTH. (See below).
     *      PATH_LENGTH: get the path length.
     *      CONTENT_LENGTH: get the content length.
     * 
     * RETURN:
     * (uint64_t) len: Length of the pathname or content.
     */

    uint64_t len = 0;

    // Set the fd to pathname length.
    uint64_t position = PATH + current_egg;
    fseek(read_stream, position, SEEK_SET);

    // Get the pathname length
    for (int i = 0; i < 2; i++) {
        uint16_t byte;
        byte = (uint16_t) fgetc(read_stream);
        len |= byte << (8 * i);
    }

    // Get the content length if mode is set to CONTENT_LENGTH
    if (mode) {
        // Set fd to content length
        fseek(read_stream, len, SEEK_CUR);
        len = 0;

        for (int i = 0; i < 6; i++) {
            uint64_t byte;
            byte = (uint64_t) fgetc(read_stream);
            len |= byte << (8 * i);
        }
    }

    return len;
}

uint64_t next_egg(FILE *read_stream, uint64_t current_egg) {
    /**
     * Find the starting byte of next egglet and set file descriptor to that byte.
     * 
     * ARGUMENTS:
     * (FILE) *read_stream: the open egg file to read.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * 
     * RETURN:
     * (uint64_t) current_egg: the starting byte of next egglet.
     */
    
    // Get the total length of the .egg file.
    fseek(read_stream, 0, SEEK_END);
    uint64_t total = ftell(read_stream);

    // Get the format of the current egglet.
    int fmt = get_format(read_stream, current_egg);

    // Get the length of the next egglet.
    uint64_t path_len = get_len(read_stream, current_egg, PATH_LENGTH);
    uint64_t cont_len = get_len(read_stream, current_egg, CONTENT_LENGTH);
    uint64_t egg_len = 21 + path_len;

    // Get the content size under the fmt.
    egg_len += fmt_len(fmt, cont_len);

    // Set the current egglet to the next egglet.
    current_egg += egg_len; 

    // Set the current egglet to -1 if it is the last one.
    if (current_egg == total) {
        current_egg = LAST_EGG;
    }

    // Set fd to the start of next egglet.
    fseek(read_stream, current_egg, SEEK_SET);
    return current_egg;
}

char *get_path(FILE *read_stream, uint64_t current_egg) {
    /**
     * Get the path name of the current egglet. 
     * 
     * [The Caller need to free the variable!]
     * 
     * ARGUMENTS:
     * (FILE) *read_stream: the open egg file to read.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * 
     * RETURN:
     * (char)path: a pointer of the path name of the egglet
     */

    // Get the length of the pathname.
    uint64_t path_len = get_len(read_stream, current_egg, PATH_LENGTH);
    
    // allocate the memory to store the pathname
    char *path = malloc(sizeof(char) * (path_len + 1));
    path[path_len] = '\0';
    for (uint16_t i = 0; i < path_len; i++) {
        uint8_t byte = fgetc(read_stream);
        path[i] = byte;
    }

    return path;
}

void print_detail(FILE *read_stream, uint64_t current_egg, int mode) {
    /**
     * Print the detail of the current egglet.
     * 
     * ARGUMENTS:
     * (FILE) *read_stream: the open egg file to read.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * (int) mode: DEFUALT or ADVANCED. (See below).
     *      DEFUALT: print the path name.
     *      ADVANCED: print the path name, format, content_size and file permission.
     */

    // Get pathname
    char *pathname = get_path(read_stream, current_egg);

    //  If mode is ADVANCED prints the detail of the current egglet.
    if (mode) {
        uint64_t content = get_len(read_stream, current_egg, CONTENT_LENGTH);
        // Set fd to format.
        uint8_t format = get_format(read_stream, current_egg);

        // Print permission
        for (int i = 0; i <= PERM_LEN; i++) {
            uint8_t byte = fgetc(read_stream);
            printf("%c", byte);
        }
        // Print format
        printf("%3c", format);
        // Print content length
        printf("%7lu  ", content);
    }

    // Print pathname of egglet.
    printf("%s", pathname);

    // Free memory
    free(pathname);
}

void check(FILE *read_stream, uint64_t current_egg, int mode) {   
    /**
     * Check if the magic number and hash is correct. Raise an error if magic number is
     * not correct. (not 0x63).
     * 
     * ARGUMENTS:
     * (FILE) read_stream: the open egg file to read.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * (int) mode: DEFUALT or ADVANCED. (See below).
     *      DEFUALT: Check magic number raise an error if is not correct.
     *               check hash, if it is wrong print out a message.
     *      ADVANCED: Check magic number and hash, raise an error 
     *                if any of them is wrong.
     * 
     * ERROR:
     *      magic number: incorrect first egglet byte.
     *      hash: incorrect egglet hash.
     */

    // Check the magic number
    fseek(read_stream, current_egg, SEEK_SET);
    uint8_t magic = fgetc(read_stream);
    if (magic != MAGIC) {
        fprintf(stderr, "error: incorrect first egglet byte: "
                        "0x%x should be 0x63\n", magic);
        exit(1);
    }

    // Get the given hash and calculate the actual hash.
    uint8_t hash_a = get_hash(read_stream, current_egg, ADVANCED);
    uint8_t hash_g = get_hash(read_stream, current_egg, DEFAULT);

    // Check hash
    if (hash_a != hash_g) {
        // If mode is ADVANCED raise an error, else print a message.
        if (mode) {
            fprintf(stderr, "error: incorrect egglet hash "
                            "0x%x should be 0x%x\n", hash_a, hash_g);
            exit(1);
        } else {
            print_detail(read_stream, current_egg, DEFAULT);
            fprintf(stdout, " - incorrect hash 0x%x should be 0x%x\n", hash_a, hash_g);
        }
    } else {
        // At DEFAULT mode print a message indicate the hashes are correct
        if (!mode) {
            print_detail(read_stream, current_egg, DEFAULT);
            fprintf(stdout, " - correct hash\n");
        }
    }
}

void update_hash(FILE *read_stream, uint8_t *hash) {
    /**
     * Update the old hash (pointer) and get the bytes of the read_stream.
     * 
     * ARGUMENTS:
     * (FILE) *read_stream: the open egg file to read.
     * (uint8_t) *hash: a pointer of the old hash.
     */

    // Get the byte from read_stream and calculate the hash.
    uint8_t byte_value = fgetc(read_stream);
    uint8_t old_value = *hash;
    *hash = egglet_hash(old_value, byte_value);
}

uint8_t get_hash(FILE *read_stream, uint64_t current_egg, int mode) {
    /**
     * Calculate the hash of the current egglet
     * 
     * ARGUMENTS:
     * (FILE) *read_stream: the open egg file to read.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * (int) mode: DEFUALT or ADVANCED. (See below).
     *      DEFUALT: Calculate the given hash.
     *      ADVANCED: Calculate the actual hash.(Re-calculate the hash)
     * 
     * RETURN: 
     * (uint8_t) hash: the hash value of the egglet.
     */
    
    // Set fd to the hash of the current egglet.
    uint64_t last_byte = next_egg(read_stream, current_egg);
    if (last_byte == LAST_EGG) {
        fseek(read_stream, -1, SEEK_END);
        last_byte = ftell(read_stream);
    } else {
        last_byte -= 1;
        fseek(read_stream, last_byte, SEEK_SET);
    }
    
    uint8_t hash = fgetc(read_stream);

    // At ADVANCED mode calculate the hash of the current egglet.
    if (mode) {
        // Set fd to the start of the egglet.
        fseek(read_stream, current_egg, SEEK_SET);

        // Reset hash.
        hash = 0;
        for (int i = current_egg; i < last_byte; i++) {
            update_hash(read_stream, &hash);
        }
    }

    return hash;
}


void copy_content(FILE *read_stream, FILE *write_stream, 
                  int format, uint64_t current_egg, int mode) {
    /**
     * Copy the content from the read_stream to write_stream.
     * 
     * ARGUMENTS:
     * (FILE *) read_stream: the open egg file to read.
     * (FILE *) write_stream: the open file to write.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * (int) mode: DEFUALT or ADVANCED. (See below).
     *      DEFUALT: copy content from an egglet to the write file.
     *      ADVANCED: copy content from a file to the .egg file.
     */

    // Get the length of the content
    uint64_t len = get_len(read_stream, current_egg, CONTENT_LENGTH);

    // If mode is ADVANCED: set len to the length of the file 
    // being copied.
    if (mode) {
        fseek(read_stream, 0, SEEK_END);        
        len = ftell(read_stream);
        fseek(read_stream, 0, SEEK_SET);
    }

    // Copy content from read_stream to write_stream
    if (format == FMT_7) {
        char *buffer = malloc(BIT * 7);

        if (!mode) {
            len = fmt_len(format, len);
        }
        
        free(buffer);
    } else if (format == FMT_6) {
        char *buffer = malloc(BIT * 6);

        if (!mode) {
            len = fmt_len(format, len);
        }
        
        free(buffer);
    } else {
        for (int i = 0; i < len; i++) {
            int byte = fgetc(read_stream);
            fputc(byte, write_stream);
        }
    }

}

void change_perm(FILE *read_stream, char *path, uint64_t current_egg) {
    /**
     * Change the permission of the file(path) to the permission of the current
     * egglet in .egg file.
     * 
     * ARGUMENTS:
     * (FILE *) read_stream: the file descriptor of .egg file.
     * (char *) path: the path of the file going to be changed.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     */

    // Set fd to permission.
    mode_t mode = 0;
    fseek(read_stream, current_egg + PERM, SEEK_SET);

    // Get the permission in (mode_t).
    uint16_t mask = 0;
    for (int i = 0; i < PERM_LEN; i++) {
        int perm = fgetc(read_stream);
        
        if (perm != '-') {
            mask = 1 << (PERM_LEN - 1 - i);
            mode |= mask;
        }
    }

    // change the given path to the mode of the egglet.
    if (chmod(path, mode) != 0) {
        perror(path);
        exit(1);
    }
}

int get_format(FILE *read_stream, uint64_t current_egg) {
    /**
     *  get the format of the current egglet in the .egg file.
     * 
     * ARGUMENTS:
     * (FILE *) read_stream: the file descriptor of .egg file.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     *
     * RETURN:
     * (int) format: the byte value of the format.
     */
    
    // Set the fd to the format and get the format.
    fseek(read_stream, current_egg + FORMAT, SEEK_SET);
    int format = fgetc(read_stream);

    return format;
}

uint64_t dump(char *pathname, FILE *write_stream,
              int format, uint64_t current_egg, int mode) {
    /**
     * Dump the detail of the read file to the .egg file. Dump Directory to .egg file when
     * mode is DEFAULT. Dump file when mode is ADVANCED, also detect if the
     * file is a directory or not, if it is call dump_everything() to dump files in that
     * directory.
     * 
     * ARGUMENTS:
     * (char *) pathname: the pathname of file being dumped.
     * (FILE *) write_stream: open file descriptor of .egg file.
     * (int) format: the required format.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * (int) mode: DEFUALT or ADVANCED. (See below).
     *      DEFUALT: Dump the directory to .egg file.
     *      ADVANCED: Dump the file to .egg file. Also detect if it is a directory.
     *                If it is, dump everything in that directory.
     *  RETURNS:
     * (uint64_t) current_egg: the new byte value indicating the start of the current egglet.
     */

    // Get the detail of the given file (pathname).
    struct stat detail;
    if ((stat(pathname, &detail)) != 0) {
        perror(pathname);
        exit(1);
    }

    // At ADVANCED mode, If the given file is a directory,
    // dump everything in the dir to the .egg file.
    if (S_ISDIR(detail.st_mode) && mode) {
        current_egg = dump_everything(pathname, write_stream, format, current_egg);
        return current_egg;
    }

    // Get the file descriptor of the given file
    FILE *read_stream = fopen(pathname, "r");
    if (read_stream == NULL) {
        perror(pathname);
        exit(1);
    }

    // Write the magic number and format to the .egg file.
    fputc('c', write_stream);
    fputc(format, write_stream);

    // Write the permission to the .egg file.
    fprintf(write_stream, (S_ISDIR(detail.st_mode)) ? "d" : "-");
    fprintf(write_stream, (detail.st_mode & S_IRUSR) ? "r" : "-");
    fprintf(write_stream, (detail.st_mode & S_IWUSR) ? "w" : "-");
    fprintf(write_stream, (detail.st_mode & S_IXUSR) ? "x" : "-");
    fprintf(write_stream, (detail.st_mode & S_IRGRP) ? "r" : "-");
    fprintf(write_stream, (detail.st_mode & S_IWGRP) ? "w" : "-");
    fprintf(write_stream, (detail.st_mode & S_IXGRP) ? "x" : "-");
    fprintf(write_stream, (detail.st_mode & S_IROTH) ? "r" : "-");
    fprintf(write_stream, (detail.st_mode & S_IWOTH) ? "w" : "-");
    fprintf(write_stream, (detail.st_mode & S_IXOTH) ? "x" : "-");
    
    // Write the length of the pathname in little-endian.
    uint16_t len = strlen(pathname);
    for (int i = 0; i < PATH_LEN; i++) {
        uint8_t byte = 0;
        byte |= len >> (BIT * i);
        fputc(byte, write_stream);
    }

    // Write the pathname to .egg file.
    fprintf(write_stream, "%s", pathname);

    // At DEFAULT mode, size is set to 0 as we are dumping a dir.
    uint64_t size = detail.st_size;
    if (!mode) {
        size = 0;
    }

    // If size is out of limit raise an error.
    if (size > 0xFFFFFFFFFFFF) {
        fprintf(stderr, "error: %s is too big\n", pathname);
        exit(1);
    } else {
        // write the length of content in little-endian.
        for (int i = 0; i < CONT_LEN; i++) {
            uint8_t byte = 0;
            byte |= size >> (BIT * i);
            fputc(byte, write_stream);
        }
    }

    // Copy to content to .egg file under the specified format.
    if (size) {
        copy_content(read_stream, write_stream, format, current_egg, ADVANCED);
    }

    // Calculate and write hash to the .egg file
    uint8_t hash = get_hash(write_stream, current_egg, ADVANCED);
    fputc(hash, write_stream);

    fclose(read_stream);
    return ftell(write_stream);
}

uint64_t dumpPath(char *pathname, FILE *write_stream,
                 int format, uint64_t current_egg) {
    /**
     * Dump the filepath to the .egg file, dump the dirctories that the file
     * belongs to as well.
     * 
     * ARGUMENTS:
     * (char *) pathname: the given path of the file.
     * (FILE *) write_stream: the file descriptor of the .egg file.
     * (int) format: the required format.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * 
     * RETURN:
     * (uint64_t) current_egg: the new byte value indicating the start of the current egglet.
     */

    // In order to get each dir of the given path,
    // create an array of char set to different pathnames to pass.
    int len = strlen(pathname);
    char file[len + 1];

    // Get the pathname for each dir included, and dump to
    // the .egg file.
    for (int current = 0; pathname[current] != '\0'; current++) {
        if (pathname[current] == '/') {
            for (int j = 0; j < current; j++) {
                file[j] = pathname[j];
            }
            file[current] = '\0';

            printf("Adding: %s\n", file);

            current_egg = dump(file, write_stream, format, current_egg, DEFAULT);
        }
    }

    // Dump the whole pathname to .egg file.
    printf("Adding: %s\n", pathname);
    current_egg = dump(pathname, write_stream, format, current_egg, ADVANCED);

    return current_egg;
}

int is_dir(FILE *read_stream, uint64_t current_egg) {
    /**
     * check if the current_egg is a directory or not
     * 
     * ARGUMENTS:
     * (FILE *) read_stream: the open .egg file to read.
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * 
     * RETURN:
     * (int) isdir: return 1 if it is a directory, 0 if it is not.
     */

    int isdir = FALSE;

    // Set fd to permission
    fseek(read_stream, current_egg + PERM_DIR, SEEK_SET);
    // Get the first byte of permission
    int file = fgetc(read_stream);
    // if it is dir set isdir to 1;
    if (file == DIRECTORY) {
        isdir = TRUE;
    }

    return isdir;
}

uint64_t dump_everything(char *dirpath, FILE *write_stream, int format, 
                        uint64_t current_egg ) {
    /**
     * dump every file in the Directory to the .egg file.
     * 
     * ARGUMENT:
     * (char *) dirpath: path of the directory.
     * (FILE *) write_stream: file descriptor of the .egg file.
     * (int) format: the required format
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     * 
     * RETURN:
     * (uint64_t) current_egg: the byte value indicating the start of the current egglet.
     */

    // Dump the directory to the .egg file.
    current_egg = dump(dirpath, write_stream, format, current_egg, DEFAULT);
    
    // Open the directory to get every file.
    DIR *d = opendir(dirpath);
    if (d == NULL) {
        perror(dirpath);
        exit(1);
    } 

    // Get every file inside the dir and dump to the .egg file.
    struct dirent *file;
    while ((file = readdir(d)) != NULL) {
        char *filename = file->d_name;

        // dump everything instead of "." and "..".
        if (strcmp(filename, THIS_DIR) && strcmp(filename, PARENT_DIR)) {
            char path[PATH_MAX];
            sprintf(path, "%s/%s", dirpath, filename);

            printf("Adding: %s\n", path);
            current_egg = dump(path, write_stream, format, current_egg, ADVANCED);
        }
    }

    closedir(d);
    return current_egg;
}

uint64_t fmt_len(int format, uint64_t cont_len) {
    /**
     * Calculate the size of the cont under the format/
     * 
     * ARGUMENTS:
     * (int) format: the required format.
     * (uint64_t) cont_len: the length of the content.
     * 
     * RETURNS:
     * (uint64_t) length: the length of the content under the format.
     */

    uint64_t length = 0;

    if (format == FMT_7) {
        double fmt_7_len = (7.0 / 8.0) * cont_len;
        length += (uint64_t) ceil(fmt_7_len);
    } else if (format == FMT_6) {
        double fmt_6_len = (6.0 / 8.0) * cont_len;
        length += (uint64_t) ceil(fmt_6_len);
    } else {
        length += cont_len;
    }

    return length;
}