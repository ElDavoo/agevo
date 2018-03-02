/************** COPYRIGHT AND CONFIDENTIALITY INFORMATION *********************
**                                                                          **
** Copyright (c) 2010 Technicolor                                           **
** All Rights Reserved                                                      **
**                                                                          **
** This program contains proprietary information which is a trade           **
** secret of TECHNICOLOR and/or its affiliates and also is protected as     **
** an unpublished work under applicable Copyright laws. Recipient is        **
** to retain this program in confidence and is not permitted to use or      **
** make copies thereof other than as permitted in a written agreement       **
** with TECHNICOLOR, UNLESS OTHERWISE EXPRESSLY ALLOWED BY APPLICABLE LAWS. **
**                                                                          **
** Programmer(s) : Joris Gorinsek (email : joris.gorinsek@technicolor.com)  **
**                                                                          **
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <malloc.h>
#include <inttypes.h>
#include <arpa/inet.h> //for endianess conversion routines
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>


#include "crc.h"
#include "rip2.h"

#define TP_STR      "ASCII"
#define TP_HEX      "HEX"
#define TP_FILE     "FILE"
#define TP_CMD      "EXEC"

#if (_BIG_ENDIAN)
#define HTOBE16(x)    (x)
#define HTOBE32(x)    (x)
#define BETOH16(x)    (x)
#define BETOH32(x)    (x)
#else
#define HTOBE16(x)    (htons(x))
#define HTOBE32(x)    (htonl(x))
#define BETOH16(x)    (ntohs(x))
#define BETOH32(x)    (ntohl(x))
#endif

typedef struct {
     uint32_t RIP2_idtag; 
     uint32_t imagesize;
     uint32_t headersize;
     uint32_t crc;
}T_RIP2_FILEHEADER;

typedef struct {
	uint16_t id;
	uint16_t size;
}T_RIP1_ELEM;

#ifndef RIP2TAG
    #define RIP2TAG            0xaacd2b85
#endif    

//#define DEBUG 

#ifdef DEBUG
#define DPRINTF(x...)	printf(x)
#else
#define DPRINTF(x...)
#endif


static T_RIP1_ELEM rip_size[] = {
{0x0000, 0x0002}, //"RIP CheckSum"
{0x0002, 0x0002}, //"Custum Pattern"
{0x0002, 0x0002}, //"Custum Pattern"
{0x0004, 0x000c}, //"PBA Code"
{0x0010, 0x0002}, //"PBA ICS"
{0x0012, 0x0010}, //"PBA Serial nr"
{0x0022, 0x0006}, //"Product Date"
{0x0028, 0x0002}, //"FIA code"
{0x002A, 0x0002}, //"FIM code"
{0x002C, 0x0006}, //"Repair Date"
{0x0032, 0x0006}, //"Ethernet MAC"
{0x0038, 0x0004}, //"Company ID"
{0x003C, 0x0004}, //"Factory ID"
{0x0040, 0x0008}, //"Board Name"
{0x0048, 0x0004}, //"Memory Conf"
{0x004C, 0x0006}, //"USB MAC"
{0x0052, 0x0001}, //"Registered
{0x0053, 0x0030}, //"VPVC Table"
{0x0083, 0x0005}, //"Access Code"
{0x0088, 0x0005}, //"Remote Mgr Pwd"
{0x008D, 0x0006}  //"WiFi MAC" 
};
static int  Do_Padding = 0; //determines if we use padding or not

static uint8_t *do_hex_input(uint8_t *data, char *arg, unsigned long *len);

/*
       uint32_t htonl(uint32_t hostlong);
       uint16_t htons(uint16_t hostshort);
       uint32_t ntohl(uint32_t netlong);
       uint16_t ntohs(uint16_t netshort);
 */

/* Helper function to find the amount of bytes to pad to */
static uint16_t get_padding(uint16_t id)
{
    int i = 0;
	int nbelem =  sizeof(rip_size)/sizeof(T_RIP1_ELEM);
	
	if (Do_Padding == 1) {
	    for (i = 0; i < nbelem ; i++) {
            if (rip_size[i].id == id)
		        return rip_size[i].size;
	    }
	}
	return 0xFFFF; //signal error
}

/* Help text */
char exRipBuilderInfo[] =
{
    "RIPv2 Builder v0.6\n\r"
    "Syntax: [-h|-v] <input file> <output file>\n\r"
    "Option:\n\r"
    "  -h : Add bootloader header for TFTP binary image\n\r"
    "  -v : Verify an extended RIP file (No output file needed)\n\r"
	"  -p : Pad the old RIPv1 values to their maximum size, regardless of input\n\r"
};

/* Global flags */

/*
 * Get rid of remaining special characters such as \" \r \n
 *
 */
static char *sanitize(char *input)
{
    int i, j, quotes = 0;

    j = 0; //will be used to modify the original string

    for (i = 0; i < strlen(input); i++) {
        // replace \n by string terminator
        switch (input[i]) {
	    case '\r':
            case '\n':
                input[j] = '\0';
                j++;
                break;

            case ' ':
		/* if we have seen an uneven amount of quotes its ok to remove
		 * these chars, otherwise keep them */
		if (quotes %2) {
		    input[j] = input[i];
                    j++;
		}
                break;

	    case '\"':
		quotes++;
	        break;

            default:
                input[j] = input[i];
                j++;
                break;
        }
    }
    return input;
}


/* Converts hex flag (32bit) to number, with length check, assume it already
    is formatted in big endian */
static int process_flag(char      *input,
                  uint32_t  *output)
{
    unsigned long len = 0;
    
    if (strlen(input) != 8)
        return -1;

    if (!do_hex_input((uint8_t *) output, input, &len))
        return -1;
        
    *output = BETOH32(*output); 
        
    if (len != 4)
        return -1;

    return 0;
}

static uint8_t *do_hex_input(uint8_t        *data,
                             char           *arg,
                             unsigned long  *len)
{
    int   cnt, i, items_read = 0;
    char  *infile  = NULL;
    char  hex[3]   = "\0\0\0";
    char  b        = 0;

    /* Sanitize input */
    infile = sanitize(arg);

    cnt = 0;
    /* We only accept HEX input if it is a multiple of 2 nibbles */
    if (strlen(infile) % 2) {
        return NULL;
    }

    for (i = 0; i < strlen(infile) - 1; i += 2) {
        hex[0] = infile[i];
        hex[1] = infile[i + 1];

        items_read = sscanf(hex, "%02hhx", &b);
        if (items_read == 1) {
            DPRINTF("Got hex value 0x%02hhx\n", b);
            data[cnt] = b;
            cnt++;
        }
    }

    *len = cnt;
    return data;
}

/*
 * process input file and return the contents as a data buffer
 * RETURNS: pointer to the data buffer containing the file content
 *
 *
 */
static uint8_t *do_file_input(uint8_t       *data,
                              char          *arg,
                              unsigned long *len)
{
    int         fd;
    uint8_t     *inbuf;
    struct stat inst;

    if ((fd = open(arg, O_RDONLY)) == -1) {
        fprintf(stderr,"Opening input file %s\n", arg);
        return NULL;
    }

    fstat(fd, &inst);
    if (inst.st_size > (RIP2_SZ - CRC_SZ)) { // TODO: check is not strict enough
        fprintf(stderr, "Input file too big, aborting!\n");
        fprintf(stderr, "	File size=%d, max=%d\n",(int) inst.st_size, RIP2_SZ - CRC_SZ);
        goto err;
    }

    /* mmap the input file */
    inbuf = mmap(0, inst.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (MAP_FAILED == inbuf) {
        fprintf(stderr,"Mapping the input file\n");
        goto err;
    }

    memcpy(data, inbuf, inst.st_size);

    *len = inst.st_size;

    close(fd);
    munmap(inbuf, inst.st_size);
    return data;

err:
    close(fd);
    return NULL;
}

/*
 * Does whatever is needed to get input data into a buffer.
 * Allocates the buffer and returns it.
 *
 * IN: type: a string representing the type of action that will need to be
 *           performed to acquired the data.
 *      arg: the command | string | filename that will provide the data
 * OUT: len: the length of the data buffer that is returned.
 *
 * RETURNS: pointer to the data buffer in case of success; this memory
 *          should be freed by the caller!
 *          NULL in case of failure.
 */
static uint8_t *get_input_data(unsigned long  *len,
                               const char     *type,
                               char           *arg)
{
    uint8_t *data = NULL;

    if ((len == NULL) || (type == NULL) || (arg == NULL)) {
        return NULL;
    }

    data = malloc(RIP2_SZ - CRC_SZ);
    if (data == NULL) {
        fprintf(stderr,"Allocating internal buffer.\n");
        return NULL;
    }

    /* string input */
    if (0 == strncasecmp(type, TP_STR, strlen(TP_STR))) {
	char * str = NULL;
	
        /* Sanitize input */
        str = sanitize(arg);

		memset(data, ' ', RIP2_SZ - CRC_SZ); //strings need to be padded with spaces
        strncpy((char*)data, str, strlen(str));
        *len = strlen(str);
        return data;
    }

    /* hex input */
    if (0 == strncasecmp(type, TP_HEX, strlen(TP_HEX))) {
		memset(data, 0x0, RIP2_SZ - CRC_SZ); // binary stuff needs to be padded with 0
        data = do_hex_input(data, arg, len);
        if (data == NULL) {
            goto err;
        }
        return data;
    }

    /* file input */
    if (0 == strncasecmp(type, TP_FILE, strlen(TP_FILE))) {
	    char * infile = sanitize(arg);
	    memset(data, 0x0, RIP2_SZ - CRC_SZ); // binary stuff needs to be padded with 0

        data = do_file_input(data, infile, len);
        if (data == NULL) {
            goto err;
        }

        return data;
    }

    /* cmd input */
    if (0 == strncasecmp(type, TP_CMD, strlen(TP_CMD))) {
	     int ret = 0;
	    char *cmd = sanitize(arg);
	
	    DPRINTF("command input: \"%s\"\n", cmd);
	    ret = system(cmd);    
		
        if (0 > ret) {
	        fprintf(stderr, "Error: executing %s returned %d\n", arg, ret);
	        goto err;
	    }
		memset(data, 0x0, RIP2_SZ - CRC_SZ); // binary stuff needs to be padded with 0
        data = do_file_input(data, "temp.exrip", len);
	
        return data;
    }

err:
    free(data);
    return NULL;
}

/*
 * Performs the real heavy lifting: processes the input file line by line:
 * parses each line, adds the corresponding data and index item to the RIP2
 * buffer.
 * IN: infile: pointer to the memory mapped input file
 *     outfile: pointer to the memory mapped output file
 *
 * RETURNS: 0 upon success, a negative value upon failure
 */
int process_inputfile(FILE    *infile,
                      uint8_t *outfile)
{
    int           items_read, i=0;
    char          line[LINE_MAX];
    T_RIP2_ID     ID;
    char          *sAttrHi, *sAttrLo, *type, *arg, *tmp;
    const char    *delim = "=:";
    uint32_t      attrHi = 0, attrLo = 0;
	uint16_t	  pad = 0;
    unsigned long len    = 0;
    uint8_t       *data  = NULL;

    DPRINTF("\n********************************************************\n");
    /* Process the input file line by line */
    while (fgets(line, LINE_MAX, infile) != NULL) {
	i++;
        if ((line[0] == '#') || 
	    (line[0] == ' ') || 
	    (line[0] == '\n') ||
	    (line[0] == '\r')){
            /* skip this line */
            continue;
        }

        /* Try to parse the line */
        items_read = 0;

        /* Chop the string up in substrings */
        tmp = strtok(line, delim);
        if (tmp != NULL) {
            items_read = sscanf(tmp, "%04hx:", &ID);
        }

        if (items_read == 1) {
            sAttrHi  = strtok(NULL, delim);
            sAttrLo  = strtok(NULL, delim);
            type   = strtok(NULL, delim);
            arg    = strtok(NULL, delim);
            DPRINTF("ID: %04x, AttrHi: %s, AttrLo: %s, type: %s, arg: %s", ID, sAttrHi, sAttrLo, type, arg); 

            data = get_input_data(&len, type, arg);
            if (data == NULL) {
                return -1;
            }

            if (0 > process_flag(sAttrHi, &attrHi)) {
                goto err;
            }
           
            if (0 > process_flag(sAttrLo, &attrLo)) {
                goto err;
            }
           
			/* Check if input needs padding */
			pad = get_padding(ID);
			if ((pad != 0xFFFF) && (len < pad)) {
			   DPRINTF("going to add %d padding bytes\r\n", pad - len);
			   len = pad;
			} 

            /* Now add it to the RIP2*/
            if (0 > rip2_drv_write(data, len, ID, attrHi, attrLo)) {
                fprintf(stderr, "Error while adding item with index %x\n", ID);
	            goto err;
	        }
			free(data);

            DPRINTF("********************************************************\n");
        }
	else {
	    fprintf(stderr, "Syntax error while processing line %d\n", i);
	    return -1;
	}
    }

    return 0;
	
err:
	free(data);
    return -1;
}


/*
 * Verify if the input file is a valid RIPv2 sector.
 */
int verify_rip2(char *argv_t[])
{
    int           infd;
    uint8_t       *ripbuf;
    struct stat inst;

    /* Generate a CRC table */
    rip2_mk_crc32_table(CRC32, rip2_crc32_hw);

    /********* Prepare input file for business *********/
    infd = open(argv_t[1], O_RDONLY);
    if (infd == -1) {
        fprintf(stderr,"Opening input file %s\n", argv_t[1]);
        return -1;
    }

    fstat(infd, &inst);
    if (inst.st_size != RIP2_SZ) {
        fprintf(stderr, "Input file does not match size requirement (%d bytes) for RIP2, aborting!\n", RIP2_SZ);
        close(infd);
        return -1;
    }

    /* mmap the output file so we can treat it as memory */
    ripbuf = mmap(0, RIP2_SZ, PROT_READ, MAP_PRIVATE | MAP_FIXED, infd, 0);
    if (MAP_FAILED == ripbuf) {
        fprintf(stderr,"Mapping to input file\n");
        munmap(ripbuf, RIP2_SZ);
        close(infd);
        return -1;
    }
    rip2_flash_init(ripbuf, RIP2_SZ);

    if (0 > rip2_init(ripbuf, 1, RIP2_SZ)) {
        fprintf(stderr, "Error intializing RIP2 library.\n");
        munmap(ripbuf, RIP2_SZ);
        close(infd);
        return -1;
    }

    if (rip2_verify_crc(ripbuf)) {
        printf("Verifying RIPv2 CRC: ok.\n");
    }
    else {
        fprintf(stderr, "Verifying RIPv2 CRC: invalid!\n");
		return -1;
    }

#if 0
    printf("\nRIPv2 index table content\r\n");
	printf("=========================\r\n");
	rip2_show_idx(ripbuf);
#endif

    munmap(ripbuf, RIP2_OFFSET);
    close(infd);

    return 0;
}

/*
 * Process an input file and generate a corresponding RIPv2 sector
 */
int generate_rip2(char *argv_t[], unsigned int  Set_ERIP_Header)
{
    int           outfd;
    FILE          *infd;
    uint8_t       *ripbuf;

    /* Generate a CRC table */
    rip2_mk_crc32_table(CRC32, rip2_crc32_hw);

    /********* Prepare input and output files for business *********/
    infd = fopen(argv_t[1], "r");
    if (infd == NULL) {
        fprintf(stderr,"Opening input file %s\n", argv_t[1]);
        goto out_err;
    }

    outfd = open(argv_t[2], O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (outfd == -1) {
        fprintf(stderr,"Opening input file %s\n", argv_t[1]);
        fclose(infd);
        goto out_err;
    }
    
    ripbuf = malloc(RIP2_SZ);
    
    if (ripbuf == 0) {
        fprintf(stderr,"Allocate memory\n");
        goto out_err_close;
    }
    memset(ripbuf, 0xFF, RIP2_SZ);
    rip2_flash_init(ripbuf, RIP2_SZ);

    if (0 > rip2_init(ripbuf, 0, RIP2_SZ)) {
        fprintf(stderr, "Error intializing RIP2 library.\n");
        goto out_err_close;
    }

    /********** Start processing and generate the RIP2 ***********/
    if (0 > process_inputfile(infd, ripbuf)) {
        goto out_err_unmap;
    }
    
    /* Prepend header for MBH upload */
    if (Set_ERIP_Header) {
        unsigned int crcsize = RIP2_SZ + sizeof(T_RIP2_FILEHEADER);
        uint8_t * tempimg  = malloc(crcsize);
        if (!tempimg) {
            fprintf(stderr, "Error allocating buffer.\n");
            goto out_err_unmap;
        }
        memcpy(tempimg + sizeof(T_RIP2_FILEHEADER), ripbuf,RIP2_SZ);
            
        T_RIP2_FILEHEADER * header = (T_RIP2_FILEHEADER *)tempimg;
        header->imagesize = HTOBE32(RIP2_SZ);
        header->RIP2_idtag = HTOBE32(RIP2TAG);
        header->headersize = HTOBE32(sizeof(T_RIP2_FILEHEADER));
        header->crc = 0;
        header->crc = HTOBE32(rip2_crc32((unsigned char *)header,crcsize));
        if (write(outfd, header,sizeof(T_RIP2_FILEHEADER)) != sizeof(T_RIP2_FILEHEADER)) {
            fprintf(stderr, "Error writing RIP2 header to file.\n");
            free(tempimg);
            goto out_err_unmap;
        }
        free(tempimg);
    }

    if (write(outfd, ripbuf,RIP2_SZ) != RIP2_SZ) {
        fprintf(stderr, "Error writing RIP2 data to file.\n");
        goto out_err_unmap;
    }

    
    /* done successful */
    DPRINTF("\rRIPv2 created.\n");  

    free(ripbuf);

    fclose(infd);
    close(outfd);

    return 0;

out_err_unmap:

out_err_close:
    free(ripbuf);
    fclose(infd);
    close(outfd);

out_err:
    printf("\rRIPv2 creation failed!\n");

    return -1;
}

int main(int  argc,
         char *argv[])
{
    int           i, y;
    unsigned int  Set_ERIP_Header = 0, Check_ERIP_File = 0;
    char          *argv_t[4];

    /***** Check the input arguments ********/
    if (argc < 3) {
        /* Error */
        printf("Error \n\r");
        printf("%s", exRipBuilderInfo);
        return -1;
    }

    for (i = 0, y = 0; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "-h")) {
                Set_ERIP_Header = 1;
                continue;
            }

            if (!strcmp(argv[i], "-v")) {
                Check_ERIP_File = 1;
                continue;
            }
			if (!strcmp(argv[i], "-p")) {
                Do_Padding = 1;
                continue;
            }
        }

        argv_t[y] = argv[i];
        y++;
    }

		
    if (Check_ERIP_File) {
        verify_rip2(argv_t);
    }
    else if (0 > generate_rip2(argv_t, Set_ERIP_Header)) {
       return -1;
    }

    return 0;
}
