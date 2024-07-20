/*
 * Jaguar Cartridge Encryption Software
 * Portable C version
 *
 * Copyright 1993-1995 Atari Corporation
 * All Rights Reserved
 *
 * Written by Eric R. Smith
 * Based on the 680x0 assembly language
 * version by Dave Staugas.
 *
 * Built in public and private key version + unsplit ROM option
 * by James L. Hammons
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "rsa.h"
#include "fileio.h"


/*
 * function to put a 32-bit integer into a stream of bytes
 */
static void
Putlong(unsigned char *dest, int32_t x)
{
  dest[0] = (x >> 24) & 0x00ff;
  dest[1] = (x >> 16) & 0x00ff;
  dest[2] = (x >> 8) & 0x00ff;
  dest[3] = x & 0x00ff;
}

/* possible output formats */
#define HILO 0
#define ROM4 1
#define UNSPLIT 2

#undef BUFSIZE
#define BUFSIZE 4096

/* Global variables */
byte privateK[] = {                     /* private key binary image */
  0x1f,0xd8,0xb4,0xfb,0xcf,0xb9,0x67,0x60,
  0x6c,0x9c,0x2f,0x1d,0x16,0xa0,0x13,0xca,
  0x83,0xda,0x63,0x2a,0xb0,0x7b,0xab,0xaa,
  0xe9,0x92,0x62,0xa3,0x57,0x56,0xd6,0xa9,
  0x9a,0x96,0x6b,0x14,0x75,0x39,0xa3,0x98,
  0xeb,0x5b,0xa7,0x42,0x1c,0x54,0xe0,0x1c,
  0xd7,0xee,0x2e,0xe7,0xa5,0xf9,0x7e,0xdf,
  0xce,0xe8,0xed,0xca,0xdc,0x3d,0x2f,0xe8,
  0xab
};

byte publicK[] = {                      /* public key binary image */
  0x2f,0xc5,0x0f,0x79,0xb7,0x96,0x1b,0x10,
  0xa2,0xea,0x46,0xab,0xa1,0xf0,0x1d,0xaf,
  0xc5,0xc7,0x94,0xc0,0x08,0xb9,0x81,0x80,
  0x5e,0x5b,0x93,0xf5,0x03,0x02,0x41,0xfe,
  0x75,0xb7,0x1c,0xe8,0xe7,0x22,0x79,0xa3,
  0xd5,0xbe,0x30,0x45,0xf9,0xea,0x35,0xd9,
  0x8a,0x0a,0x15,0x40,0xb4,0xb4,0xe8,0x4e,
  0xa6,0xdd,0x17,0xee,0x42,0x33,0x10,0x0d,
  0xf9
};

byte inbuf[0x2000];                     /* input buffer */
byte romimg[0x1c02];                    /* image for first part of ROM */

/* magic GPU boot code, compiled */
static const byte boot_orig[] = {
  0x00,0xF0,0x35,0xAC,0x00,0x00,0x02,0x80,0xA5,0x00,0xA7,0x22,0xBF,0x20,0xBD,0x02,
  0x01,0x28,0x18,0x25,0xD7,0x21,0x08,0x99,0x98,0x02,0x35,0xF4,0x00,0xF0,0x98,0x07,
  0x36,0xFC,0x00,0xF0,0xD0,0x40,0xE4,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x98,0x15,0x38,0x2C,0x00,0xF0,0x8F,0xEB,0x89,0x76,0x02,0xD6,0x98,0x0F,0x02,0xC0,
  0x00,0x80,0x98,0x0A,0x00,0x00,0x00,0x88,0x98,0x10,0x23,0x01,0x67,0x45,0x98,0x11,
  0xAB,0x89,0xEF,0xCD,0x98,0x12,0xDC,0xFE,0x98,0xBA,0x98,0x13,0x54,0x76,0x10,0x32,
  0x98,0x18,0x36,0x4C,0x00,0xF0,0x98,0x14,0x36,0x30,0x00,0xF0,0x88,0xE8,0x8A,0xAE,
  0x8E,0x09,0xA5,0xE0,0x08,0x8F,0xBD,0xC0,0x18,0x29,0xD7,0x61,0x0C,0x8E,0x8A,0x1A,
  0x8A,0x3B,0x8A,0x5C,0x8A,0x7D,0x8A,0xAE,0xA5,0x06,0x08,0x88,0xA5,0x04,0x08,0x88,
  0x88,0x83,0x25,0x63,0x76,0x04,0x25,0x64,0xA5,0x05,0x08,0x88,0xD0,0xC0,0x8E,0x09,
  0x8B,0x60,0x8B,0x61,0x27,0x80,0x30,0x01,0xD4,0xC0,0x27,0xA1,0x8B,0xA0,0x8B,0xA1,
  0x27,0x60,0x30,0x01,0x27,0x81,0xD5,0x20,0x28,0x20,0x8B,0xA0,0x2F,0x60,0xD4,0xA0,
  0x2F,0x80,0x8B,0xA0,0x30,0x00,0x2B,0x60,0x2F,0x80,0xE8,0x61,0x00,0x83,0x00,0x20,
  0xA5,0x01,0x26,0xC3,0x00,0x20,0x08,0x88,0x03,0x40,0x88,0xAC,0x75,0x05,0x25,0x6C,
  0x71,0x80,0x03,0x60,0x18,0x29,0x8B,0xBA,0x8B,0x9D,0x8B,0x7C,0xD0,0xC1,0x88,0x1B,
  0x79,0x15,0xD3,0x01,0xE4,0x00,0x03,0x50,0x03,0x71,0x03,0x92,0x03,0xB3,0x79,0x4F,
  0xD2,0x88,0x88,0xE8,0x98,0x06,0x35,0x60,0x00,0xF0,0x18,0x99,0xA7,0x20,0x7A,0x60,
  0xD0,0xC1,0x18,0x99,0xA7,0x20,0x7A,0x40,0xD0,0xC1,0x18,0x99,0xA7,0x20,0x7A,0x20,
  0xD0,0xC1,0x18,0x99,0xA7,0x20,0x7A,0x00,0xD0,0xC1,0xE4,0x00,0x08,0xC6,0x98,0x04,
  0xDE,0xAD,0x03,0xD0,0xD0,0xC0,0xE4,0x00,0x00,0xF0,0x36,0x64,0x00,0x04,0x00,0x00,
  0x0A,0x0F,0x14,0x19,0xD7,0x6A,0xA4,0x78,0xE8,0xC7,0xB7,0x56,0x24,0x20,0x70,0xDB,
  0xC1,0xBD,0xCE,0xEE,0xF5,0x7C,0x0F,0xAF,0x47,0x87,0xC6,0x2A,0xA8,0x30,0x46,0x13,
  0xFD,0x46,0x95,0x01,0x69,0x80,0x98,0xD8,0x8B,0x44,0xF7,0xAF,0xFF,0xFF,0x5B,0xB1,
  0x89,0x5C,0xD7,0xBE,0x6B,0x90,0x11,0x22,0xFD,0x98,0x71,0x93,0xA6,0x79,0x43,0x8E,
  0x49,0xB4,0x08,0x21,0x00,0xF0,0x36,0x70,0x00,0x14,0x00,0x04,0x0C,0x12,0x17,0x1B,
  0xF6,0x1E,0x25,0x62,0xC0,0x40,0xB3,0x40,0x26,0x5E,0x5A,0x51,0xE9,0xB6,0xC7,0xAA,
  0xD6,0x2F,0x10,0x5D,0x02,0x44,0x14,0x53,0xD8,0xA1,0xE6,0x81,0xE7,0xD3,0xFB,0xC8,
  0x21,0xE1,0xCD,0xE6,0xC3,0x37,0x07,0xD6,0xF4,0xD5,0x0D,0x87,0x45,0x5A,0x14,0xED,
  0xA9,0xE3,0xE9,0x05,0xFC,0xEF,0xA3,0xF8,0x67,0x6F,0x02,0xD9,0x8D,0x2A,0x4C,0x8A,
  0x00,0xF0,0x36,0x7E,0x00,0x0C,0x00,0x14,0x09,0x10,0x15,0x1C,0xFF,0xFA,0x39,0x42,
  0x87,0x71,0xF6,0x81,0x6D,0x9D,0x61,0x22,0xFD,0xE5,0x38,0x0C,0xA4,0xBE,0xEA,0x44,
  0x4B,0xDE,0xCF,0xA9,0xF6,0xBB,0x4B,0x60,0xBE,0xBF,0xBC,0x70,0x28,0x9B,0x7E,0xC6,
  0xEA,0xA1,0x27,0xFA,0xD4,0xEF,0x30,0x85,0x04,0x88,0x1D,0x05,0xD9,0xD4,0xD0,0x39,
  0xE6,0xDB,0x99,0xE5,0x1F,0xA2,0x7C,0xF8,0xC4,0xAC,0x56,0x65,0x00,0xF0,0x36,0x86,
  0x00,0x1C,0x00,0x00,0x0B,0x11,0x16,0x1A,0xF4,0x29,0x22,0x44,0x43,0x2A,0xFF,0x97,
  0xAB,0x94,0x23,0xA7,0xFC,0x93,0xA0,0x39,0x65,0x5B,0x59,0xC3,0x8F,0x0C,0xCC,0x92,
  0xFF,0xEF,0xF4,0x7D,0x85,0x84,0x5D,0xD1,0x6F,0xA8,0x7E,0x4F,0xFE,0x2C,0xE6,0xE0,
  0xA3,0x01,0x43,0x14,0x4E,0x08,0x11,0xA1,0xF7,0x53,0x7E,0x82,0xBD,0x3A,0xF2,0x35,
  0x2A,0xD7,0xD2,0xBB,0xEB,0x86,0xD3,0x91
};

/* tursi's boot code loads here */
byte boot_tursi[8192+8];        // encryption code always skips the first 8 bytes, so whatever
int boot_tursi_size = 0;

/* pointer to abstract */
byte *boot1 = (byte *)boot_orig;
int TursiMode = 0; /* operates normally unless you set -tursi */

long filesize;                  /* length of file (+ 0x2000, since ROM starts at 0x802000 */
long romsize;                   /* size of ROM needed to contain the file */
int32_t MD5state[4];            /* MD5 hash for file+fill */
int quiet = 0;
/*
 * boot flags and vectors
 */
byte Romconfig[12] = {
  0x04, 0x04, 0x04, 0x04,
  0x00, 0x80, 0x20, 0x00,
  0x00, 0x00, 0x00, 0x00
};

void usage(void)
{
  fprintf(stderr, "Usage: jagcrypt [-q] -[h|n|4|u] [-p] filename.ext\n");
  fprintf(stderr, "   -q: Be quiet\n");
  fprintf(stderr, "Output format is specified by the first flag:\n");
  fprintf(stderr, "   -h: Use HI/LO format, split in pieces if > 2 megs total\n");
  fprintf(stderr, "   -n: Use HI/LO format, don't split large files\n");
  fprintf(stderr, "   -4: Use 4xROM format, output in .U1,.U2,.U3,.U4\n");
  fprintf(stderr, "   -u: Use 1xROM format, output in .U1\n");
  fprintf(stderr, "Exactly one of the flags above must appear\n");
  fprintf(stderr, "Optional flags:\n");
  fprintf(stderr, "   -p: Use previous encryption data from a .XXX file\n");
  fprintf(stderr, "   -tursi <bin>: load and encrypt the compiled GPU BIN as a\n"
                  "                  header, no patching. Only XXX exported.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Examples:\n");
  fprintf(stderr, "To encrypt the 4 meg file FOO.ROM into FOO.HI0, FOO.HI1,\n");
  fprintf(stderr, "FOO.LO0 and FOO.LO1, use:\n");
  fprintf(stderr, "   jagcrypt -h foo.rom\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "To quickly encrypt BAR.ABS into BAR.U1, BAR.U2, BAR.U3, and\n");
  fprintf(stderr, "BAR.U4 (re-using the RSA data from BAR.XXX), use:\n");
  fprintf(stderr, "   jagcrypt -4 -p bar.abs\n");
  exit(1);
}

/* XXX Support big-endian machines */
#define SWAPUINT32(b)                           \
  (((b) << 24) | (((b) & 0x0000ff00) << 8) |    \
   (((b) & 0x00ff0000) >> 8) | ((b) >> 24))

static int DetectFileType(FILE *infile)
{
  uint32_t rombits;
  uint32_t romstart;
  uint32_t romflags;
  uint32_t romstart_swapped;
  uint32_t romflags_swapped;
  uint32_t *uptr;

  if (fseek(infile, 0x400, SEEK_SET))
  {
    /*
     * Probably not a valid file, but not fatal here.
     * Could be a tiny ABS?  However, it is not a ROM
     * file.
     */
    return 0;
  }

  if (fread(&rombits, 4, 1, infile) != 1)
  {
    /* Not fatal, same logic as above */
    return 0;
  }

  /* rombits is endian-agnostic */

  if (fread(&romstart, 4, 1, infile) != 1)
  {
    /* Not fatal, same logic as above */
    return 0;
  }

  romstart_swapped = SWAPUINT32(romstart);

  if (fread(&romflags, 4, 1, infile) != 1)
  {
    /* Not fatal, same logic as above */
    return 0;
  }

  romflags_swapped = SWAPUINT32(romflags);

  switch (rombits) {
  case 0x04040404:
  case 0x02020202:
  case 0x00000000:
    break;
  default:
    return 0;
  }

  /* Not strictly required, but is it ever not this? */
  if (romstart_swapped != 0x00802000)
  {
    return 0;
  }

  if (romflags_swapped != 0x00000000 && romflags_swapped != 0x00000001)
  {
    return 0;
  }

  /* Update Romconfig to match existing ROM data */
  uptr = (uint32_t *)&Romconfig[0];
  *uptr++ = rombits;
  *uptr++ = romstart;
  *uptr++ = romflags;

  return 1;
}

int main(int argc, char **argv)
{
  int useprevdata;      /* 1 if we should use an existing .XXX file for RSA data */
  int i;                                /* scratch variable */
  FILE * fhandle;
  byte * nnum, * cnum;
  int outfmt = ROM4;                   /* output format */
  int nosplit;          /* split HI/LO parts of output (if 0) or not (if -1) */
  char * filename;      /* name of file to encrypt */
  size_t xxxsize;               /* size of .XXX file */
  size_t powof2;                /* smallest power of 2 that the ROM can fit into */
  int ateof;                    /* flag: set to 1 at end of file */
  size_t srcoffset = 0;     /* 0x2000 if <filename> is a ROM file, 0 otherwise */

  xxxsize = 1036;               /* default size of a .XXX file */
  nosplit = 0;

  if (argc < 3) {
    usage();
  }

  /* figure out output format from first parameter */
  argv++;
  if (argv[0][0] != '-') {
    fprintf(stderr, "ERROR: you must specify an output format\n");
    usage();
  }

  if (argv[0][1] == 'q'){
    quiet = 1;
    ++argv;
  }

  switch(argv[0][1]) {
  case 'h':     /* HI/LO output format, split big files */
    outfmt = HILO;
    nosplit = 0;
    break;
  case 'n':     /* HI/LO output format, do not split big files */
    outfmt = HILO;
    nosplit = 1;
    break;
  case '4':     /* 4xROM output format */
    outfmt = ROM4;
    break;
  case 'u':     /* 1xROM output format */
    outfmt = UNSPLIT;
    nosplit = 1;
    break;
//->  case 'x': /* single file output format */
//->    outfmt = SINGLE;
//->    nosplit = 1;
    break;
  default:
    fprintf(stderr, "ERROR: unknown output format `%c'\n", argv[0][1]);
    usage();
    break;
  }
  argv++;

  if (!*argv) {
    usage();
  }

  /* check for '-p' flag for "Use previous encryption data */
  useprevdata = 0;
  while (argv[0][0] == '-') {
    if (argv[0][1] == 'p'){
      useprevdata = 1;
    } else if (0 == strcmp(argv[0], "-tursi")) {
      if ( !quiet ) printf("Switching to Tursi's encryption mode.\n");
      TursiMode=1;
      boot1 = boot_tursi;
    } else {
      fprintf(stderr, "ERROR: unknown option `%s'\n", argv[0]);
      usage();
    }
    argv++;
  }

  if (!*argv) {
    fprintf(stderr, "ERROR: no file name specified\n");
    usage();
  }

  if (argv[1]) {
    fprintf(stderr, "ERROR: only 1 file may be specified at a time\n");
    usage();
  }
  if ( !quiet ){
    printf("\n");
    printf("JAGUAR Cartridge (quik) Encryption Code\n");
    printf("Including Tursi's extentions\n");
    printf("Version 0.9\n");
  }

  filename = argv[0];

  if (!useprevdata) {
    /* copy keys to RSA numbers */
    nnum = N_num;
    cnum = C_num;
    *nnum++ = 0;
    *cnum++ = 0;
    for (i = 0; i < KEYSIZE-1; i++) {
      *nnum++ = publicK[i];
      *cnum++ = privateK[i];
    }
  }

/* try to open the file to encrypt */
  fhandle = fopen(filename, "rb");
  if (!fhandle) {
    /* report error and exit */
    perror(filename);
    exit(1);
  }
  if (TursiMode) {
    // the filename is the boot file to encrypt, so drag that in
    // note: the encryption code skips the first 8 bytes, so we do here too
    boot_tursi_size = fread(&boot_tursi[8], 1, sizeof(boot_tursi)-8, fhandle);
    boot_tursi_size -= 8;
    fclose(fhandle);
  } else {
    if (DetectFileType(fhandle))  {
      if ( !quiet ) printf("Detected existing ROM header.\n");
      srcoffset = 0x2000;
    } else {
      srcoffset = 0;
    }

    if (fseek(fhandle, srcoffset, SEEK_SET)) {
      perror(filename);
      exit(1);
    }
    if ( !quiet ) printf("Calculating MD5 on: %s\n", filename);
  }

  filesize = 0x2000;    /* file starts at offset +$2000 */
  romsize = 0x2000;

  if (!TursiMode) {
    MD5init(MD5state);
  }

/*
 *  Cartridge ROM memory map:
 *
 *      $800000-$80028A         10x65+1 byte block RSA signature
 *      $80028B-$8002BF         Unprotected, unused ROM (53 bytes)
 *
 *start of MD5 protection
 *      $8002C0-$8003FF         start of MD5 protected space, unused (320 bytes)
 *      $800400-$800403         start-up vector (usually $802000)
 *      $800404-$800407         start-up vector (usually $802000)
 *      $800408-$80040B         Flags [31:01] undefined use 0's
 *                                bit0:  0-normal boot, 1-skip boot (diag cart)
 *
 *      $80040B-$801FFF         usually unused, protected (7156 bytes)
 *
 *      $802000-$9FFFFF                game cartridge ROM (may be smaller or larger)
 *end of MD5 protection
 *
 *
 * calculate MD5 on the non-game portion of protected ROM space
 */

/* fill buffer with all FF's */
  memset(inbuf, 0xff, 0x2000);

/* initialize start up vectors, etc. */
  memcpy(inbuf+0x400, Romconfig, 12);

  if (!TursiMode) {
    /* do MD5 on first part of ROM */
    cnum = inbuf+0x2c0;
    do {
      MD5trans(MD5state, cnum);
      cnum += 64;
    } while (cnum < (inbuf+0x2000));

    /* now read in blocks of game cart and do MD5 for each */
    ateof = 0;

    do {
      size_t numbytes;

      numbytes = fread(inbuf, 1, BUFSIZE, fhandle);
      if (numbytes < 0) {
        fprintf(stderr, "ERROR: read error on input\n");
        exit(1);
      }
      if (numbytes == 0) {
        /* end of file reached */
        ateof = 1;
        break;
      }
      filesize += numbytes;
      romsize += BUFSIZE;
      if (numbytes < BUFSIZE) {
        /* only a partial buffer */
        /* fill the rest of the buffer with FFs */
        memset(inbuf+numbytes, 0xFF, BUFSIZE-numbytes);
        /* indicate end of file */
        ateof = 1;
      }

      cnum = inbuf;
      do {
        MD5trans(MD5state, cnum);
        cnum += 64;
      } while (cnum < inbuf+BUFSIZE);

    } while (!ateof);

    fclose(fhandle);            /* we're done with the input file */
  }

/*
 * We need MD5 to cover all of ROM, which often needs to be larger than
 * the file
 */

/* find smallest power of 2 which can enclose the file */
  powof2 = 2;
  while (powof2 < romsize)
    powof2 *= 2;

/* fill the rest of ROM with ff's */
  memset(inbuf, 0xff, BUFSIZE);

  if (!TursiMode) {
    while (romsize < powof2) {
      MD5trans(MD5state, inbuf);
      romsize += 64;
    }
  }
  romsize = powof2;

  /* are we using the old encrypted data in foo.XXX */
  if (useprevdata) {
    /* read in previous encryption data */
    fhandle = fopen_with_extension(filename, ".XXX", "rb");
    if (!fhandle) {
      perror("Unable to open .XXX file");
      exit(1);
    }
    xxxsize = fread(romimg, 1, 0x1c02, fhandle);
    if (xxxsize < 0) {
      fprintf(stderr, "Read error on .XXX file\n");
      exit(1);
    }
    if (xxxsize >= 0x1c01) {
      fprintf(stderr, ".XXX file is too large ( > 7168 bytes).\n");
      exit(1);
    }
    fclose(fhandle);
  } else {
    /* start the RSA up from scratch */
#define HASHBASE 0x24
#define RANGE 0x54
    byte *a0, *a1, *a2, *a3, *a4;
    int32_t d0, d1, d2, d3;

    if ( !quiet ) printf("Calculating RSA...\n");

    /* stuff appropriate values into the GPU code */
    /* (Sorry about the mess, this was a straight conversion of Dave's
     *  assembly code)
     */
    a0 = boot1+8;
    a4 = (byte *)MD5state;
    d1 = 0xbc;
    a3 = a0+HASHBASE;

    d0 = *(int32_t *)a4;                /* don't use getlong, MD5state is in native format */
    if (!TursiMode) {
      Putlong(a3-4, ~d0);
    }
    d0 = *(int32_t *)(a4+4);
    if (!TursiMode) {
      Putlong(a3+32, ~d0);
    }

    d3 = 0;
    for (i = 0; i < 8; i++)  {
      d0 = Getlong(a0+d1);      /* need Getlong because it's in 68000 format */
      if (!TursiMode) {
        Putlong(a3, d0);
      }
      a3 += 4;
      d0 = *(int32_t *)(a4+d3);
      if (!TursiMode) {
        Putlong(a0+d1,d0);
      }
      d3 = (d3+4) & 0x0f;
      d1 += 0x40;

    }

    a1 = a0 + (RANGE+2);
    d1 = 0x02c00080;    /* 0x8002c0, word swapped */
    if (!TursiMode) {
      Putlong(a1, d1);
    }
    a1 += 6;
    d1 = romsize + 0x800000;
    d1 = ((uint32_t)d1 >> 16) | ((d1 & 0x0000ffff) << 16);      /* word swap */
    if (!TursiMode) {
      Putlong(a1, d1);
    }

    /* do 1 other tricky transform */
    a2 = boot1+8;
    a1 = a0;
    d1 = 0;
    for (i = 0; i < 0x280; i++) {
      d3 = d2 = *a2++;
      d2 -= d1;
      d1 = d3;
      *a1++ = (d2 & 0x00ff);
    }

    /* patching is complete, now let's RSA */

    /* prepare keysize-1 byte chunks for RSA */
    MultRSA(a0, romimg, 10);            /* parameters are source, destination, numblocks */
  }

  /* now write out the data */

  /* build the first 0x2000 byte block, corresponding to the ROM config
   * longword, the RSA signature, the startup vector, and the flags
   */

  memset(inbuf, 0xff, sizeof(inbuf));

  /* copy over the RSA signature */
  if (TursiMode) {
    int b = (boot_tursi_size+64)/65;
    memcpy(inbuf, romimg, b*65+1);
    if ( !quiet ) printf("New boot uses %d blocks\n", b);
    b = 0x100 - b;
    inbuf[0] = b;
  } else {
    memcpy(inbuf, romimg, 651);
  }
  memcpy(inbuf+0x400, Romconfig, 12);

  // patch number of blocks
  if (!TursiMode && !quiet ) {
    printf("ROM size %ld bytes...\n", romsize);
  }
  /* create signature file */
  fhandle = fopen_with_extension(filename, ".XXX", "wb");
  if (!fhandle) {
    perror(".XXX file");
    exit(1);
  }
  if (fwrite(inbuf, 1, xxxsize, fhandle) != xxxsize) {
    fprintf(stderr, "Write error on .XXX file!\n");
    exit(1);
  }
  fclose(fhandle);

  if (!TursiMode) {
    if ( !quiet ) printf("Writing data...\n");
    if (outfmt == HILO) {                        /* Hi/Lo split */
      WriteHILO(filename, srcoffset, nosplit);
//->    } else if (outfmt == SINGLE) {
//->      WriteSINGLE(filename);
    } else if (outfmt == ROM4) {
      Write4xROM(filename, srcoffset);
    } else {
      Write1xROM(filename, srcoffset);
    }
  }

  return 0;
}
