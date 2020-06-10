#include <stdlib.h>
#include <stdint.h>

typedef unsigned char byte;

void MD5init(int32_t *state);
void MD5trans(int32_t *state, byte *inpdata);
void MultRSA(byte *src, byte *dst, int numblocks);

int ReadAsmFile(FILE *, byte *, int);
FILE *fopen_with_extension(char *name, char *ext, char *mode);
void WriteHILO(char *name, size_t srcoffset, int nosplitflag);
void Write4xROM(char *name, size_t srcoffset);
void Write1xROM(char *name, size_t srcoffset);
