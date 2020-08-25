#
# Makefile for jagcrypt Jaguar Cartridge Encryption program
# (Really, it's not encryption by a digital signature)
#

# Uncomment the following lines to compile for Win32

#SYSTYPE   = __GCCWIN32__
#EXESUFFIX = .exe
#GLLIB     = opengl32
#ICON      = vj-ico.o

# Uncomment the following lines to compile for *nix

SYSTYPE   = __GCCUNIX__
EXESUFFIX =
GLLIB     = GL
ICON      =

CC         = gcc
LD         = gcc
TARGET     = jagcrypt$(EXESUFFIX)

CFLAGS = -Wall -Wno-switch -O2 -fomit-frame-pointer
#CFLAGS = -Wall -Wno-switch -O2 -D$(SYSTYPE) -Dstricmp="strcasecmp" \
#		-fomit-frame-pointer `sdl-config --cflags`
#		-fomit-frame-pointer `sdl-config --cflags` -g
#		-fomit-frame-pointer `sdl-config --cflags` -DLOG_UNMAPPED_MEMORY_ACCESSES

LDFLAGS = $(CFLAGS)

#LIBS = -L/usr/local/lib `sdl-config --libs` -lstdc++ -lz -l$(GLLIB)
LIBS =

#INCS = -I. -Isrc -Isrc/include -I/usr/local/include
INCS = -I.

THECC = $(CC) $(CFLAGS) $(INCS)

OBJS = \
	obj/bytemath.o \
	obj/fileio.o \
	obj/jagcrypt.o \
	obj/rsa.o

all: obj $(TARGET)

clean:
	rm -rf obj
	rm -f ./vj$(EXESUFFIX)

obj:
	mkdir obj

obj/%.o: %.c
	$(THECC) -c $< -o $@

obj/%.o: %.cpp
	$(THECC) -c $< -o $@

jagcrypt$(EXESUFFIX): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)
	strip --strip-all jagcrypt$(EXESUFFIX)
	upx -9 jagcrypt$(EXESUFFIX)

# Other stuff that has unusual dependencies

#obj/gui.o: src/gui.cpp src/include/gui.h src/include/font1.h
#	$(THECC) -c src/gui.cpp -o obj/gui.o
