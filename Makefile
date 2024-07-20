#
# Makefile for jagcrypt Jaguar Cartridge Encryption program
# (Really, it's not encryption, but a digital signature)
#

# Uncomment the following line to compile for Win32
#SYSTYPE     = __GCCWIN32__

# Uncomment the following lines to compile for cygwin
SYSTYPE     = __CYGWIN__

# Uncomment the following lines to compile for *nix
SYSTYPE     = __GCCUNIX__


ifeq ($(SYSTYPE),__GCCWIN32__)
  EXESUFFIX = .exe
  WHICH     = where 2>/devNUL
  # By default, make UPX a no-op
  UPX       = dir /B
else
  ifeq ($(SYSTYPE),__CYGWIN__)
  EXESUFFIX = .exe
  else
  EXESUFFIX =
  endif
  WHICH     = which
  # By default, make UPX a no-op
  UPX       = ls
endif

# If UPX is installed in the PATH, use it.
ifneq (,$(shell $(WHICH) upx))
  UPX       = upx -9
endif

CC          = gcc
LD          = gcc
TARGET      = jagcrypt$(EXESUFFIX)

CFLAGS = -Wall -Wno-switch -O2 -fomit-frame-pointer

LDFLAGS = $(CFLAGS)

LIBS =

INCS = -I.

THECC = $(CC) $(CFLAGS) $(INCS)

OBJS = \
	obj/bytemath.o \
	obj/fileio.o \
	obj/jagcrypt.o \
	obj/rsa.o

all: obj $(TARGET)

clean:
	@rm -rf obj
	rm -f ./jagcrypt$(EXESUFFIX)
	rm -f NUL
	rm -f *.bak

obj:
	mkdir obj

obj/%.o: %.c
	$(THECC) -c $< -o $@

obj/%.o: %.cpp
	$(THECC) -c $< -o $@

jagcrypt$(EXESUFFIX): $(OBJS)
	@$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)
