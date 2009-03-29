#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#include "_skip32.c"

typedef struct skip32 {
    unsigned char key[10];
} *Crypt__Skip32__XS;

MODULE = Crypt::Skip32::XS    PACKAGE = Crypt::Skip32::XS

PROTOTYPES: DISABLE

Crypt::Skip32::XS
new (class, key)
    SV *class
    SV *key
PREINIT:
    STRLEN key_size;
    unsigned char *bytes;
CODE:
    if (! SvPOK(key)) {
        croak("key must be an untained string scalar");
    }

    bytes = (unsigned char *)SvPV(key, key_size);
    if (10 != key_size) {
        croak("key must be 10 bytes long");
    }

    New(0, RETVAL, 1, struct skip32);
    Copy(bytes, RETVAL->key, key_size, unsigned char);
OUTPUT:
    RETVAL

int
keysize (...)
CODE:
    RETVAL = 10;
OUTPUT:
    RETVAL

int
blocksize (...)
CODE:
    RETVAL = 4;
OUTPUT:
    RETVAL

SV *
decrypt (self, input)
    Crypt::Skip32::XS self
    SV *input
ALIAS:
    encrypt = 1
PREINIT:
    STRLEN block_size;
CODE:
    block_size = SvCUR(input);
    if (4 != block_size) {
        croak("input must be 4 bytes long");
    }

    RETVAL = newSVsv(input);
    skip32(self->key, (unsigned char *)SvPV(RETVAL, block_size), ix);
OUTPUT:
    RETVAL

void
DESTROY (self)
    Crypt::Skip32::XS self
CODE:
    Safefree(self);
