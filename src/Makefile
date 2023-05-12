IDIR = ../include
CC = gcc
CFLAGS = -I $(IDIR) -g

ODIR = obj

_DEPS = magnolia.h serve.h network.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = magnolia.o serve.o network.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

magnolia: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
