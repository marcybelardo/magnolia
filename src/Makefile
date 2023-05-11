IDIR = ../include
CC = gcc
CFLAGS = -I $(IDIR) -g

ODIR = obj

_DEPS = reader.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = magnolia.o reader.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

magnolia: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
