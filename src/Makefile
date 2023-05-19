CC = gcc
CFLAGS = -I $(IDIR) -g

ODIR = obj

_OBJ = magnolia.o serve.o network.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

magnolia: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
