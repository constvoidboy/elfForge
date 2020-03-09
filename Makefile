CC=gcc
CFLAGS=-W -Wall -pedantic 
LDFLAGS=
EXEC=elfForge hello

all: $(EXEC) 

elfForge: elfForge.o
	@$(CC) -o $@ $^ $(LDFLAGS)

hello: hello.o
	@$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	@$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	@rm -rf *.o

mrproper: clean
	@rm -rf $(EXEC)
