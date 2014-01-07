default: all
all: readpe

readpe: readpe.c
	gcc readpe.c -o readpe

clean: readpe.o readpe
	rm readpe.o readpe
