
all:
	gcc main.c -o main -w -g

clean:
	rm -rf ./emulator_code
	rm -rf ./emulator_code.o
	rm -rf ./main
