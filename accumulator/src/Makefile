# CFLAGS += -fsanitize=address 
CFLAGS += -g
all:
	clang++ -std=c++20 -Wall -Wextra $(CFLAGS) -pedantic -O3 -fconstexpr-steps=99999999 TestProgram.cpp
	./a.out
