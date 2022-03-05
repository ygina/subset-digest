# ILP=glpk
ILP=glpk_preprocessed
# ILP=brute

main: main.c $(ILP).c options.h iblt.h
	cc $^ -lglpk -o $@
