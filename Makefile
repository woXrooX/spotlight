OUT = ./out/bin
FILES = ./source/main.cpp
FLAGS = -Wall -std=c++20

main: clear
	g++ -o $(OUT) $(FILES) $(FLAGS)
	sudo $(OUT)

clear:
	clear
