OUT = ./out/bin
FILES = ./source/main.cpp
FLAGS = -Wall -std=c++2a

main: clear
	g++ -o $(OUT) $(FILES) $(FLAGS) 
	sudo $(OUT)

clear:
	clear
