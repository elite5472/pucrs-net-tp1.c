default:
	mkdir -p bin && g++ -pthread -std=c++11 main.cpp netstructs.h netutil.c -o bin/tp1