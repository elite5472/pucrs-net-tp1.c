default:
	mkdir -p bin && g++ -pthread -std=c++11 main.cpp -o bin/tp1
	
run:
	mkdir -p bin && g++ -pthread -std=c++11 main.cpp -o bin/tp1 && ./bin/tp1