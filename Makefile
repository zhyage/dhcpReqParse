dhcpCatch:main.o getInforFromDhcpReq.o
	g++ main.o getInforFromDhcpReq.o -o dhcpCatch

main.o:main.cpp
	g++ -c main.cpp

getInforFromDhcpReq.o:getInforFromDhcpReq.cpp
	g++ -c getInforFromDhcpReq.cpp

clean:
	rm -rf dhcpCatch
	rm -rf *.o
