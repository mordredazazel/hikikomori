hikikomori: hikikomori.c md5.c
	gcc -o hikikomori hikikomori.c md5.c -pthread

clean:
	rm hikikomori