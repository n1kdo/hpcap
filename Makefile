OPTIMIZE= -O3 -Wall
DEBUG_FLAGS= #-g 
CFLAGS= $(DEBUG_FLAGS) $(OPTIMIZE)

all: hpcap

clean:
	rm -f *.o 

realclean: distclean

distclean: 
	rm -f *.o *~ hpcap

