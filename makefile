
BINARY = cryptonomicon

CXXSOURCES = main.cpp DES.cpp RSA.cpp Flint/flintpp.cpp  
CSOURCES = Flint/flint.c  Flint/kmul.c  

OBJECTS = ${CXXSOURCES:.cpp=.o} ${CSOURCES:.c=.o} 

INCLUDES = -I . -I Flint -I /usr/include 

LOCATIONS = -L/usr/lib64

LIBRARIES = -lcrypto

CXXFLAGS = -ggdb -fmessage-length=0 -ansi -Wall
CFLAGS = -ggdb -fmessage-length=0 -ansi -Wall
CXX = g++ 
CC = gcc 

.SUFFIXES:      .cpp .o

.cpp.o:
		@echo
		@echo Building $@		
		${CXX} ${CXXFLAGS} ${INCLUDES} -c -o $@ $<
.c.o:
		@echo
		@echo Building $@		
		${CC} ${CFLAGS} ${INCLUDES} -c -o $@ $<

all:            ${OBJECTS} ${BINARY} 

${BINARY}:      ${OBJECTS}
		@echo
		@echo Building ${BINARY} Executable
		${CXX} -o $@ \
		${OBJECTS}  \
		${LIBRARIES} \
		${LOCATIONS}
                         
clean:
		rm -f ${BINARY} *.o Flint/*.o



