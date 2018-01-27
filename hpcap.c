#include <termios.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/time.h>

#include <ctype.h>
#define x_POSIX_SOURCE 1
#define TRUE 1
#define FALSE 0

#define BAUDRATE B19200

char appName[MAXPATHLEN];
char sInputPort[MAXPATHLEN];
char lprCommand[MAXPATHLEN];
char fulllprCommand[MAXPATHLEN+MAXPATHLEN+50];
int  runAsDaemon = FALSE;


#define DUMP_LINE_LENGTH 16

char dumpLine[DUMP_LINE_LENGTH];
int dumpLineChars = 0;

int escapeState = 0;
char esc2nd;
char esc3rd;
char escAction;
char escDigits[10];
int escDigitsCount;
int byteCount = 0;
int graphicsMode = FALSE;
int width = 0;
int height = 0;

#define IMAGE_DATA_SIZE 65536

int imageDataOffset = 0;
char * imageData;

void versionInfo(void)
{
    fprintf(stderr, "\nhpcap version 0.1,\n");
    fprintf(stderr, "Copyright (C) 2008 Jeff Otterson <otterson@yahoo.com>\n\n");
    fprintf(stderr, "hpcap comes with ABSOLUTELY NO WARRANTY; See COPYING for details.\n\n");
    fprintf(stderr, "This is free software, and you are welcome to redistribute it\n");
    fprintf(stderr, "under certain conditions; See COPYING for details.\n\n");
    fprintf(stderr, "You should have received a copy of the GNU General Public License\n");
    fprintf(stderr, "along with this program; if not, write to:\n");
    fprintf(stderr, "\tThe Free Software Foundation, Inc.\n");
    fprintf(stderr, "\t59 Temple Place\n");
    fprintf(stderr, "\tSuite 330\n");
    fprintf(stderr, "\tBoston, MA 02111-1307, USA\n\n");
}    

void usage ()
{
    fprintf(stderr, "\n");
    fprintf(stderr, "usage: %s [parameters]\n", appName);
    fprintf(stderr, "        Optional parameters are :\n");
    fprintf(stderr, "\t\t -d run as daemon.\n");
    fprintf(stderr, "\t\t -h display this help screen\n");
    fprintf(stderr, "\t\t -l set lpr command    \tdefault lpr -r %%s\n");
    fprintf(stderr, "\t\t -t input tty          \tdefault /dev/ttyS0\n");
    fprintf(stderr, "\t\t -v print version and exit\n");
    fprintf(stderr, "\n");
}

void printhex(char c)
{
    int lonibble = c & 0x0f;
    int hinibble = (c & 0xf0) >> 4;
    
    char hichar = (hinibble > 9) ? hinibble - 10 + 'a' : hinibble  + '0';
    char lochar = (lonibble > 9) ? lonibble - 10 + 'a' : lonibble  + '0';

    printf("%c%c", hichar, lochar);
} // printhex()

void consoleRaster(c)
{
    printf("%c", (c & 0x80) ? '*' : ' ');
    printf("%c", (c & 0x40) ? '*' : ' ');
    printf("%c", (c & 0x20) ? '*' : ' ');
    printf("%c", (c & 0x10) ? '*' : ' ');
    printf("%c", (c & 0x08) ? '*' : ' ');
    printf("%c", (c & 0x04) ? '*' : ' ');
    printf("%c", (c & 0x02) ? '*' : ' ');
    printf("%c", (c & 0x01) ? '*' : ' ');
} // consoleRaster()

void dumpToConsole(char * imageData, int width, int height)
{
    int rows;
    int columns;
    char c;

    //printf("dumpToConsole(data, %d, %d)\n", width, height);
    for (rows = 0; rows < 80; rows ++)
    {
        for (columns = 0; columns < 14; columns++)
        {
            c = imageData[width * rows + columns];
            consoleRaster(c);
        } // for columns
        printf("\n");
    } //r rows
} // dumpToConsole()

void getUniqueFileName(char *s)
{
    sprintf(s, "capture-%8x", time(NULL));
} /* getUniqueFileName() */

void char2hex(char c, char * buf)
{
    int hn = (c & 0xf0) >> 4;
    int ln = c & 0x0f;
    buf[0] = (hn > 9) ? hn - 10 + 'a' : hn + '0';
    buf[1] = (ln > 9) ? ln - 10 + 'a' : ln + '0';
    buf[2] = '\0';
} // char2hex()

void printDumpLine()
{
    char line[80];
    int offset = 0;  
    int i;
    char c;
    char ln, hn;
    line[offset++] = ' ';
    line[offset++] = ' ';
    for (i=0;i<DUMP_LINE_LENGTH;i++)
    {
        c = dumpLine[i];
        hn = (c & 0xf0) >> 4;
        ln = c & 0x0f;
        line[offset++] = (hn > 9) ? hn - 10 + 'a' : hn + '0';
        line[offset++] = (ln > 9) ? ln - 10 + 'a' : ln + '0';
        line[offset++] = ' ';
    } // for i
    line[offset++] = ' ';
    line[offset++] = ' ';
    for (i=0;i<DUMP_LINE_LENGTH;i++)
    {
        c = dumpLine[i];
        line[offset++] = isprint(c) ? c : '.';
    } // for i
    line[offset++] = '\0';
    printf("%s\n", line);
} // printDumpLine()

int getArgValue(char buf [], int size)
{
    int value = 0;
    int sign = 1;  // -1 for negative.
    int i;
    char c;

    for (i = 0; i < size; i++)
    {
        c = buf[i];
        if (i == 0) // look for sign
        {
            if (c == '-') 
            {
                sign = -1;
                continue;
            } // if c == '-'
            if (c == '+')
            {
		continue;
            } // if c == '+'
        } // if i == 0
        value *= 10;
        if (isdigit(c))
        {
            value += (c - '0');
        } // if isdigit(c)
    } // for
    return value;
} // getArgValue()

void bufferRaster(char c)
{
    if (imageDataOffset == IMAGE_DATA_SIZE)
    { 
        fprintf(stderr, "too many image bytes!\n");
        imageDataOffset = 0;
    } // if imageDataOffset == IMAGE_DATA_SIZE
    imageData[imageDataOffset++] = c;
} // bufferRaster()

// create a PBM file with the raster image from the device.
void createFile(char * imagedata, int width, int height)
{
    int rows;
    int columns;
    char outputFileName[MAXPATHLEN];
    char gifFileName[MAXPATHLEN];
    char sOutputFile[MAXPATHLEN];
    char cmd[2 * MAXPATHLEN];
    char c;
    FILE * file;

    getUniqueFileName(sOutputFile);
    sprintf(outputFileName, "%s.pbm", sOutputFile);
    sprintf(gifFileName,    "%s.gif", sOutputFile);

    if (!runAsDaemon)
        printf("opening output file %s\007\n", sOutputFile);
    file = fopen(outputFileName, "w");
    if (file == NULL)
    {
	fprintf(stderr, "could not open output file %s.\n", sOutputFile);
	return;
    } /* if file == NULL */
    fprintf(file, "P1\n");
    fprintf(file, "%d %d\n", width * 8, height);
    for (rows = 0; rows < height; rows ++)
    {
        for (columns = 0; columns < width; columns++)
        {
            c = imageData[width * rows + columns];
            fprintf(file, "%c ", (c & 0x80) ? '1' : '0');
            fprintf(file, "%c ", (c & 0x40) ? '1' : '0');
            fprintf(file, "%c ", (c & 0x20) ? '1' : '0');
            fprintf(file, "%c ", (c & 0x10) ? '1' : '0');
            fprintf(file, "%c ", (c & 0x08) ? '1' : '0');
            fprintf(file, "%c ", (c & 0x04) ? '1' : '0');
            fprintf(file, "%c ", (c & 0x02) ? '1' : '0');
            fprintf(file, "%c ", (c & 0x01) ? '1' : '0');
        } // for columns
        fprintf(file, "\n");
    } //r rows
    fclose(file);
    sprintf(cmd, "convert %s %s", outputFileName, gifFileName);
    system(cmd);
} // createFile()

void escapeParser(char c)
{
    char buf[8];

    switch (escapeState)
    {
        case 0: // looking for escape char
            if (c == 27)
            { // found escape char
                escapeState = 1;
            } // if c == 27
            else
            {
                if (isprint(c))
                {
                    printf("%c", c);
                } // if isprint(c)
                else
                {
                    char2hex(c, buf);
                    printf("(%s)", buf);
                } // if isprint(c)
            }  // if c == 27
            break;
        case 1:
            if ((c >= 33) && (c <= 47))
            {
                esc2nd = c;
                escapeState = 2; 
                break;
            }
            if ((c >= 48) && (c <= 126))
            { // 2nd character of 2 char escape sequence - ignore these 2 character escape sequences.
                escapeState = 0;
                printf("Discarding command: <esc>%c\n", c);
            }
            break;                
        case 2:
            if ((c >= 96) && (c <= 126)) 
            { // third character in escape sequence...
                esc3rd = c;
		escDigitsCount = 0;
                escapeState = 3;
            } 
            else // not likely a valid escape sequence
                escapeState = 0;
            break;
        case 3:
            if ((c == '+') || (c == '-') || ((c >= '0' && c <= '9')))
            { // got a sign or digit
                escDigits[escDigitsCount++] = c;
                break;
            } 
            if (c >=96 && c <= 126) 
            { // action letter, lower case, still escape sequence.
                escAction = c;
                escDigits[escDigitsCount] = '\0';
                if (escDigits[0])
                    printf("Discarding lowercase command: <esc>%c%c%s%c\n", esc2nd, esc3rd, escDigits, escAction);
                else
                    printf("Discarding lowercase command: <esc>%c%c%c\n", esc2nd, esc3rd, escAction);
                // throw on floor.
                break;
            }
            if ((c >= 64) && (c <= 94))
            { // action letter, upper case, ends escape sequence
		escAction = c;
                escapeState = 0;
                escDigits[escDigitsCount] = '\0';
                
                if (escDigits[0])
                    printf("command: <esc>%c%c%s%c", esc2nd, esc3rd, escDigits, escAction);
                else
                    printf("command: <esc>%c%c%c", esc2nd, esc3rd, escAction);
                switch (esc2nd)
                {
                    case '*': // we care about esc *
                        switch (esc3rd) 
                        {
                            case 'b':  // graphics command!
                                switch (escAction)
                                {
                                    case 'W': // graphics transfer
                                        byteCount = getArgValue(escDigits, escDigitsCount); 
					if (width != byteCount * 8)
                                        { // the width being sent has changed.  this is bad.
                                            printf("..width change image reset..");
                                            width = byteCount * 8;
                                            height = 0;
                                            imageDataOffset = 0;
                                        } // if width != byteCount * 8
                                        height += 1;
                                        printf(" .. GRAPHICS TRANSFER %d BYTES (line %d)", byteCount, height); 
                                        break;
                                    default:
                                        printf(" ...discarded.");
                                        break;
                                } // switch escAction
                                break;
                            case 'r': // graphics start/end command!
                                switch (escAction)
                                {
                                    case 'a':
                                    case 'A':
                                        printf(" .. GRAPHICS MODE START");
                                        graphicsMode = TRUE;
                                        width = 0;
                                        height = 0;
                                        imageDataOffset = 0;
                                        break;
                                    case 'b':
                                    case 'B':
                                    case 'c':
                                    case 'C':
                                        printf(" .. GRAPHICS MODE END");
                                        printf("..width=%d, height=%d\n", width, height);
                                        graphicsMode = FALSE;
                                        //dumpToConsole(imageData, width / 8, height);
                                        createFile(imageData, width / 8, height);
                                        break;
                                    default:
                                        printf(" .. discarded");
                                        break;
                                } // switch escAction; 
                                break;
                            default:
                                printf("... discarded");
                                break;
                        } // switch esc3rd
                        break;
                    default:
                        printf(". . discarded");
                } // switch esc2nd
                printf("\n");
                break;
            } // if c >= 64 ...
    } // switch
} // escapeParser()

void dumpChar(char c)
{
    if (byteCount)
    {
        bufferRaster(c);
        byteCount --;
    }
    else
    {
        escapeParser(c);
    } // if byteCount
} // dumpChar()

void processBytes(char *s, int count)
{
    int i;

    for (i=0; i<count;i++)
    {
        dumpChar(s[i]);
    }
} // processBytes()


int main (int argc, char **argv)
{

    imageData = malloc(IMAGE_DATA_SIZE);
    if (imageData == NULL)
    {
        fprintf(stderr, "not enough room for image data!\n");
        return 1;
    } // if imageData == null;

    char c;

    fd_set readfds;
    int status;
    int serialfd;
    int numBytes;
    struct termios oldtio, newtio;
    char buffer[256];
    int pid;

    strcpy(sInputPort, "/dev/ttyS0");
    strcpy(lprCommand, "lpr -r %s");
    strcpy(appName, argv[0]);

    /* parse command line */
    while ((c = getopt(argc, argv, "t:l:dhv")) != EOF)
    {
	switch(c)
	{
	    case 'd':
		runAsDaemon = TRUE;
		break;

	    case 'l':
		strcpy (lprCommand, optarg);
		break;

	    case 't':
		strcpy (sInputPort, optarg);
		break;

	    case 'v':
		versionInfo();
		exit(0);
			
	    case 'h':
	    default:
		usage();
		exit(1);
	} /* switch */
    } /* while */

    if (runAsDaemon)
    {
	/* fork it */
	if ((pid = fork()) < 0)
	{
	    fprintf(stderr, "unable to fork...");
	    exit(3);
	} /* failed to fork */
	
	if (pid != 0)
	    exit (0); /* kill off original process */
    } /* if runAsDaemon */
    
    /* open the serial device to be non-blocking */
    serialfd = open(sInputPort, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (serialfd < 0)
    {
	fprintf(stderr, "Can't open device %s\n", sInputPort);
	exit(1);
    } /* if serialfd < 0 */

    tcgetattr(serialfd, &oldtio);
    /* set up serial port settings */
    bzero(&newtio, sizeof(newtio));
    newtio.c_cflag = BAUDRATE | CS8 | CREAD;
    newtio.c_iflag = IGNPAR | IGNBRK | ICRNL;
    newtio.c_oflag = 0;
    newtio.c_lflag = 0;
    newtio.c_cc[VTIME]=0;
    newtio.c_cc[VMIN]=1;
    tcflush(serialfd, TCIFLUSH);
    tcsetattr(serialfd, TCSANOW, &newtio);

    for (;;)
    {
	
	FD_SET(serialfd, &readfds);
	status = select(serialfd+1, &readfds, NULL, NULL, NULL);
	if (FD_ISSET(serialfd, &readfds))
	{
	    numBytes = read(serialfd,buffer,255);
	    buffer[numBytes] = 0;
	    processBytes(buffer, numBytes);
	    //checkInputData(buffer);
	} /* if FD_ISSET */
	else
	{
            usleep(100);
	} /* if FD_ISSET */
    } /* for */
    /* restore old port settings */
    tcsetattr(serialfd,TCSANOW,&oldtio);
    close(serialfd);
    return 0;
} /* main() */

