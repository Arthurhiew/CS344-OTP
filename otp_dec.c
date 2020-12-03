#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

void error(const char *msg)
{
    perror(msg);
    exit(0);
} // Error function used for reporting issues

int main(int argc, char *argv[])
{

    int socketFD, portNumber, charsWritten, charsRead, auth;
    struct sockaddr_in serverAddress;
    struct hostent *serverHostInfo;
    char buffer[10];
    char *keyBuffer;
    char *textBuffer;
    char authenticate[] = "%";
    char decryptedText[100000];
    char temp[100000];
    size_t textSize = 0;
    size_t keySize = 0;

    if (argc < 4)
    {
        fprintf(stderr, "USAGE: %s plaintext key port\n", argv[0]);
        exit(0);
    } // Check usage & args

    // read the ciphertextfile
    FILE *textFile;

    textFile = fopen(argv[1], "r");
    if (textFile == NULL)
    {
        perror("CLIENT: ERROR, could not open file");
        exit(1);
    }

    int textLength = getline(&textBuffer, &textSize, textFile);
    if (textLength == -1)
        clearerr(textFile);

    fclose(textFile);

    //check if the input file contains any bad character
    int i;
    for (i = 0; i < textLength - 1; i++)
    {
        if (!(textBuffer[i] >= 65 && textBuffer[i] <= 90) && textBuffer[i] != 32)
        {
            fprintf(stderr, "%s ERROR: %s contains bad characters\n", argv[0], argv[1]);
            free(textBuffer);
            exit(1);
        }
    }

    //read key file
    FILE *keyFile;

    keyFile = fopen(argv[2], "r");
    if (keyFile == NULL)
    {
        perror("CLIENT: ERROR, could not open file");
        exit(1);
    }

    int keyLength = getline(&keyBuffer, &keySize, keyFile);
    if (keyLength == -1)
        clearerr(keyFile);
    fclose(keyFile); //close the file

    //check if the keylength is at least as long as the text length
    if (keyLength - 1 < textLength - 1)
    {
        fprintf(stderr, "Error: key \'%s\' is too short\n", argv[2]);
        exit(1);
    }
    // Set up the server address struct
    memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
    portNumber = atoi(argv[3]);                                  // Get the port number, convert to an integer from a string
    serverAddress.sin_family = AF_INET;                          // Create a network-capable socket
    serverAddress.sin_port = htons(portNumber);                  // Store the port number
    serverHostInfo = gethostbyname("localhost");                 // Convert the machine name into a special form of address
    if (serverHostInfo == NULL)
    {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(0);
    }
    memcpy((char *)&serverAddress.sin_addr.s_addr, (char *)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

    // Set up the socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
    if (socketFD < 0)
        error("CLIENT: ERROR opening socket");

    // Connect to server
    if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
        error("CLIENT: ERROR connecting");

    //send authentication message to the server
    auth = send(socketFD, authenticate, strlen(authenticate), 0);
    if (auth < 0)
        error("CLIENT: ERROR writing to socket");

    memset(buffer, '\0', sizeof(buffer));
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); //receive authentication message from the server
    //check if the authentication message received is correct
    if (strcmp(buffer, "%") != 0)
    {
        fprintf(stderr, "CLIENT: ERROR, Attempt to connect to incorrect daemon\n");
        close(socketFD);
        exit(2);
    }

    //send plaintext size to the server
    memset(buffer, '\0', sizeof(buffer));                     // Clear out the buffer again for reuse
    sprintf(buffer, "%d", textLength - 1);                    //convert text Length to int and remove the last character
    charsWritten = send(socketFD, buffer, strlen(buffer), 0); // Write to the server
    if (charsWritten < 0)
        error("CLIENT: ERROR writing to socket");

    //send text to the server
    int curBufferPos = 0;
    int remainingChars = textLength - 1;
    while (curBufferPos < textLength - 1) // make sure all the information is sent to the client
    {
        memset(temp, '\0', sizeof(temp));
        charsWritten = send(socketFD, textBuffer, remainingChars, 0); // Write to the server
        if (charsWritten < 0)
            error("CLIENT: ERROR writing to socket");
        curBufferPos += charsWritten;
        remainingChars -= charsWritten; //make sure only the reamaining information is sent
    }

    //send key to the server
    curBufferPos = 0;
    remainingChars = textLength - 1;
    while (curBufferPos < textLength - 1) // make sure all the information is sent to the client
    {
        charsWritten = send(socketFD, keyBuffer, remainingChars, 0); // Write to the server
        if (charsWritten < 0)
            error("CLIENT: ERROR writing to socket");
        curBufferPos += charsWritten;
        remainingChars -= charsWritten; //make sure only the reamaining information is sent
    }

    // receive encrypted text from the server
    memset(decryptedText, '\0', sizeof(decryptedText));

    curBufferPos = 0;
    remainingChars = textLength - 1;
    while (curBufferPos < textLength - 1) // make sure all the information is sent to the client
    {
        memset(temp, '\0', sizeof(temp));                    // Clear out the buffer again for reuse
        charsRead = recv(socketFD, temp, remainingChars, 0); // Read data from the socket, leaving \0 at end
        if (charsRead < 0)
            error("CLIENT: ERROR reading from socket");
        strcat(decryptedText, temp); // make sure that data is not overwritten
        curBufferPos += charsRead;
        remainingChars -= charsRead; //make sure only the reamaining information is sent
    }

    //output the decrypted message to stdout
    printf("%s\n", decryptedText);

    close(socketFD); // Close the socket
    return 0;
}
