//This is a program that runs in the background as a daemon. Upon execution, it output an error if it connot be run due
//to network error. It perform the encoding for a plaintext file received from the client. This program will listen on a particular
//port/socket , assigned when it is first ran. When the

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

void error(const char *msg)
{
    perror(msg);
    exit(1);
} // Error function used for reporting issues

int main(int argc, char *argv[])
{
    int listenSocketFD, establishedConnectionFD, pidIndex, portNumber, charsRead, auth, charsWritten;
    socklen_t sizeOfClientInfo;
    char buffer[10];
    struct sockaddr_in serverAddress, clientAddress;
    char plainText[100000];
    char keyBuffer[100000];
    char cipherText[100000];
    char temp[100000];
    int pidArray[10];
    memset(pidArray, '\0', sizeof(pidArray));
    if (argc < 2)
    {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    } // Check usage & args

    // Set up the address struct for this process (the server)
    memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
    portNumber = atoi(argv[1]);                                  // Get th e port number, convert to an integer from a string
    serverAddress.sin_family = AF_INET;                          // Create a network-capable socket
    serverAddress.sin_port = htons(portNumber);                  // Store the port number
    serverAddress.sin_addr.s_addr = INADDR_ANY;                  // Any address is allowed for connection to this process

    // Set up the socket
    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
    if (listenSocketFD < 0)
        error("ERROR opening socket");

    // Enable the socket to begin listening
    if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
        error("ERROR on binding");
    listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

    while (1)
    {

        // Accept a connection, blocking if one is not available until one connects
        sizeOfClientInfo = sizeof(clientAddress);                                                               // Get the size of the address for the client that will connect
        establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
        if (establishedConnectionFD < 0)
            error("ERROR on accept");
        int result;
        pid_t spawnPid = -5;
        int childExitStatus = -5;

        spawnPid = fork(); //process id of the child

        //fork a new process once connection is accepted
        switch (spawnPid)
        {
        case -1: //fork failed and no child is created

            perror("Fork failed!\n");
            exit(1);
            break;

        case 0: // child is created

            //Authenticate the client to make sure they are connected to the right daemon
            memset(buffer, '\0', sizeof(buffer));
            auth = recv(establishedConnectionFD, buffer, sizeof(buffer), 0); //receive authentication message from the client
            if (auth < 0)
                error("ERROR reading from socket");
            if (strcmp(buffer, "$") == 0) //check if the message received is correct
                send(establishedConnectionFD, "$", 1, 0);
            else //close the connection if unindentified client is trying to connect to the server
            {
                close(establishedConnectionFD);
                close(listenSocketFD);
                exit(2);
            }

            //receive the plaintext length from the client
            memset(buffer, '\0', sizeof(buffer));                                 // Clear out the buffer again for reuse
            charsRead = recv(establishedConnectionFD, buffer, sizeof(buffer), 0); // Read data from the socket, leaving \0 at end
            if (charsRead < 0)
                error("ERROR reading from socket");

            //convert the length of the plaintext received from the server to int
            int plainTextLength = atoi(buffer);

            //receive the plaintext from the client
            int curBufferPos = 0;
            int remainingChars = plainTextLength;
            memset(plainText, '\0', sizeof(plainText)); // Clear out the buffer
            while (curBufferPos < plainTextLength)      // make sure all the information is sent to the client
            {
                memset(temp, '\0', sizeof(temp));                                   // Clear out the buffer again for reuse
                charsRead = recv(establishedConnectionFD, temp, remainingChars, 0); // Read data from the socket, leaving \0 at end
                if (charsRead < 0)
                    error("ERROR reading from socket");
                strcat(plainText, temp); // make sure that data is not overwritten
                curBufferPos += charsRead;
                remainingChars -= charsRead; //make sure only the reamaining information is sent
            }

            // //receive the key from the client
            curBufferPos = 0;
            remainingChars = plainTextLength;
            memset(keyBuffer, '\0', sizeof(keyBuffer)); // Clear out the buffer
            while (curBufferPos < plainTextLength)      // make sure all the information is sent to the client
            {
                memset(temp, '\0', sizeof(temp));                                   // Clear out the buffer again for reuse
                charsRead = recv(establishedConnectionFD, temp, remainingChars, 0); // Read data from the socket, leaving \0 at end
                if (charsRead < 0)
                    error("ERROR reading from socket");
                strcat(keyBuffer, temp); // make sure that data is not overwritten
                curBufferPos += charsRead;
                remainingChars -= charsRead; //make sure only the remaining information is sent
            }

            //encrypt the key
            memset(cipherText, '\0', sizeof(cipherText));
            int i;
            for (i = 0; i < plainTextLength; i++)
            {
                //replace 32 (space) to 91 for modding purposes
                if (plainText[i] == 32)
                    plainText[i] = 91;
                if (keyBuffer[i] == 32)
                    keyBuffer[i] = 91;

                //take the sum of the plaintext and the key and mod it by 27
                int encrypted = ((plainText[i] - 65) + (keyBuffer[i] - 65)) % 27;

                //convert back to ascii character
                if (encrypted == 26)
                    encrypted += 6;
                else
                    encrypted += 65;

                cipherText[i] = encrypted; //store the encryted message
            }

            //send the encryted message back to the client
            curBufferPos = 0;
            remainingChars = plainTextLength;
            while (curBufferPos < plainTextLength) // make sure all the information is sent to the client
            {
                charsWritten = send(establishedConnectionFD, cipherText, remainingChars, 0); // Write to the server
                if (charsWritten < 0)
                    error("ERROR writing to socket");
                curBufferPos += charsWritten;
                remainingChars -= charsWritten; //make sure only the reamaining information is sent
            }

            break;

        default: // in the parent
            //add the child pids to the array
            pidArray[pidIndex] = spawnPid;
            pidIndex++;
            //does not wait for background process to complete
            waitpid(spawnPid, &childExitStatus, WNOHANG);
        }
        close(establishedConnectionFD); // Close the existing socket which is connected to the client
    }
    int i;
    //kill all the processes
    for (i = 0; i < pidIndex; ++i)
    {
        kill(pidArray[i], SIGTERM);
        int childExitMethod = -5;
        pid_t pidStatus = waitpid(pidArray[i], &childExitMethod, 0);
    }
    close(listenSocketFD); // Close the listening socket
    return 0;
}
