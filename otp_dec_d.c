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
    char cipherText[100000];
    char keyBuffer[100000];
    char decryptedText[100000];
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
            memset(buffer, '\0', sizeof(buffer));
            //Authenticate the client to make sure they are connected to the right daemon
            auth = recv(establishedConnectionFD, buffer, sizeof(buffer), 0); //receive authentication message from the client
            if (auth < 0)
                error("ERROR reading from socket");
            if (strcmp(buffer, "%") == 0)                 //check if the message received is correct
                send(establishedConnectionFD, "%", 1, 0); //send approval message
            else
            { //close the connection if unindentified client is trying to connect to the server
                close(establishedConnectionFD);
                close(listenSocketFD);
                exit(2);
            }

            //receive the ciphertext length from the client
            memset(buffer, '\0', sizeof(buffer));                                 // Clear out the buffer again for reuse
            charsRead = recv(establishedConnectionFD, buffer, sizeof(buffer), 0); // Read data from the socket, leaving \0 at end
            if (charsRead < 0)
                error("ERROR reading from socket");

            //convert the length of the ciphertext received from the server to int
            int cipherTextLength = atoi(buffer);

            //receive the plaintext from the client
            int curBufferPos = 0;
            int remainingChars = cipherTextLength;
            memset(cipherText, '\0', sizeof(cipherText));
            while (curBufferPos < cipherTextLength) // make sure all the information is sent to the client
            {

                memset(temp, '\0', sizeof(temp));                                   // Clear out the buffer again for reuse
                charsRead = recv(establishedConnectionFD, temp, remainingChars, 0); // Read data from the socket, leaving \0 at end
                if (charsRead < 0)
                    error("ERROR reading from socket");
                strcat(cipherText, temp); // make sure that data is not overwritten
                curBufferPos += charsRead;
                remainingChars -= charsRead; //make sure only the remaining information is sent
            }

            // //receive the key from the client
            curBufferPos = 0;
            remainingChars = cipherTextLength;

            memset(keyBuffer, '\0', sizeof(keyBuffer)); // Clear out the buffer again for reuse

            while (curBufferPos < cipherTextLength) // make sure all the information is sent to the client
            {

                memset(temp, '\0', sizeof(temp));                                   // Clear out the buffer again for reuse
                charsRead = recv(establishedConnectionFD, temp, remainingChars, 0); // Read data from the socket, leaving \0 at end
                if (charsRead < 0)
                    error("ERROR reading from socket");
                strcat(keyBuffer, temp); // make sure that data is not overwritten
                curBufferPos += charsRead;
                remainingChars -= charsRead; //make sure only the remaining information is sent
            }

            //decrypt the key
            memset(decryptedText, '\0', sizeof(decryptedText)); //clear out the buffer
            int i;
            for (i = 0; i < cipherTextLength; i++)
            {
                //replace 32 (space) to 91 for modding purposes
                if (cipherText[i] == 32)
                    cipherText[i] = 91;
                if (keyBuffer[i] == 32)
                    keyBuffer[i] = 91;

                //take the difference of the ciphertext and the key
                int decrypted = (cipherText[i] - 65) - (keyBuffer[i] - 65);

                //if the diffrence is negative, add 27 until it is positive
                while (decrypted < 0)
                    decrypted += 27;

                // printf("%d: %d -%d = %s\n", i, cipherText[i], keyBuffer[i], decrypted);

                //convert back to ascii character
                if (decrypted == 26)
                    decrypted = 32;
                else
                    decrypted += 65;

                decryptedText[i] = decrypted; //store the encryted message
            }

            //send the decrypted message back to the client
            curBufferPos = 0;
            remainingChars = cipherTextLength;
            while (curBufferPos < cipherTextLength) // make sure all the information is sent to the client
            {
                charsWritten = send(establishedConnectionFD, decryptedText, remainingChars, 0); // Write to the server
                if (charsWritten < 0)
                    error("ERROR writing to socket");
                curBufferPos += charsWritten;
                remainingChars -= charsWritten; //make sure only the remaining information is sent
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
