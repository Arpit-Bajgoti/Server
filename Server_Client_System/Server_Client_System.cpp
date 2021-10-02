// myserver.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib,"ws2_32.lib")
#include <WinSock2.h>
#include <string>
#include <iostream>
#include<WS2tcpip.h>
#include<fstream>
using namespace std;
int filesize;

enum Packet
{
	P_ChatMessage,
	P_FileTransferRequest,
	P_FileTransferByteBuffer,
	P_FileTransfer_EndOfFile,
	P_one,
	P_two,
	P_three
};

struct filename {
	string filename;
	int filesize;
	static const int buffersize = 8192;
	int bytesWritten;
	int bytescounter;
	int remaining_bytes;
	ifstream  file;
	ofstream outfile;
	char buffer[buffersize];

}File;

struct fileoperations {
	int filesize = 0;
	int buffercount = 0;
	static const int buffersize = 2048;
	int remaining_bytes = 0;
	char buffer[buffersize];
} file;

SOCKET Connections[100];
int TotalConnections = 0;


bool recvall(int ID, char* data, int totalbytes)
{
	int bytesreceived = 0; //Holds the total bytes received
	while (bytesreceived < totalbytes) //While we still have more bytes to recv
	{
		int RetnCheck = recv(Connections[ID], data, totalbytes - bytesreceived, NULL); //Try to recv remaining bytes
		if (RetnCheck == SOCKET_ERROR) //If there is a socket error while trying to recv bytes
			return false; //Return false - failed to recvall
		bytesreceived += RetnCheck; //Add to total bytes received
	}
	return true; //Success!
}

bool sendall(int ID, char* data, int totalbytes)
{
	int bytessent = 0; //Holds the total bytes sent
	while (bytessent < totalbytes) //While we still have more bytes to send
	{
		int RetnCheck = send(Connections[ID], data + bytessent, totalbytes - bytessent, NULL); //Try to send remaining bytes
		if (RetnCheck == SOCKET_ERROR) //If there is a socket error while trying to send bytes
			return false; //Return false - failed to sendall
		bytessent += RetnCheck; //Add to total bytes sent
	}
	return true; //Success!
}

bool Sendint32_t(int ID, int32_t _int32_t)
{
	_int32_t = htonl(_int32_t); //Convert long from Host Byte Order to Network Byte Order
	if (!sendall(ID, (char*)&_int32_t, sizeof(int32_t))) //Try to send long (4 byte int)... If int fails to send
		return false; //Return false: int not successfully sent
	return true; //Return true: int successfully sent
}

bool Getint32_t(int ID, int32_t& _int32_t)
{
	if (!recvall(ID, (char*)&_int32_t, sizeof(int32_t))) //Try to receive long (4 byte int)... If int fails to be recv'd
		return false; //Return false: Int not successfully received
	_int32_t = ntohl(_int32_t); //Convert long from Network Byte Order to Host Byte Order
	return true;//Return true if we were successful in retrieving the int
}

bool SendPacketType(int ID, Packet _packettype)
{
	if (!Sendint32_t(ID, _packettype)) //Try to send packet type... If packet type fails to send
		return false; //Return false: packet type not successfully sent
	return true; //Return true: packet type successfully sent
}

bool GetPacketType(int ID, Packet& _packettype)
{
	int packettype;
	if (!Getint32_t(ID, packettype)) //Try to receive packet type... If packet type fails to be recv'd
		return false; //Return false: packet type not successfully received
	_packettype = (Packet)packettype;
	return true;//Return true if we were successful in retrieving the packet type
}

bool SendString(int ID, std::string& _string)
{
	if (!SendPacketType(ID, P_ChatMessage)) //Send packet type: Chat Message, If sending packet type fails...
		return false; //Return false: Failed to send string
	int32_t bufferlength = _string.size(); //Find string buffer length
	if (!Sendint32_t(ID, bufferlength)) //Send length of string buffer, If sending buffer length fails...
		return false; //Return false: Failed to send string buffer length
	if (!sendall(ID, (char*)_string.c_str(), bufferlength)) //Try to send string buffer... If buffer fails to send,
		return false; //Return false: Failed to send string buffer
	return true; //Return true: string successfully sent
}

bool GetString(int ID, std::string& _string)
{
	int32_t bufferlength; //Holds length of the message
	if (!Getint32_t(ID, bufferlength)) //Get length of buffer and store it in variable: bufferlength
		return false; //If get int fails, return false
	char* buffer = new char[bufferlength + 1]; //Allocate buffer
	buffer[bufferlength] = '\0'; //Set last character of buffer to be a null terminator so we aren't printing memory that we shouldn't be looking at
	if (!recvall(ID, buffer, bufferlength)) //receive message and store the message in buffer array. If buffer fails to be received...
	{
		delete[] buffer; //delete buffer to prevent memory leak
		return false; //return false: Fails to receive string buffer
	}
	_string = buffer; //set string to received buffer message
	delete[] buffer; //Deallocate buffer memory (cleanup to prevent memory leak)
	return true;//Return true if we were successful in retrieving the string
}

bool HandleSendFile(int ID)
{
	if (File.bytescounter >= File.filesize) //If end of file reached then return true and skip sending any bytes
		return true;
	if (!SendPacketType(ID, P_one)) //Send packet type for file transfer byte buffer
		return false;

	File.remaining_bytes = File.filesize - File.bytescounter; //calculate remaining bytes
	if (File.remaining_bytes > File.buffersize) //if remaining bytes > max byte buffer
	{
		File.file.read(File.buffer, File.buffersize); //read in max buffer size bytes
		if (!Sendint32_t(ID, File.buffersize)) //send int of buffer size
			return false;
		if (!sendall(ID, File.buffer, File.buffersize)) //send bytes for buffer
			return false;
		File.bytescounter += File.buffersize; //increment fileoffset by # of bytes written
	}
	else
	{
		File.file.read(File.buffer, File.remaining_bytes); //read in remaining bytes
		if (!Sendint32_t(ID, File.remaining_bytes)) //send int of buffer size
			return false;
		if (!sendall(ID, File.buffer, File.remaining_bytes)) //send bytes for buffer
			return false;
		File.bytescounter += File.remaining_bytes; //increment fileoffset by # of bytes written
	}

	if (File.bytescounter == File.filesize) //If we are at end of file
	{
		if (!SendPacketType(ID, P_FileTransfer_EndOfFile)) //Send end of file packet
			return false;
		//Print out data on server details about file that was sent
		std::cout << std::endl << "File sent: " << File.filename << std::endl;
		std::cout << "File size(bytes): " << File.filesize << std::endl << std::endl;
		File.file.close();
	}
	return true;
}


bool ProcessPacket(int ID, Packet _packettype)
{
	string filename;
	switch (_packettype)
	{
	case P_ChatMessage: //Packet Type: chat message
	{
		std::string Message; //string to store our message we received
		if (!GetString(ID, Message)) //Get the chat message and store it in variable: Message
			return false; //If we do not properly get the chat message, return false

		for (int i = 0; i < TotalConnections; i++) //Next we need to send the message out to each user
		{
			if (i == ID) //If connection is the user who sent the message...
				continue;//Skip to the next user since there is no purpose in sending the message back to the user who sent it.

			if (!SendString(i, Message)) //Send message to connection at index i, if message fails to be sent...
			{
				std::cout << "Failed to send message from client ID: " << ID << " to client ID: " << i << std::endl;
			}
		}
		std::cout << "Processed chat message packet from user ID: " << ID << std::endl;
		break;
	}

	case P_FileTransferRequest:
	{  string filename;
	if (!GetString(ID, filename))
		return false;
	File.outfile.open(filename, std::ios::binary); //open file to write file to
	File.filename = filename; //save file name
	File.bytesWritten = 0; //reset byteswritten to 0 since we are working with a new file
	if (!File.outfile.is_open()) //if file failed to open...
	{
		std::cout << "ERROR: Function(Client::RequestFile) - Unable to open file: " << filename << " for writing.\n";
		return false;
	}
	std::cout << "Requesting file from client: " << File.filename << std::endl;
	if (!SendPacketType(ID, P_FileTransferByteBuffer)) //send file transfer request packet
		return false;

	return true;
	break;
	}

	case P_FileTransferByteBuffer:
	{
		int32_t buffersize; //buffer to hold size of buffer to write to file
		if (!Getint32_t(ID, buffersize)) //get size of buffer as integer
			return false;
		if (!recvall(ID, File.buffer, buffersize)) //get buffer and store it in file.buffer
		{
			return false;
		}
		File.outfile.write(File.buffer, buffersize); //write buffer from file.buffer to our outfilestream
		File.bytesWritten += buffersize; //increment byteswritten

		if (!SendPacketType(ID, P_FileTransferByteBuffer)) //send packet type to request next byte buffer (if one exists)
			return false;
		break;
	}

	case P_one:
	{
		std::string FileName; //string to store file name
		if (!GetString(ID, FileName)) //If issue getting file name
			return false; //Failure to process packet

		File.file.open(FileName, std::ios::binary | std::ios::ate); //Open file to read in binary | ate mode. We use ate so we can use tellg to get file size. We use binary because we need to read bytes as raw data
		if (!File.file.is_open()) //If file is not open? (Error opening file?)
		{
			std::cout << "Client: " << ID << " requested file: " << FileName << ", but that file does not exist." << std::endl;
			std::string ErrMsg = "Requested file: " + FileName + " does not exist or was not found.";
			if (!SendString(ID, ErrMsg)) //Send error msg string to client
				return false;
			return true;
		}

		File.filename = FileName; //set file name just so we can print it out after done transferring
		File.filesize = File.file.tellg(); //Get file size
		File.file.seekg(0); //Set cursor position in file back to offset 0 for when we read file
		File.bytescounter = 0; //Update file offset for knowing when we hit end of file

		if (!HandleSendFile(ID)) //Attempt to send byte buffer from file. If failure...
			return false;
		break;
	}
	case P_two:
	{
		if (!HandleSendFile(ID)) //Attempt to send byte buffer from file. If failure...
			return false;
		break;
	}

	case P_FileTransfer_EndOfFile:
	{
		std::cout << "File transfer completed. File received." << std::endl;
		std::cout << "File Name: " << File.filename << std::endl;
		std::cout << "File Size(bytes): " << File.bytesWritten << std::endl;
		File.bytesWritten = 0;
		File.outfile.close(); //close file after we are done writing file
		break;
	}




	default: //If packet type is not accounted for
	{
		std::cout << "Unrecognised packet: " << _packettype << std::endl; //Display that packet was not found
		break;
	}
	}
	return true;
}
void ReqChatFile()
{
	while (true)

	{
		string ReqFile;
		int _ID;
		system("pause");
		cout << "ENTER CLIENT ID - ";
		cin >> _ID;
		if (!SendPacketType(_ID, P_three))
			cout << "FILE REQUEST FAILED" << endl;
	}
}
void ClientHandlerThread(int ID) //ID = the index in the SOCKET Connections array
{
	Packet PacketType;
	while (true)
	{
		if (!GetPacketType(ID, PacketType)) //Get packet type
			break; //If there is an issue getting the packet type, exit this loop
		if (!ProcessPacket(ID, PacketType)) //Process packet (packet type)
			break; //If there is an issue processing the packet, exit this loop
	}
	std::cout << "Lost connection to client ID: " << ID << std::endl;
	closesocket(Connections[ID]);
}

int main()
{

	//Winsock Startup
	WSAData wsaData;
	WORD DllVersion = MAKEWORD(2, 2);
	if (WSAStartup(DllVersion, &wsaData) != 0) //If WSAStartup returns anything other than 0, then that means an error has occured in the WinSock Startup.
	{
		MessageBoxA(NULL, "WinSock startup failed", "Error", MB_OK | MB_ICONERROR);
		return 0;
	}

	sockaddr_in addr; //Address that we will bind our listening socket to
	int addrlen = sizeof(addr); //length of the address (required for accept call)
	addr.sin_addr.S_un.S_addr = INADDR_ANY; //Broadcast publically
	addr.sin_port = htons(1111); //Port
	addr.sin_family = AF_INET; //IPv4 Socket

	SOCKET sListen = socket(AF_INET, SOCK_STREAM, NULL); //Create socket to listen for new connections
	bind(sListen, (SOCKADDR*)&addr, sizeof(addr)); //Bind the address to the socket
	listen(sListen, SOMAXCONN); //Places sListen socket in a state in which it is listening for an incoming connection. Note:SOMAXCONN = Socket Oustanding Max Connections

	SOCKET newConnection; //Socket to hold the client's connection
	int ConnectionCounter = 0; //# of client connections
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ReqChatFile, NULL, NULL, NULL);
	for (int i = 0; i < 100; i++)
	{
		newConnection = accept(sListen, (SOCKADDR*)&addr, &addrlen); //Accept a new connection
		if (newConnection == 0) //If accepting the client connection failed
		{
			std::cout << "Failed to accept the client's connection." << std::endl;
		}
		else //If client connection properly accepted
		{
			std::cout << "Client Connected!" << std::endl;
			Connections[i] = newConnection; //Set socket in array to be the newest connection before creating the thread to handle this client's socket.
			TotalConnections += 1; //Incremenent total # of clients that have connected

			CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ClientHandlerThread, (LPVOID)(i), NULL, NULL); //Create Thread to handle this client. The index in the socket array for this thread is the value (i).
			//Create Thread to handle this client. The index in the socket array for this thread is the value (i).



		}
	}
	system("pause");
	return 0;
}