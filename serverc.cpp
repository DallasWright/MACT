#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <algorithm>
#include <ctime>
#include <strsafe.h>
#include <chrono>
#include <future>
#include <c:\sqlite\sqlite3.h>
/*
To create the lib file for linking I had to execute:
lib /def:sqlite3.def /out:sqlite3.lib
*/
#pragma comment (lib, "Ws2_32.lib")
#pragma comment(lib, "c:\\sqlite\\sqlite3.lib")

static BOOL MACTSTART  = FALSE;
static BOOL MACTFINISH = FALSE;
static BOOL MACTDEBUG  = FALSE;
static int MACTCallSequence = 0;
static HANDLE SR_HANDLE;
static BOOL   SR_BOOL;
static LPVOID SR_LPVOID;

static std::string MACTdir;
static std::string MACTdbname;
std::string MACTAPISkip[6];
std::string MACTbp[100];
int iMACTbp = 0;
    
//std::string* ParsedTokens = new std::string[6];

SOCKET Socket; 

DWORD WINAPI MACTMemThread( LPVOID lpParam );

typedef struct Mem {
    LPVOID            Mem_address;
    size_t            Mem_size;
    int               Mem_interval;
    std::future<void> Mem_futureObj;
} MEMDATA, *PMEMDATA;

//
// Setup threads.
//
PMEMDATA pDataArray[255];
DWORD    dwThreadIdArray[255];
HANDLE   hThreadArray[255];
int      THREADCOUNT = 0;
 
// Create MAX_THREADS worker threads.
std::promise<void> exitSignal; 

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}
/*
c:\research\poc\slept>sqlite3 "C:\MACT\Mon Jun 18 102020 2018\mact.db"
SQLite version 3.24.0 2018-06-04 19:24:41
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .mode csv
sqlite> .output data.csv
sqlite> select * from mact;
sqlite> .quit
*/
void MACTCreateDatabase()
{
    static sqlite3 *MACTdb;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    MACTdbname = MACTdir + "\\MACT.db";

    rc = sqlite3_open(MACTdbname.c_str(), &MACTdb);

    if(rc) {
        printf("Can't open database: %s\n", sqlite3_errmsg(MACTdb));
        exit(0);
    } else {
        printf("Opened database successfully\n");
    }

    /* Create SQL statement */
    sql = "CREATE TABLE MACT("  \
          "CALLSEQ INT  PRIMARY KEY NOT NULL," \
          "CALLRAW TEXT NOT NULL," \
          "APINAME TEXT NOT NULL," \
          "APIP01 TEXT NOT NULL," \
          "APIP02 TEXT NOT NULL," \
          "APIP03 TEXT NOT NULL," \
          "APIP04 TEXT NOT NULL," \
          "APIP05 TEXT NOT NULL," \
          "APIP06 TEXT NOT NULL," \
          "APIP07 TEXT NOT NULL," \
          "APIP08 TEXT NOT NULL," \
          "APIP09 TEXT NOT NULL," \
          "APIP10 TEXT NOT NULL," \
          "APIP11 TEXT NOT NULL," \
          "APIP12 TEXT NOT NULL," \
          "APIRET TEXT NOT NULL," \
          "APIOV TEXT NOT NULL," \
          "APIOVRET TEXT NOT NULL);";

    /* Execute SQL statement */
    rc = sqlite3_exec(MACTdb, sql, callback, 0, &zErrMsg);
       
    if(rc != SQLITE_OK){
        printf("SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        exit(0);
    } else {
        printf("Table created successfully\n");
    }

    sqlite3_close(MACTdb);
}

void MACTInsertDatabase(char* buffer)
{
    static sqlite3 *MACTdb;
    char *zErrMsg = 0;
    int rc;
    char *sql;

    std::string sMACTCallSequence = std::to_string(MACTCallSequence);
    std::string sbuffer;

    switch(buffer[0]) {
        case '*' :
            sbuffer = buffer;
            sbuffer = sbuffer.substr(1,(strlen(buffer)-1));
            ++MACTCallSequence;
            break;
        case '-' :
            return;
        case '+' :
            return;
        case '>' :
            return;
        case ':' :
            return;
        default :
            printf("Error!!! : %s\n", buffer);
            sbuffer = buffer;   
            ++MACTCallSequence;
            break;
    }

    /* Open database */

    rc = sqlite3_open(MACTdbname.c_str(), &MACTdb);
       
    if(rc) {
        printf("Can't open database: %s\n", sqlite3_errmsg(MACTdb));
        exit(0);
    } 

    std::string sSource = sbuffer;

    std::replace(sSource.begin(), sSource.end(), '(', ',');
    std::replace(sSource.begin(), sSource.end(), ')', ',');


    size_t pos = 0;
    std::string token;
    std::string sTokens[16];
    int iToken = 0;
    while((pos = sSource.find(',')) != std::string::npos) {
        token = sSource.substr(0, pos);
        sTokens[iToken] = token;
        ++iToken;
        sSource.erase(0, pos + 1);
    }

    for(int i = 15; i > 4; --i) {
        if(sTokens[i] != "") {
            sTokens[15] = sTokens[i];
            sTokens[14] = sTokens[i-1];
            sTokens[13] = sTokens[i-2];
            if(i < 13) 
                sTokens[i] = "";
            if((i-1) < 13)
                sTokens[i-1] = "";
            if((i-2) < 13)
                sTokens[i-2] = "";
            break;
        }
    }


    /* Create SQL statement */

      std::string ssql = "INSERT INTO MACT (CALLSEQ, CALLRAW, APINAME, APIP01, APIP02, "   \
                                           "APIP03, APIP04, APIP05, APIP06, APIP07, "     \
                                           "APIP08, APIP09, APIP10, APIP11, APIP12, "     \
                                           "APIRET, APIOV, APIOVRET) "                   \
                       "VALUES (" + sMACTCallSequence + ", '" + sbuffer.c_str() + "', '" +  \
                                sTokens[0].c_str()  + "', '"  + sTokens[1].c_str() + "', '" +  \
                                sTokens[2].c_str()  + "', '"  + sTokens[3].c_str() + "', '" +  \
                                sTokens[4].c_str()  + "', '"  + sTokens[5].c_str() + "', '" +  \
                                sTokens[6].c_str()  + "', '"  + sTokens[7].c_str() + "', '"+  \
                                sTokens[8].c_str()  + "', '"  + sTokens[9].c_str() + "', '" + \
                                sTokens[10].c_str() + "', '"  + sTokens[11].c_str() + "', '" + \
                                sTokens[12].c_str() + "', '"  + sTokens[13].c_str() + "', '" + \
                                sTokens[14].c_str() + "', '"  + sTokens[15].c_str() + "');";

    /* Execute SQL statement */
    rc = sqlite3_exec(MACTdb, ssql.c_str(), callback, 0, &zErrMsg);
   
    if(rc != SQLITE_OK){
        printf("SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        exit(0);
    } 

    sqlite3_close(MACTdb);
}

BOOL ishex(std::string HexString)
{
    if(HexString.length() == 0)
        return FALSE;

    if((HexString[0] == '0') && (HexString[1] == 'X'))
        HexString = HexString.substr(2, HexString.length());

    if(HexString.length() > 8)
        return FALSE;

    for(size_t i=0; i < HexString.length(); i++) 
        if(!isxdigit(static_cast<unsigned char>(HexString[i])))
            return FALSE;
  
    return TRUE;
}

void MACTWriteLog(char* buffer)
{
    FILE * pFile;
    std::string sFilename = MACTdir + "\\serverlog.txt";

    pFile = fopen(sFilename.c_str(), "a");

    fwrite(buffer, sizeof(char), strlen(buffer), pFile);

    fclose(pFile);
}

void MACTSendSocket(std::string* sParsedTokens)
{
    //    for(;;) {
        fd_set WriteFDs;
        FD_ZERO(&WriteFDs);
        FD_SET(Socket, &WriteFDs);
        char buffer[80];
        std::string strBuffer;

        if(select(0, NULL, &WriteFDs, NULL, 0) > 0) {
            if (FD_ISSET(Socket, &WriteFDs)) {
//                std::cout<<buffer;
//                if(send(Socket, buffer, 80, 0) == SOCKET_ERROR)
                memset(buffer, 0, 80);
                buffer[79] = '\0';
//                sParsedTokens[5] = "\0";
                strBuffer = sParsedTokens[0] + sParsedTokens[1] + sParsedTokens[2] + sParsedTokens[3];  
                strncpy(buffer, strBuffer.c_str(), 80);             
//                strncpy(buffer, strBuffer.c_str(), 3);
//                buffer[3] = '\0';
                buffer[79] = '\0';
//                printf("sParsedTokens = %s\n", sParsedTokens[0].c_str());
//                if(send(Socket, sParsedTokens->c_str(), 6, 0) == SOCKET_ERROR)
                if(send(Socket, buffer, 80, 0) == SOCKET_ERROR)
                    std::cout<<"Socket error on write.\n";
            }
            else {
                printf("Error Write FD_ISSET\n");
            }
        } 
        else {
            printf("Error on select write.\n");
        }
}

void DCCommand()
{
    std::cout << "\n\nValid Commands:\n\n";
    std::cout << "B A                                 Breakpoint add.\n";
    std::cout << "B C                                 Breakpoint clear.\n";
    std::cout << "B D                                 Breakpoint delete.\n";
    std::cout << "B L                                 Breakpoint list.\n";
    std::cout << "C                                   Continue executing application.\n";
    std::cout << "C E                                 Continue to end of API.\n";
    std::cout << "D C                                 Display valid commands.\n";
    std::cout << "D S                                 Display memory construct structure.\n";
    std::cout << "D M <Address> <Length>              Display memory at address.\n";
    std::cout << "M A <Address> <Length>              Get and write memory from location.\n";
    std::cout << "M S <Address> <Length> <FileName>   Initiate the substitution of the an artifact from the specified File Name to the Address and of the Length specified.\n";
    std::cout << "S P <Parameters>                    Substitute parameters for function call.\n";
    std::cout << "S R <Return Value>                  Substitute return values from function call.\n";
    std::cout << "\n\n";
}


BOOL ExecuteMACTCommand(char *sType, std::string* ParsedTokens)
{
/*
    for(int i=0; i<=4; i++)
      printf("You have entered %s\n", ParsedTokens[i].c_str());
*/
//    double CommandAddress;
//    double CommandLength;
    char sSwitch[2];
    strncpy(sSwitch, ParsedTokens[0].c_str(), 1);

    switch(sSwitch[0]) {
        case 'B' :
            if((ParsedTokens[1] == "A") && (ParsedTokens[2] != "") && ((ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == "")) {
                std::cout << "Breakpoint Add\n";
            }
            else if((ParsedTokens[1] == "D") && (ParsedTokens[2] != "") && ((ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == "")) {
                            std::cout << "Breakpoint Delete\n";
            }           
            else if((ParsedTokens[1] == "C") && ((ParsedTokens[2] + ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == "")) {
                std::cout << "Breakpoint Clear\n";
            }

            else if((ParsedTokens[1] == "L") && ((ParsedTokens[2] + ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == "")) {
                std::cout << "Breakpoint List\n";
            }
            else {
                std::cout << "Invalid Command B.\n";
                return FALSE;
            }
            break;
        case 'C' :
            if((ParsedTokens[1] + ParsedTokens[2] + ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == "") {
                if(MACTDEBUG)
                    std::cout << "Continue executing application.\n";
            }
            else if((ParsedTokens[1] == "E") && ((ParsedTokens[2] + ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == "")) {
                MACTFINISH = TRUE;
                std::cout << "Continue to end..\n";
            }
            else {
                std::cout << "Invalid Command C.\n";
                return FALSE;
            }
            break;
        case 'D' :
            if((ParsedTokens[1] == "B") && ((ParsedTokens[2] + ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == "")) {
                std::cout << "Display Breakpoints.\n";
            }
            else if((ParsedTokens[1] == "C") && ((ParsedTokens[2] + ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == ""))
                DCCommand();
            else if((ParsedTokens[1] == "M") && (ishex(ParsedTokens[2]) && ishex(ParsedTokens[3])) && ((ParsedTokens[4] + ParsedTokens[5]) == "")) {
                if(MACTDEBUG)
                    std::cout << "Display memory at address.\n";

                std::string sString = ParsedTokens[2];
                if((sString[0] == '0') && (sString[1] == 'X'))
                    sString = sString.substr(2, sString.length());
                sString.insert (0, 8 - sString.length(), '0');
                ParsedTokens[2] = sString;

                sString = ParsedTokens[3];
                if((sString[0] == '0') && (sString[1] == 'X'))
                    sString = sString.substr(2, sString.length());
                sString.insert (0, 8 - sString.length(), '0');
                ParsedTokens[3] = sString;
            }
            else if((ParsedTokens[1] == "S") && ((ParsedTokens[2] + ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == "")) {
                if(MACTDEBUG)
                    std::cout << "Display memory construct structure.\n";
            }
            else {
                std::cout << "Invalid Command D.\n";
                return FALSE;
            }
            break;
        case 'M' :
            if((ParsedTokens[1] == "A") && (ishex(ParsedTokens[2]) && ishex(ParsedTokens[3])) && ((ParsedTokens[4] + ParsedTokens[5]) == "")) {
                std::cout << "Initiate the serialization of an artifact using the address and length specified.\n";

                std::string sString = ParsedTokens[2];
                if((sString[0] == '0') && (sString[1] == 'X'))
                    sString = sString.substr(2, sString.length());
                sString.insert (0, 8 - sString.length(), '0');
                ParsedTokens[2] = sString;

                sString = ParsedTokens[3];
                if((sString[0] == '0') && (sString[1] == 'X'))
                    sString = sString.substr(2, sString.length());
                sString.insert (0, 8 - sString.length(), '0');
                ParsedTokens[3] = sString;
            }
            else {
                std::cout << "Invalid Command M.\n";
                return FALSE;
            }
            break;
        case 'S' :
            if((ParsedTokens[1] == "R") && (ishex(ParsedTokens[2]) && (ParsedTokens[3] + ParsedTokens[4] + ParsedTokens[5]) == "")) {
                if(sType == "HANDLE") {
                    UINT cValue;
                    sscanf(ParsedTokens[2].c_str(), "%x", &cValue);
                    SR_HANDLE = (HANDLE)cValue;
                    printf("=======>%p\n", SR_HANDLE);
                }
                else if(sType == "BOOL") {
                    BOOL cValue;
                    sscanf(ParsedTokens[2].c_str(), "%d", &cValue);
                    SR_BOOL = (BOOL)cValue;
                    printf("=======>%d\n", SR_BOOL);
                }
            }  
            else {
                std::cout << "Invalid Command S.\n";
                return FALSE;
            }
            break;
        case 'Q' :
            std::cout << "Quitting.\n";
            exit(0);
            break;
        default :
            std::cout << "Invalid Command X.\n";
            return FALSE;
    }


    return TRUE;

}

std::string* MACTGetCommand()
{
    if(MACTDEBUG)
        printf("serverb: In MACTGetCommand\n");

    std::string RawTokens;
    std::string* ParsedTokens = new std::string[6];
    int CurrentToken;

//    OutputDebugStringA("GetMACTCommand");

//    std::cout << "MACT>> ";
    printf("MACT>> ");

    getline(std::cin, RawTokens);
    std::transform(RawTokens.begin(), RawTokens.end(), RawTokens.begin(), toupper);
    RawTokens += " ";

    CurrentToken = 0;
    size_t pos = 0;
    std::string token;
    while ((pos = RawTokens.find(" ")) != std::string::npos) {
        token = RawTokens.substr(0, pos);
        ParsedTokens[CurrentToken] = token + "\0";
//        printf(" p = %s\n", ParsedTokens[CurrentToken].c_str());
        if(CurrentToken < 5) 
            ++CurrentToken; 
        RawTokens.erase(0, pos + 1);
    }

    return ParsedTokens;
}

int MACTMain(char* sType)
{
//    return 0;
    if(MACTDEBUG)
        printf("serverb: In MACTMAIN\n");

    if(MACTFINISH){
        printf("serverb: In MACTMAIN MACTFINISH\n");
        return 1;
    }

    if(MACTDEBUG)
        printf("serverb: In MACTMAIN point A\n");

    std::string* ParsedTokens = new std::string[6];

//    do {
        if(strncmp(sType, "CONTINUE", 8) == 0) {
            ParsedTokens[0] = 'C';
            MACTSendSocket(ParsedTokens);
        } 
        else {
            BOOL bValid = FALSE;
            while(!bValid) {
                ParsedTokens = MACTGetCommand();
                bValid = ExecuteMACTCommand(sType, ParsedTokens);
            }
            MACTSendSocket(ParsedTokens);
        }
 //       ParsedTokens = MACTGetCommand();
 //       ExecuteMACTCommand(sType, ParsedTokens);
 //       MACTSendSocket(ParsedTokens);
 //   } while(ParsedTokens[0] == "D")
//    while(ParsedTokens[0] != "Q" && ParsedTokens[0] != "C" && ParsedTokens[0] != "D");
//    while((ParsedTokens[0] != "C") && !((ParsedTokens[0] == "S") && (ParsedTokens[1] == "R")));

    int ret = 0;
//    if((ParsedTokens[0] == "S") && (ParsedTokens[1] == "R"))
//        ret = 1;

    delete[] ParsedTokens;

//    std::string ret = ParsedTokens[1] + ParsedTokens[2];
    return(ret);
}

void MACTDisplayMemory(LPVOID lAddress, int xRows)
{
    int xCols = 0;
    for(int z = 1; z <= xRows; ++z) {
        printf("%x: ", ((int)lAddress + xCols));
        for(int x = xCols; x < (xCols + 16); ++x)
            printf("%02x ", ((uint8_t*) lAddress)[x]);
        printf("\n");
        xCols += 16;
    }
}

DWORD WINAPI MACTMemThread(LPVOID lpParam) 
{ 
    HANDLE   hStdout;
    PMEMDATA ptDataArray;

    TCHAR msgBuf[255];
    size_t cchStringSize;
    DWORD dwChars;

    // Make sure there is a console to receive output results. 
//
//    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
//    if( hStdout == INVALID_HANDLE_VALUE )
//        return 1;

    printf("In thread.\n");

    ptDataArray = (PMEMDATA)lpParam;
    printf("In CreateThread %x, %d\n", (int)ptDataArray->Mem_address, ptDataArray->Mem_size);
    char *MemoryChunk = new char[ptDataArray->Mem_size];
    printf("After MemoryChunk\n");
    MACTDisplayMemory(ptDataArray->Mem_address, 4);
//    CopyMemory(MemoryChunk, ptDataArray->Mem_address, ptDataArray->Mem_size);

    printf("After CopyMemory\n");

//    StringCchPrintf(msgBuf, 255, TEXT("Parameters = %x, %d\n"), (int)(ptDataArray->Mem_address), ptDataArray->Mem_size); 
//    StringCchLength(msgBuf, 255, &cchStringSize);
//    WriteConsole(hStdout, msgBuf, (DWORD)cchStringSize, &dwChars, NULL);
/*
    while (ptDataArray->Mem_futureObj.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout) {
        if(memcmp(MemoryChunk, ptDataArray->Mem_address, ptDataArray->Mem_size) != 0)
            printf("MemoryChunk != ptDataArray->Mem_address\n");
    }
*/
    return 0; 
} 

void MACTCreateThread(LPVOID buffer, size_t msize, int interval)
{
    pDataArray[THREADCOUNT] = (PMEMDATA) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMDATA));

    if( pDataArray[THREADCOUNT] == NULL )
        ExitProcess(2);

    pDataArray[THREADCOUNT]->Mem_address   = buffer;
    pDataArray[THREADCOUNT]->Mem_size      = msize;
    pDataArray[THREADCOUNT]->Mem_interval  = interval;
    pDataArray[THREADCOUNT]->Mem_futureObj = exitSignal.get_future();

    printf("Before CreateThread\n");
    printf("CreateThread %x, %d\n", (int)pDataArray[THREADCOUNT]->Mem_address, pDataArray[THREADCOUNT]->Mem_size);

    hThreadArray[THREADCOUNT] = CreateThread(NULL, 0, MACTMemThread, pDataArray[THREADCOUNT], 0, &dwThreadIdArray[THREADCOUNT]);   

    printf("After CreateThread\n");

    if (hThreadArray[THREADCOUNT] == NULL) 
           ExitProcess(3);

    ++THREADCOUNT;
}

void MACTCleanUp()
{
    exitSignal.set_value();
 
    for(int i=0; i<THREADCOUNT; i++)
    {
        CloseHandle(hThreadArray[i]);
        if(pDataArray[i] != NULL)
        {
            HeapFree(GetProcessHeap(), 0, pDataArray[i]);
            pDataArray[i] = NULL;    // Ensure address is not reused.
        }
    }
}

VOID MACTMemoryMonitor(char *buffer)
{
    std::string sSource = buffer;
    sSource = sSource.substr(1,(strlen(buffer)-1));
    std::replace(sSource.begin(), sSource.end(), '(', ',');
    std::replace(sSource.begin(), sSource.end(), ')', ',');
    
//    printf("sSource = %s\n", sSource.c_str());
    size_t pos = 0;
    std::string token;
    std::string sTokens[3];
    int iToken = 0;
    while((pos = sSource.find(',')) != std::string::npos) {
        token = sSource.substr(0, pos);
        sTokens[iToken] = token;
        ++iToken;
        sSource.erase(0, pos + 1);
    }

//    printf("0 = %s\n", sTokens[0].c_str());
//    printf("1 = %s\n", sTokens[1].c_str());
//    printf("2 = %s\n", sTokens[2].c_str());
    char *xbuffer = new char[10];
    LPVOID pbuffer = (LPVOID)atoi(sTokens[1].c_str());
//    printf("pbuffer = %d\n", (int) pbuffer); 
    size_t psize = atoi(sTokens[2].c_str());
//    printf("psize = %d\n", psize);

    MACTCreateThread(pbuffer, psize, 50);    
}

void main() {
    WSADATA WsaDat;
    char buffer[512];
    char lastbuffer[512];
    int inDataLength = 0;
    std::string slastbuffer;

    lastbuffer[0]  = '\0';
    MACTAPISkip[0] = "CLOSEHANDLE";

    if(WSAStartup(MAKEWORD(2,2),&WsaDat)!=0) {
        std::cout<<"WSA Initialization failed!\r\n";
        WSACleanup();
        system("PAUSE");
        return;
    }
            
    Socket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(Socket==INVALID_SOCKET) {
        std::cout<<"Socket creation failed.\r\n";
        WSACleanup();
        system("PAUSE");
        return;
    }
            
    SOCKADDR_IN serverInf;
    serverInf.sin_family=AF_INET;
    serverInf.sin_addr.s_addr=INADDR_ANY;
    serverInf.sin_port=htons(27015);
            
    if(bind(Socket,(SOCKADDR*)(&serverInf),sizeof(serverInf))==SOCKET_ERROR) {
        std::cout<<"Unable to bind socket!\r\n";
        WSACleanup();
        system("PAUSE");
        return;
    }
      
    listen(Socket, 1);
            
    SOCKET TempSock=SOCKET_ERROR;
    while(TempSock==SOCKET_ERROR) {
        std::cout<<"Waiting for incoming connections...\r\n";
        TempSock=accept(Socket,NULL,NULL);
    }
          
    // If iMode!=0, non-blocking mode is enabled.
    u_long iMode=1;
    ioctlsocket(Socket,FIONBIO,&iMode);
            
    Socket=TempSock;
    std::cout<<"Client connected!\r\n\r\n";
    bool selected = FALSE;
    std::string* ParsedTokens = new std::string[6];
    ParsedTokens[0] = "C";
//    
//    SendSocket();


    for(;;) {

        for(;;) {

            fd_set ReadFDs;
            FD_ZERO(&ReadFDs);
            FD_SET(Socket, &ReadFDs);
            inDataLength = 0;

            if(select(0, &ReadFDs, NULL, NULL, 0) > 0) {
    //            printf("Hello.\n");
            // some socket event was triggered, check which one
    //            std::cout<<"Selected.\n";
                if (FD_ISSET(Socket, &ReadFDs)) {
                // it was a read event on our socket, so call recv
    //                char buffer[180];
                    if(MACTDEBUG)
                        printf("serverb: read\n");
                    memset(buffer, 0, 512);
                    inDataLength = recv(Socket, buffer, 512, 0);
 //                   if(inDataLength < 1)
 //                       break;
                    if(inDataLength > 0) {
                        buffer[511] = '\0';
//                        printf("buffer = [%s]\n", buffer);
                        if(MACTDEBUG) {
                            printf("serverb: Got bytes: %d\n", inDataLength);
                            printf("serverb: Got: %s\n", buffer);
                        }
                        
// Comms may get off due to functions that fail, this resets the communication if two MACTSTARTS in a row are sent.
                        if((strncmp(lastbuffer, "MACTSTART", 9) == 0) &&
                           (strncmp(buffer, "MACTSTART", 9) == 0)) {
                            strncpy(buffer, ">Resetting comms.\n", 18);
                            MACTSendSocket(ParsedTokens);
                        }
                        else
                            strncpy(lastbuffer, buffer, 512);

                        if(strncmp(buffer, "MACTSTART", 9) == 0) {
                            MACTFINISH = FALSE;
                            break;
//                        } else if(strncmp(buffer, "MACTBP", 6) == 0) {
//                            MACTFINISH = FALSE;
                        } else if(strncmp(buffer, "MACTEXIT", 9) == 0) {
                            exit(0);
                        } else if(strncmp(buffer, "MACTINIT", 7) == 0) {
                            printf("First time start up!\n");
                            MACTdir = buffer;
                            size_t idirlength = MACTdir.length() - 9;
                            MACTdir = MACTdir.substr(9, idirlength);
                            MACTCreateDatabase();
                        } else { 
                            if(buffer[0] == '=') {
                                std::string sbuffer = buffer;
                                size_t ibuffer = sbuffer.length() - 1;
                                sbuffer = sbuffer.substr(1, ibuffer);
                                memset(buffer, 0, 512);
                                strncpy(buffer, sbuffer.c_str(), ibuffer);
                            }
                            else if(buffer[0] == '&') {
                                printf("Set up memory monitor.\n");
                                printf("%s\n", buffer);
                                MACTMemoryMonitor(buffer);                          
                            }
                            else {
                                MACTWriteLog(buffer);
                                MACTInsertDatabase(buffer);
                            }
                            if(buffer[0] != '*')
                                printf("%s", buffer);
//                            strncpy(lastbuffer, buffer, 512);      
                        }
                    }
                    else {
                        buffer[0] = '\0';
                        printf("Done.\n");
                        MACTCleanUp();
                        closesocket(Socket);
                        WSACleanup();
                        return;
                    }
                }
                else {
                    printf("Error FD_ISSET\n");
                    MACTCleanUp();
                    exit(0);
                }
            } 
            else {
                printf("Error on select.\n");
                MACTCleanUp();
                exit(0);
            }
            
        } 

//        if(MACTSTART)
//        if(strncmp(lastbuffer, "CloseHandle", 11) == 0) 
/*
        if(inDataLength > 0) {
            slastbuffer = lastbuffer;
            std::transform(slastbuffer.begin(), slastbuffer.end(), slastbuffer.begin(), toupper);
            if(strncmp(slastbuffer.c_str(), MACTAPISkip[0].c_str(), MACTAPISkip[0].length()) == 0) {
                MACTMain("CONTINUE");
            }
            else
                MACTMain("TEST");
        }
*/
//        printf("***********  MACTMain\n");
        MACTMain("TEST");
    }
}