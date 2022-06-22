#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <pthread.h>

#define BUFFSIZE 1024
#define PORTNO 39999

int sub_process = 0;
pid_t main_server_pid;
time_t run_time;

struct w_th{
	int ishit;
	char* url;
	char* logfile_path;
	char* cache_dir;
	char* cache_file;
};

/////////////////////////////////////////////////////////////////////////////////
// File Name	:server.c						       					       //
// Date			:2022/06/03					  	       						   //
// Os			:Ubuntu 16.04 LTS 64bits				       				   //
// Author		:Park Gun Woo					               				   //
// Student ID	:2018202012						       						   //
// ----------------------------------------------------------------------------//
// Title : System Programming Assignment #3-2 (proxy server)		       	   //
// Description : This program is server program and make socket to communicate //
// with client. When client connect to server, this program will make child pro//
// cess, and child process creates a cache directory by receiving url input    //
// from client and encrypting it and leave logfile.txt and verify hit or miss  //
// and main process handles SIGCHLD, SIGALRM signal, and wait other connection.//
// When server response to client, client browser show the html file. and store//
// response message in the cache file. using semapore, block other process whil//
// e one process is in the critical section and by using thread, write log     // 
/////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// getHomeDir							             					     //
// ========================================================================= //
// Input: home -> home directory path(empty)				     		     //
// 									     									 //
// Output: home -> home directory path					     			     //
//									     								     //
// Purpose: to get Home directory path					     				 //
///////////////////////////////////////////////////////////////////////////////

char *getHomeDir(char *home){
	struct passwd *usr_info = getpwuid(getuid());
	strcpy(home, usr_info -> pw_dir);

	return home;
}

/////////////////////////////////////////////////////////////////////////////////
// sha1_hash								       							   //
// ============================================================================//
// Input: input_url -> input URL from user				      				   //
//	  hashed_url -> encrpted url					       					   //
// Output: hashed_url							       						   //
//									       									   //
// Purpose: hashing url							       						   //
/////////////////////////////////////////////////////////////////////////////////	

char *sha1_hash(char *input_url, char * hashed_url){
	unsigned char hashed_160bits[20];
	char hashed_hex[41];
	int i;

	SHA1(input_url, strlen(input_url), hashed_160bits); //hashing url
	
	//changing url to hexadecimal url
	for(i=0; i<sizeof(hashed_160bits); i++)
		sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);
	
	//store result in hashed_url
	strcpy(hashed_url, hashed_hex);

	return hashed_url;
}

///////////////////////////////////////////////////////////////////////////////
// isHit							             						     //
// ========================================================================= //
// Input: hashed_url -> hashed url 				     		     			 //
// 		  path -> cache data directory path						     		 //
// Output: is_hit -> is there a same file in the cache					     //
//									     								     //
// Purpose: verifying that the same file exists					     		 //
///////////////////////////////////////////////////////////////////////////////

int isHit(char *hashed_url, char * path){
	struct dirent *pFile;
	DIR *pDir;

	pDir=opendir(path); //open cache data directory
	if(pDir == NULL){ //if there is no directory
		return 0; //return false
	}
	
	//read directory if there is same file, return true
	for(pFile=readdir(pDir); pFile; pFile=readdir(pDir)){
		if(!strcmp(pFile->d_name,hashed_url+3)){
			closedir(pDir);
			return 1;
		}
	}
	
	closedir(pDir);
	return 0; //return false		
}

///////////////////////////////////////////////////////////////////////////////
// write log							             						 //
// ========================================================================= //
// Input: is_hit -> hit or miss value										 //
//		  input_url -> input url from web browser 				     		 //
// 		  home_dir_path_logfile -> logfile path								 //
//		  cache_dir -> cache directory path									 //
//		  cache_file -> cache file path			         				 	 //
// Output: none (void)					     								 //
//									     								     //
// Purpose: write log in logfile.txt					     		 		 //
///////////////////////////////////////////////////////////////////////////////
void *write_log(void * th_arg){
	struct w_th *arg = (struct w_th *)th_arg;
	int is_hit = arg->ishit;
	char* input_url = arg->url;
	char* home_dir_path_logfile = arg->logfile_path;
	char* cache_dir = arg->cache_dir;
	char* cache_file = arg->cache_file;

	input_url[strlen(input_url)] = '\0';
	time_t now;
	struct tm* ltp;

	//write miss log in the logfile.txt
	if(is_hit == 0){
	FILE *fp = NULL;
	fp = fopen(home_dir_path_logfile,"a");
	time(&now);
	ltp = localtime(&now);
	fprintf(fp,"[Miss]%s-[%d/%02d/%02d, %02d:%02d:%02d]\n",input_url,ltp->tm_year+1900,ltp->tm_mon+1,ltp->tm_mday,ltp->tm_hour,ltp->tm_min,ltp->tm_sec);
	fclose(fp);	
	}
	
	//Hit	
	else{
		//write hit log in the logfile.txt
		time(&now);
		ltp = localtime(&now);
		FILE* fp = fopen(home_dir_path_logfile,"a");
		fprintf(fp,"[Hit]%s/%s-[%d/%02d/%02d, %02d:%02d:%02d]\n",cache_dir,cache_file,ltp->tm_year+1900,ltp->tm_mon+1,ltp->tm_mday,ltp->tm_hour,ltp->tm_min,ltp->tm_sec);
		fprintf(fp,"[Hit]%s\n",input_url);
		fclose(fp);	
	}
}

///////////////////////////////////////////////////////////////////////////////
// make_cache_file							             					 //
// ========================================================================= //
// Input: hashed_dir_path_cache -> cache directory path 				     //
// 		  hashed_url -> hashed url											 //
//		  											 						 //
// Output: none (void)					    								 //
//									     								     //
// Purpose: make cache directory and file 					     			 //
///////////////////////////////////////////////////////////////////////////////

 void make_cache_file(char * home_dir_path_cache, char * hashed_url, char * buf, int is_hit){
	char path[150];
	char cache_dir[5];
	char cache_file[100];

	//create data directory
	strcpy(path,home_dir_path_cache);
	strcat(path,"/");
	strncat(path,hashed_url,3); //copy 3 character
	strncpy(cache_dir,hashed_url,3); //copy 3 character
	cache_dir[3]='\0';
	strcpy(cache_file,hashed_url+3);

	mkdir(path,S_IRWXU|S_IRWXG|S_IRWXO); //create cache data directory
	
	//create data file
	strcat(path,"/");
	strcat(path,hashed_url+3);
	creat(path,S_IRWXU|S_IRWXG|S_IRWXO);

	return;
 }

///////////////////////////////////////////////////////////////////////////////
// sig_int							             					 		 //
// ========================================================================= //
// Input: signo -> signal number					 						 //
//		  											 						 //
// Output: NONE					     										 //
//									     								     //
// Purpose: when press ctrl + C, SIGINT occur, handle the signal function	 //				     				 
///////////////////////////////////////////////////////////////////////////////
void sig_int(int signo){
	char path[150];
	time_t now;
	time(&now);

	if(main_server_pid == getpid()){
		strcpy(path, getHomeDir(path)); //get home directory path
 		strcat(path, "/logfile/logfile.txt"); //make logfile directory path
 		FILE* fp = fopen(path,"a"); //write the log int logfile.txt
		fprintf(fp,"**SERVER** [Terminated] run time: %ld sec. #sub process : %d \n", now-run_time, sub_process);
		fclose(fp);
	}

	exit(0); //terminate process
}

///////////////////////////////////////////////////////////////////////////////
// handler							             					 		 //
// ========================================================================= //
// Input: NONE					 											 //
//		  											 						 //
// Output: NONE					     										 //
//									     								     //
// Purpose: When child make SIGCHLD signal, parent process will catch the    //
// terminate signal using this fucntion					     				 //
///////////////////////////////////////////////////////////////////////////////

static void handler(){
	pid_t pid; 
	int status;
	while((pid = waitpid(-1, &status, WNOHANG)) > 0);
}

///////////////////////////////////////////////////////////////////////////////
// getIPAddr							             						 //
// ========================================================================= //
// Input: addr -> host URL						     		 				 //
// Output: haddr -> dotted 32-bit IP address					    		 //
//									     								     //
// Purpose: get IP address from host name					     		 	 //
///////////////////////////////////////////////////////////////////////////////
char *getIPAddr(char *addr){
    struct hostent* hent;
    char * haddr = NULL;
    int len = strlen(addr);

    if((hent = (struct hostent *)gethostbyname(addr)) != NULL){
        haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));
    }
    return haddr;
}

///////////////////////////////////////////////////////////////////////////////
// myalarm							             						     //
// ========================================================================= //
// Input: none						     		 							 //
// Output: none					     										 //
//									     								     //
// Purpose: if SIGALRM occur, print message and terminate process			 //
///////////////////////////////////////////////////////////////////////////////
void myalarm(){
	printf("==============No Response================\n");
	exit(0);
}


///////////////////////////////////////////////////////////////////////////////
// p							             						         //
// ========================================================================= //
// Input: semid -> semapore ID						     		 			 //
// Output: none					     										 //
//									     								     //
// Purpose: block other process while one process executing			 		 //
///////////////////////////////////////////////////////////////////////////////
void p(int semid){
    struct sembuf pbuf;
    pbuf.sem_num = 0; //one semapore
    pbuf.sem_op = -1; //lock on
    pbuf.sem_flg = SEM_UNDO; //auto close
    if((semop(semid, &pbuf, 1)) == -1){ //operation
        perror("p : semop failed");
        exit(1);
    }
	printf("*PID# %d is in the critical zone.\n", getpid());
}


///////////////////////////////////////////////////////////////////////////////
// v							             						         //
// ========================================================================= //
// Input: semid -> semapore ID						     		 			 //
// Output: none					     										 //
//									     								     //
// Purpose: lock off semapore			 		 							 //
///////////////////////////////////////////////////////////////////////////////
void v(int semid){
    struct sembuf vbuf;
    vbuf.sem_num = 0;
    vbuf.sem_op = 1; //lock off
    vbuf.sem_flg = SEM_UNDO; //auto close
	printf("*PID# %d is exited the critical zone.\n", getpid());
    if((semop(semid, &vbuf,1)) == -1){ 
        perror("v: semop failed");
        exit(1);
    }
}

int main(){
	int socket_fd,client_fd, len, len_out;
	struct sockaddr_in server_addr, client_addr;
	int state;
	pid_t pid;
	char buf[BUFFSIZE];
	time_t now;
	struct tm* ltp;
	
	char input_url[100];
 	char home_dir_path[50];
	char home_dir_path_cache[50];
 	char home_dir_path_log[50];
 	char home_dir_path_logfile[50];
 	char hashed_url[41];
 	char cmd[20];
 	int miss = 0;
 	int hit = 0;
 	int status;
	int subprocess = 0;
	
	time(&run_time);
	main_server_pid = getpid();

	strcpy(home_dir_path, getHomeDir(home_dir_path)); //get home directory path
 	strcpy(home_dir_path_cache,home_dir_path); 
 	strcat(home_dir_path_cache, "/cache"); //make cache directory path
 	strcpy(home_dir_path_log, home_dir_path); 
 	strcat(home_dir_path_log, "/logfile"); //make logfile directory path
 	strcpy(home_dir_path_logfile,home_dir_path_log);
 	strcat(home_dir_path_logfile,"/logfile.txt"); //make logfile.txt path

 	umask(0); //umask reset
 	mkdir(home_dir_path_cache,S_IRWXU|S_IRWXG|S_IRWXO); //make cache directory
 	mkdir(home_dir_path_log,S_IRWXU|S_IRWXG|S_IRWXO); //make logfile directory
 	creat(home_dir_path_logfile,S_IRWXU|S_IRWXG|S_IRWXO); //make logfile.txt

	//create socket to connect client
	if((socket_fd=socket(PF_INET, SOCK_STREAM, 0)) < 0){
		printf("SERVER: Cant open stream socket.");
		return 0;
	}

	int opt =1;
	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	//Server IP address reset
	bzero((char *)&server_addr, sizeof(server_addr));
	//set IPv4 internet protocol system
	server_addr.sin_family = AF_INET;
	//Server IP address to network byte order
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	//Port number to network byte order
	server_addr.sin_port = htons(PORTNO);
	//struct information binding to socket
	if(bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
		printf("Server : Can't bind local address. \n");
		return 0;
	}
	//Server wait client connection
	listen(socket_fd, 5);
	//if child terminated, handle signal
	signal(SIGINT, sig_int); 
	signal(SIGCHLD, (void*)handler);
	signal(SIGALRM, myalarm);
	
	int semid; //semapore ID
	union semun //semapore arg
	{
		int val;
		struct semid_ds *sbuf;
		unsigned short int * array;
	}arg;

	//create semapore
	if((semid = semget((key_t)PORTNO, 1, IPC_CREAT|0666)) == -1){ //key value, sem count, permission
        perror("semget failed");
        exit(1);
    }

	//semapore SETVAL parameter
	arg.val =1;

	//semapore control
	if((semctl(semid, 0, SETVAL, arg)) == -1){
		perror("semctl failed");
        exit(1);
	}

	while(1){
		bzero((char *)&client_addr, sizeof(client_addr)); //reset client address
		len = sizeof(client_addr);
		client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &len); //accept client connection
		if(client_fd < 0){ //if connection failed
			printf("Server: accept failed %d\n", getpid());
			close(socket_fd);
			return 0;
		}
		sub_process++;
		pid = fork(); //make child process
		time(&now); //Get calendar time
		//if fork failed
		if(pid == -1){
			close(client_fd);
			close(socket_fd);
			return 0;
		}
		bzero(buf, sizeof(buf)); //reset buf
		//Child process section
		if(pid == 0){			
			char *ip = inet_ntoa(client_addr.sin_addr);//convert binary IP address to decimal address									
			read(client_fd, buf, BUFFSIZE); //read client input URL
			char response_header[BUFFSIZE] = {0,};
			char response_message[BUFFSIZE] = {0,};
			char tmp[BUFFSIZE] = {0,};
			char method[20]={0,};
			char url[BUFFSIZE] = {0,};
			char *tok = NULL;

			strcpy(tmp, buf); //copy HTTP request			
			tok = strtok(tmp, " "); //split HTTP request per " "
			strcpy(method, tok); //extract method from HTTP request
			//extract URL from HTTP request
			if(strcmp(method, "GET") == 0){
				tok = strtok(NULL, " ");
				strcpy(url, tok);
			}else{
				//printf("[%s : %d] client was disconnected.\n",ip, client_addr.sin_port);
				close(client_fd); //close child process socket
				exit(0); //child process terminate
			}
			//Make hashcode
			char ori[BUFFSIZE];
			char *url_1;
			//parsing URL
			strcpy(ori, url);
			strcpy(url, url+7);			
			strtok(tok, "/");
			url_1 = strtok(NULL, "/");

			//make hashed URL
			strcpy(hashed_url, sha1_hash(url, hashed_url));

			char path[150];
			char cache_dir[5];
			char cache_file[100];
			char buf2[BUFFSIZE*10]; //buf for response message
			int err, status;
			pthread_t tid;
			void *tret;

			//make cache directory path
			strcpy(path,home_dir_path_cache);
			strcat(path,"/");
			strncat(path,hashed_url,3); //copy 3 character
			strncpy(cache_dir,hashed_url,3); //copy 3 character
			cache_dir[3]='\0';
			strcpy(cache_file,hashed_url+3);
			
			printf("*PID# %d is waiting for the semaphore\n", getpid());
			struct w_th *th_arg; //thread argument struct
			th_arg = (struct w_th *)malloc(sizeof(struct w_th)); //memory allocation
			//if HIT
			if(isHit(hashed_url, path)){
				strcat(path,"/");
				strcat(path, cache_file);
				
				//thread argument struct init
				th_arg->ishit = 1;
				th_arg->url = url;
				th_arg->logfile_path = home_dir_path_logfile;
				th_arg->cache_dir = cache_dir;
				th_arg->cache_file = cache_file;
		
				//semapore lock on
				p(semid);
				//create thread and call write log function
				err = pthread_create(&tid, NULL, write_log, (void *)th_arg);
				printf("*PID# %d create the *TID# %lu\n", getpid(), tid);
				//error detection
				if(err != 0){
					printf("pthread error \n");
					return 0;
				}
				sleep(5);
				//thread exit state catch
				pthread_join(tid, &tret);

				printf("*TID# %lu is exited.\n", tid);					
				//semaphore lock off
				v(semid);
				int fd;
				fd = open(path, O_RDONLY); //read from cache file to get response message
				while(read(fd, buf2, BUFFSIZE)>0){
					write(client_fd, buf2, BUFFSIZE); //send response message to client
				}
				close(fd);
				
				hit++;
			}
			else{//MISS
				char *IPAddr = NULL;

				//thread argument struct init
				th_arg->ishit = 0;
				th_arg->url = url;
				th_arg->logfile_path = home_dir_path_logfile;
				th_arg->cache_dir = cache_dir;
				th_arg->cache_file = cache_file;

				//semapore lock on
				/*Critical Section*/
				p(semid);
				//create thread and call write log function
				err = pthread_create(&tid, NULL, write_log, (void *)th_arg);
				printf("*PID# %d create the *TID# %lu\n", getpid(), tid);
				//error detection
				if(err != 0){
					printf("pthread error \n");
					return 0;
				}
				sleep(5);
				//thread exit state catch
				pthread_join(tid, &tret);
				printf("*TID# %lu is exited.\n", tid);
				//semapore lock off
				v(semid);
				while(IPAddr == NULL){ //if gethostbyname return error, repeat the function per 1 sec
					IPAddr = getIPAddr(url_1);
					sleep(1);
				}
				alarm(50); //timer start
				int s_fd; //socket descripotr
				struct sockaddr_in s_addr; //socket to communicate web server			
				s_fd = socket(AF_INET, SOCK_STREAM, 0);
				bzero((char *)&s_addr, sizeof(s_addr));
				s_addr.sin_family = AF_INET;
				s_addr.sin_addr.s_addr = inet_addr(IPAddr); //web server IP address -> binary address
				s_addr.sin_port = htons(80); //HTTP port number 80 

				strcat(path,"/");
				strcat(path, cache_file);
				miss++;
					
				//connect to web server, if error returned, repeat per 1 sec
				while(connect(s_fd, (struct sockaddr*)&s_addr, sizeof(s_addr)) < 0){
					sleep(1);
				}
				//send request message, if error returned, repeat per 1 sec	
				while(write(s_fd, buf, BUFFSIZE)<0){
					sleep(1);
				}
				make_cache_file(home_dir_path_cache, hashed_url, buf2, 0);
				int fd;
				fd = open(path,O_WRONLY|O_TRUNC);
				ssize_t len_out = 0;
				//receive response message, if error returned, repeat per 1 sec
				while((len_out = read(s_fd, buf2, BUFFSIZE)) > 0){
					write(client_fd, buf2, len_out);					 
					write(fd, buf2, len_out);
					//bzero(buf2, sizeof(buf2));
				}

				close(fd); //file stream close
				alarm(0); //timer reset
			}
			close(client_fd); //close child process socket
			exit(0); //child process terminate
		
		}close(client_fd); //close parent process socket    
	}

	//return semapore resource
	if((semctl(semid, 0, IPC_RMID, arg)) == -1){
        	perror("semctl failed");
        	exit(1);
    }

	close(socket_fd); //close server socket
	return 0;
}

