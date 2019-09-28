#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define VERSION			24
#define BUFSIZE			8096		//Tamaño del buffer
#define ERROR			42			//Codigo de error para un fallo de una función o llamada al sistema
#define LOG				44			//Código para escribir información en el buffer del log
#define OK				200
#define BADREQUEST		400
#define PROHIBIDO		403			//Codigo obtenido cuando se intenta acceder a un recurso prohibido
#define NOENCONTRADO	404			//Codigo obtenido cuando no se encuentra un recurso loicitado
#define UNSUPPORTED		415

struct {
	char *ext;						//Estructura usada para hallar los recursos según la extensión
	char *filetype;					//Tenemos por un lado un string que simboliza la extensión del archivo,
} extensions [] = {					//y por el otro un string con el directorio en el que se puede encontrar
	{"gif", "image/gif" },			//extensions es un array con dichos pares de struct
	{"jpg", "image/jpg" },
	{"jpeg","image/jpeg"},
	{"png", "image/png" },
	{"ico", "image/ico" },
	{"zip", "image/zip" },
	{"gz",  "image/gz"  },
	{"tar", "image/tar" },
	{"htm", "text/html" },
	{"html","text/html" },
	{0,0} };

char * ServerHead = "Server: Apache/2.0.52 (CentOS)\r\n";
char * HostHead2 = " web.sstt1334.org:5100";
char * HostHead = " 192.168.56.102:5100";
char resourceType[12];
int hostChecked = 0;
int cookieCounter = 0;
int connecKeepAlive = 1;
int keepAlive = 1;
int timeAlive = 2;
int actualNumRequest = 0;
int maxNumRequest = 1;
long resourceSize = -1;




//
// Comprueba que la versión de http sea válida
//
int ValidateHTTPVersion(char * version) {
	if (strcmp(version, "HTTP/1.0") == 0) return 0;
	if (strcmp(version, "HTTP/1.1") == 0) return 0;
	if (strcmp(version, "HTTP/1.2") == 0) return 0;
	return -1;
}

//
// Crea una cabecera Date para un mensaje HTTP de 
// respuesta
//
char * DateHead() {
	time_t t;
	struct tm *tm;
	t = time(NULL);
	tm = localtime(&t);
	char fecha[200];
	strftime(fecha, 200, "%a, %d %b %Y %X %Z", tm);
	char aux[500] = "Date: ";
	char * aux2 = strcat(aux, fecha);
	strcat(aux2, "\r\n");
	return aux2;
}

char * SetCookieHeader() {
	char header[64] = "Set-Cookie: cookie_counter=";
	char number[12];
	snprintf(number, 12, "%d", (cookieCounter));
	strcat(header, number);
	strcat(header, "; Max-Age=120\r\n");
	char * ptr = header;
	return ptr;
}

char * ConnectionHeader() {
	if (connecKeepAlive == 0) return "Connection: close\r\n";
	else return "Connection: keep-alive\r\n";
}

char * KeepAliveHeader() {
	char header[64] = "Keep-Alive: timeout=";
	char number[10];
	snprintf(number, 10, "%d", timeAlive);
	strcat(header, number);
	strcat(header, ", max=0\r\n"); //Estam max a 1000
	char * ptr = header;
	return ptr;
}

char * ContentLengthHeader(){
	char cadena[64] = "Content-Length: ";
	char tamFile[20];
	snprintf(tamFile, 20, "%ld", resourceSize);
	strcat(cadena, tamFile);
	strcat(cadena, "\r\n");
	char * ptr = cadena;
	return ptr;
}

char * ContentTypeHeader(){
	char cadena[200] = "Content-Type: ";
	strcat(cadena, resourceType);
	strcat(cadena, "; charset=UTF-8\r\n");
	char * ptr = cadena;
	return ptr;
}

char * CreateResponse(int codigo) {
	char message[BUFSIZE];
	strcpy(message, "HTTP/1.1");
	switch (codigo)
	{
	case OK:
		strcat(message, " 200 OK\r\n");
		strcat(message, ContentTypeHeader());
		strcat(message, ContentLengthHeader());
		break;
	case BADREQUEST:
		strcat(message, " 400 Bad Request\r\n");
		break;
	case PROHIBIDO:
		strcat(message, " 403 Forbidden\r\n");
		break;
	case NOENCONTRADO:
		strcat(message, " 404 Not Found\r\n");
		break;
	case UNSUPPORTED:
		strcat(message, " 415 Unsupported Media Type\r\n");
		break;
	}
	strcat(message, DateHead());
	strcat(message, ServerHead);
	strcat(message, SetCookieHeader());
	strcat(message, ConnectionHeader());
	if (connecKeepAlive == 1) strcat(message, KeepAliveHeader());
	strcat(message, "\r\n");
	char * ptr = message;
	return ptr;
}

// Función que irá escribiendo en un fichero los errores que vaya obteniendo el programa
void debug(int log_message_type, char *message, char *additional_info, int socket_fd)
{
	int fd ;
	char logbuffer[BUFSIZE*2];
	char * response;
	switch (log_message_type) {
		case ERROR: (void)sprintf(logbuffer,"ERROR: %s:%s Errno=%d exiting pid=%d",message, additional_info, errno,getpid());
			break;
		case OK:
			// Enviar como respuesta 200 OK
			(void)sprintf(logbuffer, "OK: %s:%s", message, additional_info);
			response = CreateResponse(OK);
			write(socket_fd, response, strlen(response));
			(void)sprintf(logbuffer, " INFO: %s:%s:%d\nMensaje enviado\n%s", message, additional_info, socket_fd, response);
			break;
		case BADREQUEST:
			// Enviar como respuesta 400 Bad Request
			(void)sprintf(logbuffer, "BAD REQUEST: %s:%s", message, additional_info);
			response = CreateResponse(BADREQUEST);
			write(socket_fd, response, strlen(response));
			(void)sprintf(logbuffer, " INFO: %s:%s:%d\nMensaje enviado\n%s", message, additional_info, socket_fd, response);
			break;
		case PROHIBIDO:
			// Enviar como respuesta 403 Forbidden
			(void)sprintf(logbuffer,"FORBIDDEN: %s:%s",message, additional_info);
			response = CreateResponse(PROHIBIDO);
			write(socket_fd, response, strlen(response));
			(void)sprintf(logbuffer, " INFO: %s:%s:%d\nMensaje enviado\n%s", message, additional_info, socket_fd, response);
			break;
		case NOENCONTRADO:
			// Enviar como respuesta 404 Not Found
			(void)sprintf(logbuffer,"NOT FOUND: %s:%s",message, additional_info);
			response = CreateResponse(NOENCONTRADO);
			write(socket_fd, response, strlen(response));
			(void)sprintf(logbuffer, " INFO: %s:%s:%d\nMensaje enviado\n%s", message, additional_info, socket_fd, response);
			break;
		case UNSUPPORTED:
			// Enviar como respuesta 415 Unsupported Media File
			(void)sprintf(logbuffer, "UNSUPPORTED: %s:%s", message, additional_info);
			response = CreateResponse(UNSUPPORTED);
			write(socket_fd, response, strlen(response));
			(void)sprintf(logbuffer, " INFO: %s:%s:%d\nMensaje enviado\n%s", message, additional_info, socket_fd, response);
			break;
		case LOG: (void)sprintf(logbuffer," INFO: %s:%s:%d",message, additional_info, socket_fd); break;
	}

	if((fd = open("webserver.log", O_CREAT| O_WRONLY | O_APPEND,0644)) >= 0) {
		(void)write(fd,logbuffer,strlen(logbuffer));
		(void)write(fd,"\n",1);
		(void)close(fd);
	}
	if(log_message_type == ERROR || log_message_type == BADREQUEST || log_message_type == UNSUPPORTED || log_message_type == PROHIBIDO || log_message_type == NOENCONTRADO || log_message_type == PROHIBIDO) {
		close(socket_fd);
		exit(3);
	}
}

//
// Obtiene los campos de la cabecera de una solicitud HTTP y comprueba la correctitud del método que se
// le pide, el número de campos, que el recurso no sea nulo y la version HTTP
//
int EvaluateRequestLine(char * cabecera, char ** metodo, char ** recurso, char ** version, int descriptorFichero) {
	char * saveptr2;
	*metodo = strtok_r(cabecera, " ", &saveptr2);
	*recurso = strtok_r(NULL, " ", &saveptr2);
	*version = strtok_r(NULL, " ", &saveptr2);
	if (strtok_r(NULL, " ", &saveptr2) != NULL) {
		//Enviar mensaje error 400 Bad Request
		debug(BADREQUEST, "Error al procesar la petición web", "Cabecera con demasiados campos", descriptorFichero);
	}
	if (metodo == NULL) {
		//Enviar mensaje error 400 Bad Request
		debug(BADREQUEST, "Error al procesar la petición web", "Método nulo", descriptorFichero);
	}
	if (strcmp(*metodo,"GET") != 0) {
		//Se cierra sin enviar mensaje de error
		debug(BADREQUEST, "Error al procesar la petición web", "No es método GET", descriptorFichero);
	}
	if (recurso == NULL) {
		//Enviar mensaje error 400 Bad Request
		debug(BADREQUEST, "Error al procesar la petición web", "Recurso nulo", descriptorFichero);
	}
	if (version == NULL || ValidateHTTPVersion(*version) != 0) {
		//Enviar mensaje error 400 Bad Request
		debug(BADREQUEST, "Error al procesar la petición web", "Versión HTTP incorrecta", descriptorFichero);
	}
	char logmess[200];
	sprintf(logmess, "Se ha recibido una petición HTTP GET del recurso: %s y con versión %s", *recurso, *version);
	debug(LOG, "Peticion recibida", logmess, descriptorFichero);
	return 0;
}


//
// Obtiene la ruta absoluta a un fichero si este es accesible por estar en un directorio legal
// si el fichero está fuera de la jerarquía legal de ficheros envía un mensaje 403 de error
//
char * GetLegalResourcePath(char * recurso, int descriptorFichero) {
	char cwd[PATH_MAX];
	getcwd(cwd, PATH_MAX);
	char auxcwd[PATH_MAX];											//Obtengo la ruta del directorio actual que es la que tiene los recursos
	getcwd(auxcwd, PATH_MAX);
	char * recurso_path = strcat(auxcwd, recurso);					//Obtengo la ruta del recurso juntandolo con la ruta de este directorio
	char absolute_path[PATH_MAX];
	realpath(recurso_path, absolute_path);							//Cambio dicha ruta que puede ser relativa a absoluta 
	char * sal1 = strstr(absolute_path, cwd);
	if (sal1 != NULL && sal1 == absolute_path) {
		return sal1;
	}
	else {
		//Enviar mensaje de error 403 Forbidden
		debug(PROHIBIDO, "Error al tratar la ruta del recurso", "Recurso superior o de acceso ilegal", descriptorFichero);
	}
}

void CheckSupportedFile(char * recurso, int descriptorFichero) {
	char * saveptr3, *extension;
	strtok_r(recurso, ".", &saveptr3);
	extension = strtok_r(NULL, ".", &saveptr3);
	if (extension == NULL) {
		//Enviar mensaje de error 400 Bad Request
		debug(BADREQUEST, "Error en el recurso", "no tiene bien la extension", descriptorFichero);
	}
	int iterador = 0;
	int soportado = 0;
	while (extensions[iterador].ext != 0 && soportado == 0) {
		if (strcmp(extensions[iterador].ext, extension) == 0) {
			soportado = 1;
			strcpy(resourceType, extensions[iterador].filetype);
		}
		else { iterador++; }
	}

	if (soportado != 1) {
		//Devolver un error 415 Unsupported Media Type
		debug(UNSUPPORTED, "Error Tipo de fichero", "Tipo de fichero no soportado", descriptorFichero);
	}
}

void EvaluateHeader(char * header, int descriptorFichero) {
	char * aux;
	char * type = strtok_r(header, ":", &aux);
	char * content = strtok_r(NULL, "\0", &aux);
	if (type == NULL || content == NULL) {
		printf("Error, en strtok_r type NULL\n");
		//Devolver un error 400 Bad Request
		debug(BADREQUEST, "Error Evaluar cabecera","cabecera no sigue el formato",descriptorFichero);
	}	
	if (strcmp(type, "Host") == 0) {
		if (strcmp(content, HostHead) == 0 || strcmp(content, HostHead2) == 0) {
			hostChecked = 1;
		}
		else {
			//Devolver un error 400 Bad Request
			debug(BADREQUEST, "Error al evaluar cabecera", "Host destino incorrecto",descriptorFichero);
		}
	}
	else if (strcmp(type, "Cookie") == 0) {
		char * aux;
		strtok_r(content, "=", &aux);
		if (aux == NULL) debug(BADREQUEST, "Error al evaluar cabecera", "Cookie no sigue bien el formato", descriptorFichero);
		int cookieNum = atoi(aux);
		if (cookieCounter < cookieNum) cookieCounter = cookieNum;
		cookieCounter = cookieCounter+1;
		if (cookieCounter >= 10) {
			char * denegation = "Service denegation: cookie value over 10";
			write(descriptorFichero, denegation, strlen(denegation));
			debug(ERROR,"Denegación de servicios por cookie por encima de 10",aux,descriptorFichero);
		}
	}
	else if (strcmp(type, "Connection") == 0) {
		if (strcmp(content, " close") == 0) connecKeepAlive = 0;
		else if (strcmp(content, " keep-alive") != 0) {
			//Devolver un error 400 Bad Request
			debug(BADREQUEST,"Error Evaluar cabecera","Cabecera connection mal escrita",descriptorFichero);
		}
	}
	else if (strcmp(type, "Keep-Alive") == 0) {
		int reqKeepAlive = atoi(content);
		if (reqKeepAlive == 0) 
			debug(BADREQUEST,"Error Evaluar cabecera","Cabecera keep alive incorrecta o con valor 0",descriptorFichero);
		if (reqKeepAlive < timeAlive) 
			timeAlive = reqKeepAlive;
	}
}

//Una vez creado el socket y la conexión se trata la web request
int process_web_request(int descriptorFichero)
{
	debug(LOG,"request","Ha llegado una peticion",descriptorFichero);

	//
	// Definir buffer y variables necesarias para leer las peticiones
	//
	char buffer[BUFSIZE] = { 0 };
	
	//
	// Leer la petición HTTP
	//
	
	int bytes_leidos = read(descriptorFichero, buffer, BUFSIZE);
	if (bytes_leidos == 0) {
		debug(LOG, "El cliente ha cerrado la conexión", "Cerrando conexión", descriptorFichero);
		return 0;
	}

	//
	// Comprobación de errores de lectura
	//
	if (bytes_leidos == -1) {
		debug(ERROR,"Error al procesar la petioción web", "Lectura de socket",descriptorFichero);
		return -1;
	}
	
	//
	// Si la lectura tiene datos válidos terminar el buffer con un \0
	//

	buffer[BUFSIZE-1] = '\0';
	debug(LOG,"HTTP request: \n",buffer,descriptorFichero);
	
	//
	// Se eliminan los caracteres de retorno de carro y nueva linea
	//

	// --Mis comentarios--
	// Obtengo la que sería la línea de solicitud de la petición HTTP de tipo get
	// Creo un puntero (token) que señalarán a las distintas cabeceras de la petición más adelante
	// El puntero saveptr lo usaré para iterar por las cabeceras
	
	char * cabecera, * token, * saveptr1;
	cabecera = strtok_r(buffer, "\r\n", &saveptr1);
	if (cabecera == NULL) 
		debug(BADREQUEST, "Error al procesar la petición web", "Cabecera nula", descriptorFichero);
	
	//
	//	TRATAR LOS CASOS DE LOS DIFERENTES METODOS QUE SE USAN
	//	(Se soporta solo GET)
	//
	
	char * metodo, * recurso, * version;
	EvaluateRequestLine(cabecera, &metodo, &recurso, &version, descriptorFichero);
	do {
		token = strtok_r(NULL, "\r\n", &saveptr1);
		if (token != NULL) EvaluateHeader(token, descriptorFichero);
	} while (token != NULL); 
	
	if (hostChecked == 0)
		debug(BADREQUEST, "Error en las cabeceras", "El host al que va dirigido el mensaje no ha sido identificado", descriptorFichero);

	//
	//	Como se trata el caso de acceso ilegal a directorios superiores de la
	//	jerarquia de directorios
	//	del sistema
	//
	
	if (strcmp(recurso, "/") == 0 || strcmp(recurso, "") == 0) {				//Compruebo si el recurso pedido es / o cadena vacía y en ese 
		recurso = strcpy(recurso, "/index.html");					//caso decide que el recurso a transmitir es el index 
	}
	
	char * absolute_path = GetLegalResourcePath(recurso, descriptorFichero);
	
	
	//
	//	Como se trata el caso excepcional de la URL que no apunta a ningún fichero
	//	html
	//
	int recursofd = open(absolute_path, O_RDONLY);
	
	if ( recursofd == -1) {
		//Enviar un error 404
		debug(NOENCONTRADO, "Error NOT FOUND enviado", "URL apunta a ningún fichero", descriptorFichero);
	} 
	struct stat stats;
	if (stat(absolute_path, &stats) == 0) resourceSize = stats.st_size;

	//
	//	Evaluar el tipo de fichero que se está solicitando, y actuar en
	//	consecuencia devolviendolo si se soporta u devolviendo el error correspondiente en otro caso
	//

	CheckSupportedFile(recurso, descriptorFichero);
	debug(OK, "enviada respuesta OK", "", descriptorFichero);

	//
	//	En caso de que el fichero sea soportado, exista, etc. se envia el fichero con la cabecera
	//	correspondiente, y el envio del fichero se hace en blockes de un máximo de  8kB
	//

		
	int bytes_enviados = 1;
	while (bytes_enviados > 0) {
		buffer[0] = '\0';
		bytes_enviados = read(recursofd, buffer, BUFSIZE);
		write(descriptorFichero, buffer, BUFSIZE);
	}
	if (bytes_enviados == -1) 
		debug(ERROR, "error de escritura","envio de un recurso",descriptorFichero);
	buffer[0] = '\0';
	actualNumRequest = actualNumRequest + 1;
	if (actualNumRequest == maxNumRequest) {
		actualNumRequest = 0;
		return 2;
	}
	return 1;
}

int main(int argc, char **argv)
{
	int i, port, pid, listenfd, socketfd;											
	socklen_t length;
	static struct sockaddr_in cli_addr;		// static = Inicializado con ceros
	static struct sockaddr_in serv_addr;	// static = Inicializado con ceros
	
	//  Argumentos que se esperan:
	//
	//  argv[1]
	//  En el primer argumento del programa se espera el puerto en el que el servidor escuchara
	//
	//  argv[2]
	//  En el segundo argumento del programa se espera el directorio en el que se encuentran los ficheros del servidor
	//
	//  Verficiar que los argumentos que se pasan al iniciar el programa son los esperados
	//

	//
	//  Verficiar que el directorio escogido es apto. Que no es un directorio del sistema y que se tienen
	//  permisos para ser usado
	//

	if(chdir(argv[2]) == -1){															
		(void)printf("ERROR: No se puede cambiar de directorio %s\n",argv[2]);		
		exit(4);																		
	}
																						
	if(fork() != 0)																		
		return 0;																		

	(void)signal(SIGCHLD, SIG_IGN);														// Ignoramos a los hijos
	(void)signal(SIGHUP, SIG_IGN);														// Ignoramos cuelgues
	
	debug(LOG,"web server starting...", argv[1] ,getpid());								
	
	/* setup the network socket */
	if((listenfd = socket(AF_INET, SOCK_STREAM,0)) <0)									
		debug(ERROR, "system call","socket",0);											
	
	port = atoi(argv[1]);				
	
	if(port < 0 || port >60000)			
		debug(ERROR,"Puerto invalido, prueba un puerto de 1 a 60000",argv[1],0);		
	
																						
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);										/* Escucha en cualquier IP disponible*/
	serv_addr.sin_port = htons(port);													/* ... en el puerto port especificado como parámetro*/
	
	if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0)	
		debug(ERROR,"system call","bind",0);			
	
	if( listen(listenfd,64) <0)															
		debug(ERROR,"system call","listen",0);											
	while(1){																			
		length = sizeof(cli_addr);														
		if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)	
			debug(ERROR,"system call","accept",0);
		if((pid = fork()) < 0) {														
			debug(ERROR,"system call","fork",0);
		}
		else {
			if(pid == 0) { 																
				(void)close(listenfd);
				int retval = 1;
				debug(LOG, "inicio de la sesion", DateHead(), socketfd);
				while (retval) {								// El hijo termina tras llamar a esta función
					if (connecKeepAlive == 0) {
						process_web_request(socketfd);
						debug(LOG, "Connection closed by close type connection", DateHead(), socketfd);
						close(socketfd);
						exit(1);									
					}
					fd_set rfds;
					FD_ZERO(&rfds);
					FD_SET(socketfd, &rfds);
					struct timeval tv;
					tv.tv_sec = timeAlive;
					tv.tv_usec = 0;
					retval = select(socketfd + 1, &rfds, NULL, NULL, &tv);
					if (retval > 0) {
						int resultRequest = process_web_request(socketfd);
						if (resultRequest == 0) {
							debug(LOG, "Connection closed by client", DateHead(), socketfd);
							close(socketfd);
							exit(1);
						} else if (resultRequest == 2) {
							debug(LOG, "Connection closed by max num of request reached", DateHead(), socketfd);
							close(socketfd);
							exit(1);
						}	
					} else if (retval == -1) {
						debug(LOG, "Ha habido un error con select","",socketfd);
					} else
						debug(LOG, "Connection closed for keep alive time finished", DateHead(), socketfd);
				}
				close(socketfd);
				exit(1);
			} else { 																	
				(void)close(socketfd);													
			}
		}
	}
}
