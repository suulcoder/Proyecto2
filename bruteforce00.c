#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <tirpc/rpc/des_crypt.h>


#define MAXC 1024
#define KEY  2310089
#define DEFAULT_FILENAME "message.txt"


/*******
DECRYPT

Toma una llave y texto cifrado, para transformarlo
a texto plano. Utiliza funciones de 'des_crypt.h'.

Params
    key (long): llave a utilizar
    ciph (char *): texto cifrado
    len (int): tamaño del texto

Returns
    void: texto plano sobre texto de entrada
*******/
void decrypt(long key, char *ciph, int len){
	long k = 0;

	for(int i=0; i<8; ++i){
		key <<= 1;
		k += (key & (0xFE << i*8));
	}

	des_setparity((char *)&k);
	ecb_crypt((char *)&k, (char *) ciph, 16, DES_DECRYPT);
}


/*******
ENCRYPT

Toma una llave definida y texto plano, para transformarlo
a texto cifrado. Utiliza funciones de 'des_crypt.h'.

Params
    key (long): llave a utilizar
    ciph (char *): texto plano
    len (int): tamaño del texto

Returns
    void: texto cifrado sobre texto de entrada
*******/
void _encrypt(long key, char *ciph, int len){
	long k = 0;

	for(int i=0; i<8; ++i){
		key <<= 1;
		k += (key & (0xFE << i*8));
	}

	des_setparity((char *)&k);
	ecb_crypt((char *)&k, (char *) ciph, 16, DES_ENCRYPT);
}


char search[] = " bubble ";


/*******
TRY KEY

Toma una llave aleatoria y el texto cifrado,
e intenta descifrar el texto utilizando decrypt.

Params
    key (long): llave a probar
    ciph (char *): texto cifrado
    len (int): tamaño del texto cifrado

Returns
    bool: la llave es o no correcta
*******/
int tryKey(long key, char *ciph, int len){
	char temp[len+1];
	memcpy(temp, ciph, len);
	temp[len]=0;

	decrypt(key, temp, len);

	return strstr((char *)temp, search) != NULL;
}


int main(int argc, char *argv[]){
	int N, id;
	long upper = (1L << 56);
	long mylower, myupper;

	MPI_Status st;
	MPI_Request req;

	FILE *file;
	char *buffer = malloc(sizeof(char) * MAXC);
	char *cipher = malloc(sizeof(char) * MAXC);

	file = fopen(DEFAULT_FILENAME, "r");
	if (file == NULL) return -1;

	int i = 0;
	while((buffer[i] = fgetc(file)) != EOF){
		cipher[i] = buffer[i];
		i++;

		if (i + 1 > MAXC) break;
	}

	cipher[i] = '\0';

	free(buffer);

	int ciphlen = strlen(cipher);

	_encrypt(KEY, cipher, ciphlen);

	MPI_Comm comm = MPI_COMM_WORLD;

	MPI_Init(NULL, NULL);
	MPI_Comm_size(comm, &N);
	MPI_Comm_rank(comm, &id);

	long range_per_node = upper / N;

	mylower = range_per_node * id;
	myupper = range_per_node * (id + 1) - 1;

	if(id == N - 1){
		myupper = upper;
	}

	long found = 0;
	int ready = 0;

	MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

	for(long i = mylower; i<myupper; ++i){
		MPI_Test(&req, &ready, MPI_STATUS_IGNORE);

		if(ready) break;

		if(tryKey(i, (char *)cipher, ciphlen)){
			found = i;
			for(int node = 0; node < N; node++){
				MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
			}
			break;
		}
	}

	if(id==0){
		MPI_Wait(&req, &st);
		decrypt(found, (char *)cipher, ciphlen);

		printf("FOUND KEY:\n %li %s\n", found, cipher);
	}

	free(cipher);

	MPI_Finalize();
}
