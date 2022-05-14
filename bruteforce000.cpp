/*

***
Here we include all Cryptopp lib imports
***

*/

#include "cryptopp/cryptlib.h"
#include "cryptopp/des.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <math.h>      
#include <mpi.h>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string>

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::CBC_Mode;
using CryptoPP::DES;
using CryptoPP::Exception;
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using CryptoPP::SecByteBlock;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using std::cerr;
using std::cout;
using std::endl;
using std::exit;
using std::ifstream;
using std::string;

/*
***
Many things from this code are imported from:
https://github.com/weidai11/cryptopp
***
*/

string decode(CBC_Mode< DES >::Decryption decryptor, string cipher, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE]){
	string recovered;
	decryptor.SetKeyWithIV(key, 8, iv);
	StringSource s(cipher, true, 
		new StreamTransformationFilter(decryptor,
			new StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING 
		) // StreamTransformationFilter
	); // StringSource


	return recovered;
}

/*
***
Here we validate the key.
It calls the decode function declared above
***
*/

bool validate_key(CBC_Mode< DES >::Decryption decryptor, string cipher, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE]){
	bool is_key = decode(decryptor, cipher, key, iv).find("bubble") != std::string::npos;	
	if(is_key){
	cout << "El mensaje es: " << decode(decryptor, cipher, key, iv) << endl;
	}
	return is_key;
}

int main(int argc, char* argv[]) {
	SecByteBlock key(8);

	CryptoPP::byte iv[DES::BLOCKSIZE] = {0};
	CryptoPP::byte key2[DES::KEYLENGTH] = {255, 255, 10, 0, 0, 0, 0, 0};
	AutoSeededRandomPool prng;

	string readLine;
	/*loop for the file name */
	ifstream file ("message.txt");
	string cipherText;
	if (file.is_open())
	{
		while ( getline (file,readLine) )
		{
			cipherText = readLine;
		}
		file.close();
	}
	else
	{
		cout << "Sorry, the file is broken or something, we cannot open it";
	} 

	string plain = cipherText;
	string cipher, encodedTxt, recovered;

	/*
	***
	We move bit by bit to left on the length of the key
	Also we move like that on the block size
	***
	*/

	encodedTxt.clear();
	StringSource(key2, 8, true,
		new HexEncoder(
			new StringSink(encodedTxt)
		) 
	); 

	/*
	***
	We try to do the encryptation file 
	it should be padded to the block size of the cipher.
	***
	*/

	try
	{
		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key2, 8, iv);

		
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			)     
		); 
	}

	/*
	***
	If we get an error we just catch the exception
	***
	*/

	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*
	***
	Here it prints what we get as key
	***
	*/

	encodedTxt.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encodedTxt)
		) 
	); 


	try
	{
		int N, id;
   
    //limite superior para la llave (hay llaves de 0 hasta 2^56)  
		uint64_t upper = (uint64_t)(pow(2, 56)); 
		uint64_t lowerLimit, upperLimit;
   
    //variables MPI
		MPI_Status st;
		MPI_Request req;
   
		int flag;
   
    //inicializamos y guardamos el size & rank
		MPI_Comm comm = MPI_COMM_WORLD;
		MPI_Init(NULL, NULL);
		MPI_Comm_size(comm, &N);
		MPI_Comm_rank(comm, &id);
   
    //rango por proceso, cantidad de llaves a probar
		long int range_per_node = upper / N;
		
    //limite superior e inferior para cada nodo
    lowerLimit = range_per_node * id;
		upperLimit = range_per_node * (id+1) -1;
		
    //ajustamos el sobrante
    if(id == N-1){
		  upperLimit = upper;
		}

    long found = 0;

    //recibimos señal de si alguien encuentra la llave (llamada non-blocking)
  	MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);
   
    double start_time, end_time;
    start_time = MPI_Wtime();

    //inicializamos modelo de descifrado
		CBC_Mode< DES >::Decryption d;
   
		unsigned char arrayOfByte[8];
		memcpy(arrayOfByte, &lowerLimit, 8);
   
		cout << "Evaluando el thread: " << id << "\n";

		bool is_key = false;
   
    uint64_t next_i = id;

    //ciclo hasta encontrar la llave
		while (!is_key) {
			memcpy(arrayOfByte, &next_i, 8);
      
      //llamada a función que valida cada llave individual
			is_key = validate_key(d, cipher, arrayOfByte, iv);

			if (is_key) {
				found = 15;
				cout << " Se encontro en el thread: " << id << "\n";
        
        end_time = MPI_Wtime();
        
        cout << "TIEMPO: " << end_time - start_time << endl;
        cout << "LLAVE: " << next_i << endl;
        //enviamos a cada nodo que se encontró la llave
				for(int node=0; node<N; node++){
					MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
				}
			}

			MPI_Test(&req, &flag, &st);
      
			if (found) break;
      
      next_i = next_i + 4;
		}

    //finalizamos operación con MPI
		MPI_Finalize();
		return 0;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	return 0;
}
