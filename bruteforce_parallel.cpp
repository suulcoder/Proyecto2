/**************************************************************************
                       BRUTEFORCE DECRYPTION USING MPI        

      * Requirements:
        > Install cryptopp
          > Download .zip from https://www.cryptopp.com/
          > Unzip files
          > On terminal, move into directory
          > Execute following commands
            > make
            > make test
            > sudo make install 

      * To compile & run:
        > mpic++ -o <object> -lcryptopp bruteforce.cpp
        > mpirun -np <N> ./<object> <input_file> <keyword> <mode (1|2)>
      
**************************************************************************/

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
using std::ofstream;
using std::string;

/*
***
Many things from this code are imported from:
https://github.com/weidai11/cryptopp
***
*/

string _decipher(CBC_Mode<DES>::Decryption decryptor, string cipher_text, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE]){
	string decipher_text;
  decryptor.SetKeyWithIV(key, 8, iv);
	
  StringSource s(cipher_text, true, new StreamTransformationFilter(decryptor, new StringSink(decipher_text), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING));

	return decipher_text;
}

/*
***
Here we validate the key.
It calls the decode function declared above
***
*/
bool _validate(CBC_Mode<DES>::Decryption decryptor, string cipher_text, CryptoPP::byte key[DES::KEYLENGTH], CryptoPP::byte iv[DES::BLOCKSIZE], string kw){
	string decipher_text = _decipher(decryptor, cipher_text, key, iv); 	
	
  if(decipher_text.find(kw) != std::string::npos){
    cout << endl << "MESSAGE: " << decipher_text << endl;
    return true;
  }
	
  return false;
}

int main(int argc, char* argv[]) {
  int N, id;
  
  //variables MPI
  MPI_Status st;
	MPI_Request req;
   
  //inicializamos y guardamos el size & rank
	MPI_Comm comm = MPI_COMM_WORLD;
	MPI_Init(NULL, NULL);
	MPI_Comm_size(comm, &N);
	MPI_Comm_rank(comm, &id);

  if(argc < 2) {
    if(id == 0) cout << "NO HAY SUFICIENTES ARGUMENTOS" << endl;
    exit(1);
  }
  
  string filename = argv[1];
  string keyword  = argv[2];
  string mode     = argv[3]; //1 for local, 2 for external
  
  if (id == 0) cout << "FILENAME: " << filename << endl;
  if (id == 0) cout << "KEYWORD: " << keyword << endl << endl;

	SecByteBlock key(8);

	CryptoPP::byte iv[DES::BLOCKSIZE] = {0};
	CryptoPP::byte local_key[DES::KEYLENGTH] = {255, 0, 0, 0, 0, 0, 0, 0};
	AutoSeededRandomPool prng;

	string read_line;
 
	/*loop for the file name */
	ifstream file (filename);
	string plain;
 
	if (file.is_open())
	{
		while (getline(file, read_line))
		{
			plain = read_line;
		}
		file.close();
	}
	else
	{
		cout << "No se pudo abrir el archivo";
	} 

	string cipher_text, encoded_text;

	/*
	***
	Agregamos padding a la llave para que cumpla con el tamaño del bloque
	***
	*/
	encoded_text.clear();
	StringSource(local_key, 8, true,
		new HexEncoder(
			new StringSink(encoded_text)
		)
  );
 

  if(mode == "2")
  {
    cipher_text.clear();
	  StringSource(plain, true,
  	  new HexDecoder(
  		  new StringSink(cipher_text)
      ) 
    );
  }
  
  else
  {
	/*
	***
	We try to do the encryption file 
	it should be padded to the block size of the cipher.
	***
	*/

  
	  try
	  {
  		CBC_Mode< DES >::Encryption encryptor;
  		encryptor.SetKeyWithIV(local_key, 8, iv);
  		
  		StringSource(plain, true, 
  			new StreamTransformationFilter(encryptor,
  				new StringSink(cipher_text)
  			)     
  		); 
  	}

	  /*
	  ***
	  Prevencion de errores
	  ***
	  */
  
  	catch(const CryptoPP::Exception& e)
  	{
  		cerr << e.what() << endl;
  		exit(1);
  	}

	  /*
	  ***
	  Convertimos llave a hexadecimal
	  ***
	  */
  
  	encoded_text.clear();
	  StringSource(cipher_text, true,
  		new HexEncoder(
  			new StringSink(encoded_text)
  		) 
  	);
  
    /*
    ***
    Escribe texto cifrado a un archivo de salida
    ***
    */
  
    ofstream ofile ("ciphertext.txt");
    
    ofile << encoded_text;
    
    ofile.close();
  }

	try
	{   
    //limite superior para la llave (hay llaves de 0 hasta 2^56)  
		uint64_t upper = (uint64_t)(pow(2, 56)); 
		uint64_t lower_limit, upper_limit;
   
		int flag;
   
    //rango por proceso, cantidad de llaves a probar
		long int range_per_node = upper / N;
		
    //limite superior e inferior para cada nodo
    lower_limit = range_per_node * id;
		upper_limit = range_per_node * (id + 1) - 1;
		
    //ajustamos el sobrante
    if(id == N - 1){
		  upper_limit = upper;
		}

    
    long found = 0;

    //recibimos señal de si alguien encuentra la llave (llamada non-blocking)
  	MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);
   
    double start_time, end_time;
    start_time = MPI_Wtime();

    //inicializamos modelo de descifrado
		CBC_Mode< DES >::Decryption decryptor;
   
		unsigned char potential_key[8];
		memcpy(potential_key, &lower_limit, 8);
   
		cout << "EVALUANDO P: " << id << endl;

		bool found_key = false;
   
    //inicializamos la primer llave potencial a probar al id del thread
    uint64_t next_i = id;

    //ciclo hasta encontrar la llave
		while (!found_key) {
			memcpy(potential_key, &next_i, 8);
      
      //llamada a función que valida cada llave individual
			found_key = _validate(decryptor, cipher_text, potential_key, iv, keyword);

			if (found_key) {
				found = 1;
				cout << endl << "SE ENCONTRÓ EN P: " << id << endl;
        
        end_time = MPI_Wtime();
        
        cout << endl << "TIEMPO: " << end_time - start_time << endl;
        cout << "LLAVE: " << next_i << endl;
        
        //enviamos a cada nodo que se encontró la llave
				for(int node=0; node < N; node++){
					MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
				}
			}

			MPI_Test(&req, &flag, &st);
      
			if (found) break;
      
      //sumamos N, la cantidad de procesos, para que cada uno vaya evaluando de N en N   
      next_i = next_i + N;
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
