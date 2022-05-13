#include <stdio.h>
#include <stdlib.h>
#include <math.h>      
#include <mpi.h>
#include <random>
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include <fstream>
using std::ifstream;

/*
***
Here we include all Cryptopp lib imports
***
*/

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

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
	return decode(decryptor, cipher, key, iv).find("bubble") != std::string::npos;	
}

int main(int argc, char* argv[]) {
	SecByteBlock key(8);
	prng.GenerateBlock(key, 8);

	CryptoPP::byte iv[DES::BLOCKSIZE] = {0};
	CryptoPP::byte key2[DES::KEYLENGTH] = {250, 255, 255, 255, 255, 255, 255, 223};
	AutoSeededRandomPool prng;

	string readLine;
	/*loof for the file name */
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
		unsigned char charsToCheck[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};
		int N, id;
		uint64_t upper = (uint64_t)(pow(2, 56)); 
		uint64_t lowerLimit, upperLimit;
		MPI_Status st;
		MPI_Request req;
		int flag;
		int ciphlen = *(&charsToCheck + 1) - charsToCheck;
		MPI_Comm comm = MPI_COMM_WORLD;
		MPI_Init(NULL, NULL);
		MPI_Comm_size(comm, &N);
		MPI_Comm_rank(comm, &id);
		long int range_per_node = upper / N;
  		lowerLimit = range_per_node * id;
  		upperLimit = range_per_node * (id+1) -1;
  		if(id == N-1){
    		upperLimit = upper;
  		}

  		long found = 0;

  		MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);
		// cout << " Something: " << id << " lower: " << lowerLimit << " upper: " << upperLimit << ";";

		CBC_Mode< DES >::Decryption d;
		uint64_t x = 0;
		unsigned char arrayOfByte[8];
		memcpy(arrayOfByte, &lowerLimit, 8);
		cout << "Checking " << id << " " << (int)arrayOfByte[0] << (int)arrayOfByte[1] << (int)arrayOfByte[2] << (int)arrayOfByte[3] << (int)arrayOfByte[4] << (int)arrayOfByte[5] << (int)arrayOfByte[6] << (int)arrayOfByte[7] << "\n";

		bool is_key = false;
		std::default_random_engine generator;
		std::uniform_int_distribution<uint64_t> distribution(lowerLimit, upperLimit);

		while (!is_key) {
			uint64_t rand_i = distribution(generator);  // generates number in the range lowerLimit..upperLimit
			memcpy(arrayOfByte, &rand_i, 8);
			is_key = validate_key(d, cipher, arrayOfByte, iv);

			if (is_key) {
				found = 15;
				cout << "Found " << id << "\n";
				cout << "Checking " << id << " " << (int)arrayOfByte[0] << (int)arrayOfByte[1] << (int)arrayOfByte[2] << (int)arrayOfByte[3] << (int)arrayOfByte[4] << (int)arrayOfByte[5] << (int)arrayOfByte[6] << (int)arrayOfByte[7] << "\n";
				for(int node=0; node<N; node++){
					MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
				}
			}

			MPI_Test(&req, &flag, &st);
			if (found)
				break;
		}

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
