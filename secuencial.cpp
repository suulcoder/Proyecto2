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
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <chrono>
#include <iostream>
#include <iomanip>
using namespace std::chrono;

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
	//cout << "el mensaje cifrado es: " << cipher << endl;
	//cout << "El mensaje es: " << decode(decryptor, cipher, key, iv) << endl;
	}
	return is_key;
}

int main(int argc, char* argv[]) {
	SecByteBlock key(8);

	CryptoPP::byte iv[DES::BLOCKSIZE] = {0};
	CryptoPP::byte key2[DES::KEYLENGTH] = {1, 0, 0, 0, 0, 0, 0, 0};
	AutoSeededRandomPool prng;

	string readLine;
	/*loop for the file name */
	string filename = "message.txt";
	if (argv[1]!=NULL){
		filename = argv[1];
	}

	cout << "Se procede a abrir el archivo " << filename << endl;
	ifstream file (filename);
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
		cout << "No se puede abrir el archivo" << endl;
		return 0;
	} 

	if(cipherText.length() == 0){
		cout << "Hay algo mal con el archivo";
		return 0;
	}
	else {
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
		Here it prints what we get as key
		***
		*/

		try
		{
			// cout << "plain text: " << plain << endl;

			CBC_Mode< DES >::Encryption e;
			e.SetKeyWithIV(key2, 8, iv);

			// The StreamTransformationFilter adds padding
			//  as required. ECB and CBC Mode must be padded
			//  to the block size of the cipher.
			StringSource(plain, true, 
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter      
			); // StringSource
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
			exit(1);
		}

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
			uint64_t _lower_limit, _upper_limit;

		// secuencial
			auto initial_seq_time = high_resolution_clock::now();
			CBC_Mode< DES >::Decryption dd;

			unsigned char _byteArray[8];
			memcpy(_byteArray, &_lower_limit, 8);
			for (uint64_t i = _lower_limit; i < _upper_limit; i++)
			{
				memcpy(_byteArray, &i, 8);
				bool is_key = validate_key(dd, cipher, _byteArray, iv);

				if (is_key) {
					break;
				}
			}

			auto final_seq_time = high_resolution_clock::now();
			auto seq_time = (final_seq_time - initial_seq_time);
			cout << "Tiempo Secuencial: " << seq_time.count() << " milisegundos" << endl;
		
			return 0;
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
			exit(1);
		}

		return 0;
	}
}
