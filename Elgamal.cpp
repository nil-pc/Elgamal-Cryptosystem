#include <stdio.h>
#include <iostream>
#include <cstring>
#include <time.h>
#include <mpir.h>
#include <mpirxx.h>
#include <string>

using namespace std;

#define PRIME_LENGTH 1024

//Initialise a seed for prime number generation
static unsigned long seed = 353;

//Public Key p, g, y
typedef struct
{
	mpz_t p;
	mpz_t g;
	mpz_t y;

} PublicKey;

//Private Key x
typedef struct
{
	mpz_t x;

} PrivateKey;

typedef struct 
{
	mpz_t C1;
	mpz_t C2;
} CipherText;

void randomStateInit(gmp_randstate_t state)
{
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, seed);
}

void generatePrimes(mpz_t prime, gmp_randstate_t state)
{
	//Generate a random number
	mpz_rrandomb(prime, state, PRIME_LENGTH);

        //Check if the number is Prime or not using Miller Rabin Test 
	while (!(mpz_millerrabin(prime, 512)))
	{
		gmp_randclear(state);
		seed++;
		randomStateInit(state);
		mpz_rrandomb(prime, state, PRIME_LENGTH);
	}
	gmp_randclear(state);
	seed++;
}

// Function to generate g, a number between 1 and p-1
void getGenerator(mpz_t g, gmp_randstate_t state, mpz_t p)
{
	mpz_t r, m;
	mpz_inits(r,m, NULL);
        do	
	{
		gmp_randclear(state);
		seed++;
		randomStateInit(state);
		mpz_urandomm(g, state, p);
	        mpz_gcd(r, g, p);
        }while((g == 0) || (mpz_cmp_ui(r,1) != 0));
        mpz_clears(r, m, NULL);
}

//Generate a prime number p and call function to generate g
void generatePublicKey(PublicKey* pubkey, gmp_randstate_t state)
{

	//Generate p
	randomStateInit(state);
	generatePrimes(pubkey->p, state);

	//Generate g
	randomStateInit(state);
	getGenerator(pubkey->g, state, pubkey->p);
}

//Generate value of x
void generatePrivateKey(PrivateKey*privkey, PublicKey* pubkey, gmp_randstate_t state)
{

	gmp_randclear(state);
	seed++;
	randomStateInit(state);
	mpz_urandomm(privkey->x, state, pubkey->p);
}

//Convert char_arr to Int from a string of length 'len'
void decodeText(mpz_t decode,  unsigned char decode_array[], int len)
{
	mpz_import(decode, len, 1, sizeof(decode_array[0]), 0, 0, decode_array);
}

//Convert Int to char_arr
void encodeText(mpz_t encode, unsigned char encode_array[])
{
	mpz_export(encode_array, NULL, 1, sizeof(encode_array[0]), 0, 0, encode);
}

// Encryption Algorithm
void ElgamalEncryption(CipherText* ciphertext, mpz_t plaintext,PublicKey* pubkey, mpz_t r)
{
	cout<<"\n......ENCRYPTION Algorithm Running......";
	mpz_t c, p;
	mpz_inits(c,p, NULL);

	// C1 = (g^r) mod p
	mpz_powm(ciphertext->C1, pubkey->g, r, pubkey->p);
	mpz_powm(c, pubkey->y, r, pubkey->p);
	mpz_mod(p, plaintext, pubkey->p);
        mpz_mul(c, c, p);

        // C2 = (m * (y^r)) mod p
	mpz_mod(ciphertext->C2, c, pubkey->p);

        cout<<"\n\nCipher Text  :\n";
	gmp_printf("C1-value :\n%Zd\n\n", ciphertext->C1);
	gmp_printf("C2-value :\n%Zd\n\n", ciphertext->C2);	
	mpz_clears(c, p, NULL);	
}

// Decryption Algorithm
void ElgamalDecryption(mpz_t message,CipherText*  ciphertext, PrivateKey* privkey, PublicKey* pubkey)
{
	cout<<"\n.......DECRYPTION Algorithm Running......";
	mpz_t c1, c2, m;
	mpz_inits(c1, c2, m, NULL);
	mpz_powm(c1, ciphertext->C1, privkey->x, pubkey->p);
	mpz_invert(c2, c1,pubkey->p);
	mpz_mul(m, ciphertext->C2, c2);

	// m = (C2 * inverse(C1^x)) mod p
	mpz_mod(message, m, pubkey->p);
	mpz_clears(c1, c2, m, NULL);
}

//Function to generate the public key and private key
void keyGeneration(PrivateKey*privKey, PublicKey* pubKey, gmp_randstate_t state)
{
	// Function to generate p and g
	generatePublicKey(pubKey, state);

	// Function to generate a random x to keep as secret key
	generatePrivateKey(privKey, pubKey, state);

        // Calculate value of y from g, x and p
        // y = (g^x) mod p
	mpz_powm(pubKey->y, pubKey->g, privKey->x, pubKey->p);
}

int main()
{
	
	PrivateKey privKey; 
	PublicKey pubKey;
	CipherText ciphertext;
	mpz_t r, plaintext, message;
	mpz_inits(pubKey.g, pubKey.p, pubKey.y, privKey.x, NULL);
	mpz_inits(plaintext, ciphertext.C1, ciphertext.C2, message, r, NULL);
	int exit = 0;
        gmp_randstate_t state;
	string msg, test;
	unsigned long int len;

        cout<<"\n..........ELGAMAL CRYPTOGRAPHIC SYSTEM..........";
	keyGeneration(&privKey, &pubKey, state);
        cout<<"\nPublic Key : \n";
        gmp_printf("p :\n%Zd\n\n", pubKey.p);
        gmp_printf("g :\n%Zd\n\n", pubKey.g);
        gmp_printf("y :\n%Zd\n\n", pubKey.y);

        while(exit != 1)
        {

	  	cout<<"Enter string to encrypt :\n";
		cin>>test;
		len = test.length();

		unsigned char data_array[len] = { 0 };
		unsigned char message_array[len] = { 0 };
		copy(test.begin(), test.end(), data_array);

                cout<<"\nGenerating a random value r : ";
		gmp_randclear(state);
		seed++;
		randomStateInit(state);
		mpz_urandomm(r, state, pubKey.p);
		gmp_printf("\n%Zd\n\n", r);

		decodeText(plaintext, data_array, len);
		gmp_printf("Plaintext Value :\n%Zd\n\n", plaintext);

		ElgamalEncryption(&ciphertext, plaintext, &pubKey, r);

                cout<<"Private Key\n";
		gmp_printf("x :\n%Zd\n\n", privKey.x);

		ElgamalDecryption(message, &ciphertext, &privKey, &pubKey);
		encodeText(message, message_array);

                gmp_printf("\n\nDecrypted Value :\n%Zd\n\n", message);
		cout<<"Decoded Message/Plaintext : ";
		for(int i=0; i<len; ++i)
		{
			cout<<message_array[i];
		}	
		cout<<"\n\nExit (Yes : 1 | No : 0)\n";
		cin>>exit;
    }

    mpz_clears(r, plaintext, message, NULL);
    return 0;
}
