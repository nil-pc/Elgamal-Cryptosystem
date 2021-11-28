#include <stdio.h>
#include <iostream>
#include <cstring>
#include <time.h>
#include <mpir.h>
#include <mpirxx.h>

using namespace std;

#define PRIME_LENGTH 512

mpz_t message, plaintext, ciphertext, p, g,y,x, m;
mpz_t c1, c2;

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

void getGenerator(mpz_t g, gmp_randstate_t state, mpz_t p)
{
	mpz_t r, m, q;
	mpz_inits(r,m,q, NULL);
    do	
	{
		gmp_randclear(state);
		seed++;
		randomStateInit(state);
		mpz_urandomm(g, state, p);
	    mpz_gcd(r, g, p);
	    gmp_printf("g-value:\n%Zd\n\n", g);
        gmp_printf("r-value:\n%Zd\n\n", r);
    }while((g == 0) || (mpz_cmp_ui(r,1) != 0));
}


//Generate a prime number p and generator g
void generatePublicKey(PublicKey* pubkey, gmp_randstate_t state)
{

	//Generate p
	randomStateInit(state);
	generatePrimes(pubkey->p, state);
	gmp_printf("p-value:\n%Zd\n\n", pubkey->p);

	//Generate g
	randomStateInit(state);
	getGenerator(pubkey->g, state, pubkey->p);
	gmp_printf("g-value:\n%Zd\n\n", pubkey->g);
}

//Generate value of x
void generatePrivateKey(PrivateKey*privkey, PublicKey* pubkey, gmp_randstate_t state)
{

	gmp_randclear(state);
	seed++;
	randomStateInit(state);
	mpz_urandomm(privkey->x, state, pubkey->p);
	gmp_printf("PrivateKey:%Zd\n\n", privkey->x);
}

void decodeText(mpz_t decode,  unsigned char decode_array[])
{
	mpz_import(decode, 128, 1, sizeof(decode_array[0]), 0, 0, decode_array);
}

void ElgamalEncryption(CipherText* ciphertext, mpz_t plaintext,PublicKey* pubkey, mpz_t r)
{
	mpz_t c;
	mpz_inits(c);
	mpz_powm(ciphertext->C1, pubkey->g, r, pubkey->p);
	mpz_powm(c, pubkey->y, r, pubkey->p);
	mpz_mul(c, c, plaintext);
	mpz_mod(ciphertext->C2, c, pubkey->p);

	gmp_printf("C1-value:\n%Zd\n\n", ciphertext->C1);
	gmp_printf("C2-value:\n%Zd\n\n", ciphertext->C2);		
}

void ElgamalDecryption(mpz_t message,CipherText*  ciphertext, PrivateKey* privkey, PublicKey* pubkey)
{
	mpz_t c1, c2, m;
	mpz_inits(c1, c2, m, NULL);
	mpz_powm(c1, ciphertext->C1, privkey->x, pubkey->p);
	mpz_invert(c2, c1,pubkey->p);
	mpz_mul(m, ciphertext->C2, c2);
	mpz_mod(message, m, pubkey->p);
	gmp_printf("m-value:\n%Zd\n\n", message);
}

//Convert INT Array to string
void encodeText(mpz_t encode, unsigned char encode_array[])
{
	mpz_export(encode_array, NULL, 1, sizeof(encode_array[0]), 0, 0, encode);
}

//Function to generate the public key and private key
void keyGeneration(PrivateKey*privKey, PublicKey* pubKey, gmp_randstate_t state)
{		
	generatePublicKey(pubKey, state);
	generatePrivateKey(privKey, pubKey, state);
	mpz_powm(pubKey->y, pubKey->g, privKey->x, pubKey->p);
	gmp_printf("y-value%Zd\n\n", pubKey->y);
}

int main()
{
	
	PrivateKey privKey; PublicKey pubKey;
	CipherText ciphertext;
	mpz_t r;
	mpz_inits(pubKey.g, pubKey.p, pubKey.y, privKey.x, NULL);
	mpz_inits(plaintext, ciphertext.C1, ciphertext.C2, message, r, NULL);
	int exit = 0;
        gmp_randstate_t state;

	//Consider the following string for encryption
	string test = "4getgt0fs947lWgfPha15Cs61r6xyjiFP6Gg4WFO3w9H0v15crwdp7dW9Tqu2L4IrCm6b8xjOLXLe1UO2Pv9j2jmi5634g20b0uZT0K6X6zSLAd3p2GCAa5j6VbUqPQq";
	
	keyGeneration(&privKey, &pubKey, state);

    while(exit != 1)
    {

	  	cout<<"Enter string to encrypt :\n"<<test<<"\n";
		unsigned char data_array[256] = { 0 };
		unsigned char message_array[256] = { 0 };
		copy(test.begin(), test.end(), data_array);

		gmp_randclear(state);
		seed++;
		randomStateInit(state);
		mpz_urandomm(r, state, pubKey.p);
		gmp_printf("Random value r:\n%Zd\n\n", r);

		decodeText(plaintext, data_array);
		gmp_printf("Plaintext Value :\n%Zd\n\n", plaintext);
		ElgamalEncryption(&ciphertext, plaintext, &pubKey, r);

		cout<<"Decryption : ";

		ElgamalDecryption(message, &ciphertext, &privKey,&pubKey);
		encodeText(message, message_array);
		cout<<message_array;
		cout<<"\nExit (Yes : 1 | No : 0)\n";
    }
	return 0;
}
