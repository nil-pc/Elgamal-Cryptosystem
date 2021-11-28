#include <stdio.h>
#include <iostream>
#include <cstring>
#include <time.h>
#include <mpir.h>
#include <mpirxx.h>

using namespace std;

#define PRIME_LENGTH 1024

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

//Generate a prime number p
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

//Function to generate the public key and private key
void keyGeneration(PrivateKey*privKey, PublicKey* pubKey)
{		
	gmp_randstate_t state;
	generatePublicKey(pubKey, state);
	generatePrivateKey(privKey, pubKey, state);

	mpz_powm(pubKey->y, pubKey->g, privKey->x, pubKey->p);
}

int main()
{
	
	PrivateKey privKey; PublicKey pubKey;
	mpz_inits(pubKey.g, pubKey.p, privKey.x, NULL);
	mpz_inits(plaintext, ciphertext, message, m, NULL);
	//double time_diff = 0, t1, t2;

	//Consider the following string for encryption
	string test = "4getgt0fs947lWgfPha15Cs61r6xyjiFP6Gg4WFO3w9H0v15crwdp7dW9Tqu2L4IrCm6b8xjOLXLe1UO2Pv9j2jmi5634g20b0uZT0K6X6zSLAd3p2GCAa5j6VbUqPQq";
	
	unsigned char data_array[128] = { 0 };
	unsigned char message_array[128] = { 0 };
	copy(test.begin(), test.end(), data_array);

	keyGeneration(&privKey, &pubKey);

	return 0;
}
