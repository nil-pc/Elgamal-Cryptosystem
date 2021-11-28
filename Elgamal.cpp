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

void generateModularPowers(mpz_t m, mpz_t g, mpz_t p)
{
	mpz_t *mod_array;
	mpz_t i, j, k, q;
	mpz_inits(i, j, k, m, q, NULL);
    mod_array = (mpz_t *) malloc(q * sizeof(mpz_t));
    mpz_set_ui(m , 0);
    mpz_set_ui(i,1);
	while(mpz_cmp(i, p) < 0);
	{
        // k = (g^i)mod p
        mpz_powm(k, g, i, p);
        mpz_set_ui(j,0);
        mpz_sub_ui(q, i, 1);
        while(mpz_cmp(j,q) < 0)
		{
             if(mpz_cmp(k, mod_array[j]) != 0)
             {
             	mpz_add_ui(m, m, 1);
             }
             else
             	break;
             mpz_add_ui(j, j, 1);
		}
		if(mpz_cmp(m, q) == 0)
		{
			mpz_set(mod_array[q], k);
			mpz_add_ui(i, i, 1);
		}
		else
		{
			break;
		}
	}
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
        if(mpz_cmp_ui(r,1) == 0)
        {
        	generateModularPowers(m, g, p);
        }
        else
        {
        	mpz_set_ui(m, 0);
        }
        gmp_printf("m-value:\n%Zd\n\n", m);
        mpz_sub_ui(q, p , 1);
	}while((g == 0) || ((mpz_cmp(m,q) < 0)))
}

//Generate a prime number p
void generatePublicKey(gmp_randstate_t state, mpz_t p, mpz_t g)
{
	mpz_inits(p, g, NULL);
	randomStateInit(state);

	//Generate p
	generatePrimes(p, state);
	gmp_printf("p-value:\n%Zd\n\n", p);
	randomStateInit(state);

	//Generate g
	getGenerator(g, state, p);
	gmp_printf("g-value:\n%Zd\n\n", g);

}

//Function to generate the public key and private key
void keyGeneration(PrivateKey*privKey, PublicKey* pubKey)
{		
	gmp_randstate_t state;
	generatePublicKey(state, p, g);
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
