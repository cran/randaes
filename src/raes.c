
/* This file implements the deterministic PRNG part of the
   Fortuna cryptographic PRNG described in "Practical Crytography"
   by Ferguson & Schneier.

   They claim that distinguishing the output from random uniforms in 
   less than 2^113 operations without knowledge of the key
   implies an attack on the underlying block cipher (in this case 
   256-bit AES), or, more likely, a bug in the implementation.

   The random seed returned to R is a 256bit AES key, a 128bit counter,
   and a 16bit reseed counter. set.seed sets the last four bytes of the
   key.

   Fortuna returns 128-bit integers. We use the upper 64 bits to
   create a random U[0,1] and save the lower 64bits for the next request.

/* (c) 2005 R Foundation for Statistical Computing */


#include "aes.h"
#include "R.h"

#define I2to32 2.328306437080797e-10   /* 1/(2^32-1) */
#define I2to64m1 5.421010862427522e-20 /* 1/(2^64-1) */

static aes_context *ctx;

static int leftover;
static unsigned int seed_storage[8+4+1+2];
static unsigned int *key=seed_storage;
static unsigned int *counter;
static unsigned int *reseed_counter;
static unsigned int *buffer;
static const int seedlength=8+4+1+2;

#define INC_COUNTER do{ counter[3]++; \
    if (counter[3]==0) {\
      counter[2]++;\
      if (counter[2]==0){\
	counter[1]++;\
	if (counter[1]==0){\
	  counter[0]++;\
	}\
      }\
    } }while(0)
 

void user_unif_init(unsigned int seed){
  memcpy(key, "This is a very random key(!)", 28);
  key[7]=seed;

  counter=key+8;
  counter[0]=0;
  counter[1]=0;
  counter[2]=0;
  counter[3]=1;
  reseed_counter=counter+4;
  reseed_counter[0]=0;
  buffer=reseed_counter+1;
  buffer[0]=buffer[1]=0;
  if (ctx == 0)
    ctx=malloc(sizeof(*ctx));
  aes_set_key(ctx, (uint8 *) key, 256);
  leftover=0;
}


static void fortuna_generate(int *result){

   unsigned int newkey[8];
   
   if (ctx==NULL)
       error("RAES not initialized");
   reseed_counter[0]++;
   aes_encrypt(ctx, (uint8 *) counter, (uint8 *) result);
   if (reseed_counter[0] > 65535) {
	   /* Rekey after 2^20 bytes of output */
       INC_COUNTER;
       aes_encrypt(ctx, (uint8 *) counter, (uint8 *) newkey);
       INC_COUNTER;
       aes_encrypt(ctx, (uint8 *) counter, (uint8 *) (newkey+4));
       memcpy(key,newkey,32);
       aes_set_key(ctx, (uint8 *) key, 256);
       reseed_counter[0]=0;
   }
   
   INC_COUNTER;
   
   return;
}


double *user_unif_rand(void){
  
  unsigned int output[4];
  static double rval;

  if(!leftover){

    fortuna_generate(output);
 
    /* use 64bits of output to make a double [0,1]
       store the rest for next time */

    rval= ((output[0]* I2to32) + (output[1]* I2to64m1));
    buffer[0] = output[2];
    buffer[1] = output[3];
    leftover=1;
  } else {
    /* use 64bits generated last time around */

    rval=((buffer[0]* I2to32) + (buffer[1]* I2to64m1));
    buffer[0]=0;
    buffer[1]=0;
    leftover=0;
  }
      
 return &rval;

}

void fortuna_ints(int *n, int result[]){

    int i,j,nblocks;

    nblocks= (*n / 4);
    for(i=0; i<nblocks; i++)
	fortuna_generate(result+(4*i));    
    *n=4*nblocks;

    return;
}


int *user_unif_nseed(void){
  return ((int *)(&seedlength));
}

int *user_unif_seedloc(void){
  return ((int *) seed_storage);
}

/* should be called when .Random.seed is changed 
   (but it won't be, because R doesn't work like that)
*/
void user_PutRNGState(void){
  if (ctx==0)
    ctx=malloc(sizeof(*ctx));
  counter=key+8;
  reseed_counter=counter+4;
  buffer=reseed_counter+1;
  aes_set_key(ctx, (uint8 *) key, 256);
}


