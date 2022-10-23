/* This program is used to measure the encryption speed of stream cipher HC-256 for a 256-bit key and a 256-bit IV
  
   The document of HC-256 is available at:
   1) Hongjun Wu. ``A New Stream Cipher HC-256.'' Fast Software Encryption -- FSE 2004, LNCS 3017, pp. 226-244, Springer-Verlag 2004.
   2) eSTREAM website:  http://www.ecrypt.eu.org/stream/hcp3.html

   -----------------------------------
   The encryption speed is measured by repeatedly encrypting a 64-byte buffer.

   -----------------------------------
   Written by: Hongjun Wu
   Last Modified: December 15, 2009
*/

#include <stdio.h>
#include <time.h>

#include "hc256_opt32.h"
//#include "hc256_ref.h"

int main() 
{
      unsigned char key[32],iv[32];
      unsigned char message[1024],ciphertext[1024];
      unsigned long long msglength;
      HC256_State state;

      unsigned long i;
    
      clock_t start, finish;
      double duration, speed;
   

      /*set the value of the key and iv*/
      for (i = 0; i < 32; i++) {key[i] = 0; iv[i] = 0;}
      /*key[0] = 0x55;*/

      /*initialize the message*/
      for (i = 0; i < 1024; i++) message[i] = 0;

      /*key and iv setup*/
      Initialization(&state,key,iv);

      /*mesure the encryption speed by encrypting a 64-byte message repeatedly for 2*0x4000000 times*/
      
      msglength = 64;

      start = clock();
      for (i = 0; i < 0x4000000; i++)  {
            EncryptMessage(&state,message,ciphertext,msglength);
            EncryptMessage(&state,ciphertext,message,msglength);
      } 
      finish = clock();

      /*compute the speed*/
      duration = ((double)(finish - start))/ CLOCKS_PER_SEC;
      speed = duration*3.20*1000*1000*1000/(((double)i)*2*msglength); /* 3.20*1000*1000*1000 indicates a 3.20GHz CPU */

      /*print out the speed*/
      printf("\n\nThe encryption takes %4.4f seconds.\nThe encryption speed is %3.4f cycles/byte \n",duration,speed);

      /*print out part of the contents of message 
        It is to prevent the over-optimization of compiler so as to 
        ensure that the above cipher computation must be computed*/
      printf("\nPart of the message after being repeatedly encrypted: \n");
      for (i = 0; i < 16; i++)  printf("%x%x",message[i] >> 4, message[i] & 0xf);
      printf("\n");

      return (0);
}

