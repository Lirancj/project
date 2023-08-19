#include <stdio.h>
#include <stdlib.h>

int main() {
        int *v;
        int num_elements;

        num_elements = 100000000;

   v = (int*)calloc(num_elements, sizeof(short));

   // Try to add more elements than the vector can hold
   for (int i = 0; i < num_elements; i++) {
      v[i]=i*328;
   }
   return 0;
}