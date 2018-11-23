#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned int uint;

uint xbit(uint a){ // a가 최소 몇비트로 표현가능한지 리턴
    uint c = 0;
    while(a > 0){
        a >>= 1;
        c++;
    }
    return c;
}
uint bitdivide(uint a, uint b){
    // a / b
    uint c = 0;
    while(a > b){
        a = a - b;
        c++;
    }

    return c;
}


uint bitminus(uint a, uint b){
    //a - b
    uint x = xbit(a);
    uint u;
    uint d;
    uint tmp;
    uint res = 0;
    uint result = 0;
    // uint tmp[10];
    // memset(tmp, 9, 10);
    uint k = x;
    // uint i = 9;
    while(k--){
        u = a & 1;
        d = b & 1;
        if(u == 0 && d == 1){
            uint copy_a = a;
            while((copy_a >>= 1) & 1)
            a = ~a;
        }
        tmp = u ^ d;
        res <<= 1;
        if(tmp == 1){
            res = res | 1;
        }
        a >>= 1;
        b >>= 1;
    }
    // for(i = 0; i < 10; i++){
         printf("@@@%u ",res);
    // }
    k = x;
    while(k--){
        tmp = res & 1;
        result <<= 1;
        if(tmp == 1){
            result = result | 1;
        }
        res >>= 1;
        
    }

    printf("@@@%u ",result);
    printf("\n");
    return 10001;
}

uint bitmodular(uint a, uint b){
    // a % b
    uint c = 0;
    while(a > b){
        a = a - b;
        c++;
    }

    return a;
}

int main(){
    uint a = 134;
    uint b = 21;
    
    printf("%d\n",bitminus(a,b));
    printf("%d\n",a/b);
    printf("%d\n",bitdivide(a,b));
    printf("%d\n",a/b);
    printf("%d\n",bitmodular(a,b));
    printf("%d\n",a%b);
}