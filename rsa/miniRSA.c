/*
 * @file    rsa.c
 * @author  작성자 이름 / 학번
 * @date    작성 일자
 * @brief   mini RSA implementation code
 * @details 세부 설명
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "miniRSA.h"

uint p, q, e, d, n;
uint result;
uint pow15 = 32768;//128;//32768;
uint CONS = 46340;//181;//46340;
uint xbit(uint a){ // a가 최소 몇비트로 표현가능한지 리턴
    uint c = 0;
    while(a > 0){
        a >>= 1;
        c++;
    }
    return c;
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
/*
 * @brief     모듈러 덧셈 연산을 하는 함수.
 * @param     uint a     : 피연산자1.
 * @param     uint b     : 피연산자2.
 * @param     byte op    : +, - 연산자.
 * @param     uint n      : 모듈러 값.
 * @return    uint result : 피연산자의 덧셈에 대한 모듈러 연산 값. (a op b) mod n
 * @todo      모듈러 값과 오버플로우 상황을 고려하여 작성한다.
 */
uint ModAdd(uint a, uint b, byte op, uint n) {
    uint t1, t2;
    if(op == '+'){
        t1 = bitmodular(a, n);
        t2 = bitmodular(b, n);
        return (t1 >= n - t2? t1 - (n - t2) : t1 + t2);
        // return (t1 + t2) % n;
    }
    else if(op == '-'){
        t1 = bitmodular(a, n);
        t2 = bitmodular(b, n);
        return (t1 > t2 ? bitmodular(t1 - t2, n) : bitmodular(t2 - t1, n));
    }
    else{
        fprintf(stderr, "ModAdd Error\n");
        exit(-1); 
    }
}

/*
 * @brief      모듈러 곱셈 연산을 하는 함수.
 * @param      uint x       : 피연산자1.
 * @param      uint y       : 피연산자2.
 * @param      uint n       : 모듈러 값.
 * @return     uint result  : 피연산자의 곱셈에 대한 모듈러 연산 값. (a x b) mod n
 * @todo       모듈러 값과 오버플로우 상황을 고려하여 작성한다.
 */
uint ModMul(uint x, uint y, uint n) {
    uint t1, t2;
    t1 = x  ;
    t2 = y;// % n;
    //printf("%u X %u mod %u = %u\n",t1, t2, n , (t1 * t2) % n);
    // return (t1 * t2) % n;
    uint r = 0;
    while(t2 > 0){
        if((t2 & 1) == 1){
            r = ModAdd(r, t1, '+', n);
        }
        t1 = ModAdd(t1, t1, '+', n);
        t2 >>= 1;
    }
    
    return r;//%n;
}

/*
 * @brief      모듈러 거듭제곱 연산을 하는 함수.
 * @param      uint base   : 피연산자1.
 * @param      uint exp    : 피연산자2.
 * @param      uint n      : 모듈러 값.
 * @return     uint result : 피연산자의 연산에 대한 모듈러 연산 값. (base ^ exp) mod n
 * @todo       모듈러 값과 오버플로우 상황을 고려하여 작성한다.
               'square and multiply' 알고리즘을 사용하여 작성한다.
 */
uint ModPow(uint base, uint exp, uint n) {
    //printf("%u ^ %u mod %u",base, exp, n);
    
    uint x = xbit(exp); //exp 가 몇 비트인지 검사
    uint k = 0;
    uint result = 1;
    uint sq = base;
    uint tmp;
    while(k < x){ // 비트 수만큼 반복
        if((exp & 1) == 1){ // 최우측비트가 1이면 
            if(k == 0){ // 첫번째 시행인 경우에는 result 에 (현재거듭제곱값 * 1) % n 을 multiply 하고 현재거듭제곱값을 update
                tmp = ModMul(sq,1,n);
                result = ModMul(result, tmp, n);
                sq = tmp;
            }
            else { // result 에 (현재거듭제곱값*현재거듭제곱값) % n 을 multiply 하고 현재거듭제곱값을 update
                tmp = ModMul(sq,sq,n);
                result = ModMul(result, tmp, n);
                sq = tmp;
            }
        }
        else{ // 최우측비트가 0이면 현재거듭제곱값만 update
            if(k == 0){ 
                sq = ModMul(sq,1,n);
            }else{
                sq = ModMul(sq,sq,n);
            }
        }
        //result = result % n;
        //printf(" result :  %u , temp : %u\n",result, sq);
        exp >>= 1; // 우측으로 비트시프트
        k++; // 카운트 증가
    }    
    //printf(" = %u\n",result%n);
    return result;
    
}


/*
 * @brief      입력된 수가 소수인지 입력된 횟수만큼 반복하여 검증하는 함수.
 * @param      uint testNum   : 임의 생성된 홀수.
 * @param      uint repeat    : 판단함수의 반복횟수.
 * @return     uint result    : 판단 결과에 따른 TRUE, FALSE 값.
 * @todo       Miller-Rabin 소수 판별법과 같은 확률적인 방법을 사용하여,
               이론적으로 4N(99.99%) 이상 되는 값을 선택하도록 한다. 
2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 
101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 
199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 
317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 
443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541
 */
bool IsPrime(uint testNum, uint repeat) {

    if(repeat == 4) return TRUE; //4번 반복했다면 소수

    uint list[4] = {2,3,5,7}; // 검사해볼 밑 배열
    uint n = testNum;

    if (n <= 1) // 1보다 작을경우 소수가 아니다.
        return FALSE;
    if( n == 2 || n == 3 || n == 5 ||n == 7) // 2,3,5,7일경우는 소수이다.
        return TRUE;
    if((n & 1) == 0) // 짝수일경우 홀수가 아니다.
        return FALSE;
    
    uint d = n - 1; // 짝수 d
    uint s = 0;
    while((d & 1) == 0){ // n - 1 = d * 2^s // 2로나눠서 나머지가 0이면
        //printf("%u - 1 = %u X 2^%u\n",testNum, d, s);
        if(ModPow(list[repeat],d,n) == n - 1){ 
            return IsPrime(n, repeat + 1);;
        }
        d >>= 1;
        s++;        
    }
    uint fin = ModPow(list[repeat],d,n);
    if(fin == 1 || fin == n - 1){
        return IsPrime(testNum, repeat + 1);;
    }
    return FALSE;
}

/*
 * @brief       모듈러 역 값을 계산하는 함수.
 * @param       uint a      : 피연산자1.
 * @param       uint m      : 모듈러 값.
 * @return      uint result : 피연산자의 모듈러 역수 값.
 * @todo        확장 유클리드 알고리즘을 사용하여 작성하도록 한다.
 */
uint ModInv(uint a, uint m) {

    uint x1, x2, y1, y2, r, q, tmp, mod, n;

    x1 = 1, y1 = 0, r = a;
    x2 = 0, y2 = 1; mod = m;
    printf("%10u  %10u  %10u    \n",x1, y1, r);  
    printf("%10u  %10u  %10u    \n",x2, y2, mod);  
    while(r != 1 && mod != 0){
        n = mod;
        q = r / mod;

        tmp = mod;
        mod = r % mod;
        r = tmp;
        
        tmp = x2;
        // x2 = ModAdd(x1, ModMul(x2, q, m), '-', m);
        if(x1 - (x2 * q) > 0){
            x2 = x1 - (x2 * q);
        }else{
            x2 = (x2 * q) - x1;
        }
        x1 = tmp;
        
        tmp = y2;
        // y2 = ModAdd(y1 , ModMul(y2, q, m), '-', m);
        if(y1 - (y2 * q) > 0){ 
            y2 = y1 - (y2 * q);
        }else{
            y2 = (y2 * q) - y1;
        }
        y1 = tmp;

        printf("%10u  %10u  %10u  %10u\n",x2, y2, mod, q);        
    }

    return bitmodular(x1 + m, m);
}
uint GCD(uint a, uint b) {
    uint prev_a;

    while(b != 0) {
        //printf("GCD(%u, %u)\n", a, b);
        prev_a = a;
        a = b;
        while(prev_a >= b) prev_a -= b;
        b = prev_a;
    }
    //printf("GCD(%u, %u)\n\n", a, b);
    return a;
}
/*
 * @brief     RSA 키를 생성하는 함수.
 * @param     uint *p   : 소수 p.
 * @param     uint *q   : 소수 q.
 * @param     uint *e   : 공개키 값.
 * @param     uint *d   : 개인키 값.
 * @param     uint *n   : 모듈러 n 값.
 * @return    void
 * @todo      과제 안내 문서의 제한사항을 참고하여 작성한다.
 */
void miniRSAKeygen(uint *p, uint *q, uint *e, uint *d, uint *n) {


    // 1 < r1 < root(2) 
    // 1 < r2 < root(2) 이므로
    // 1 < r1*r2 < 2
    // 2^31 < 2*(2^15*r1)*(2^15*r2) < 2^32
    // 2^31 < (rand1)*(rand2) < 2^32

    double r1 = WELLRNG512a()+1;
    double r2 = WELLRNG512a()+1;
    while(r1 > 1.41421356237 || r2 > 1.41421356237){ // 1 < r1, r2 < root(2) 까지 반복
    
        r1 = WELLRNG512a()+1;
        r2 = WELLRNG512a()+1; 
    }
    uint rand1 = (r1*CONS);  // rand1 = r1 X 2^15 * root(2)
    uint rand2 = (r2*CONS);  // rand2 = r2 X 2^15 * root(2)
     
    //printf("r1 : %f, r2 : %f, rand1 : %u, rand2 : %u \n",r1,r2,rand1,rand2);
    while(!IsPrime(rand1,0)){ // 소수인지 검사하고 아니면 1증가
        rand1++;
    }
    while(!IsPrime(rand2,0)){ // 소수인지 검사하고 아니면 1증가
        rand2++;
    }
    //printf("r1 : %f, r2 : %f, rand1 : %u, rand2 : %u \n",r1,r2,rand1,rand2);
    //rand1 = 64553;//54623; //47;//
    //rand2 = 62401;//62189; //59;//
    
    uint N = rand1 * rand2;
    if(N > 4294967295) miniRSAKeygen(p, q, e, d, n); //두 소수의 곱이 2^32를 초과 할경우 다시 키 생성
//      p : 64553
//  q : 62401
//  e : 4028044699
//  d : 1368224403
//  N : 4028171753
    
    uint Euler = (rand1-1)*(rand2-1);
    uint being_e = Euler - 100; 
    while(GCD(Euler,being_e) != 1){ 
        being_e--;
    }
    //being_e = 3152570619; //17;//
    uint being_d = ModInv(being_e, Euler);

    memcpy(p,&rand1,sizeof(uint));
    memcpy(q,&rand2,sizeof(uint));
    memcpy(n,&N,sizeof(uint));
    memcpy(e,&being_e,sizeof(uint));
    memcpy(d,&being_d,sizeof(uint));
    
    
}

/*
 * @brief     RSA 암복호화를 진행하는 함수.
 * @param     uint data   : 키 값.
 * @param     uint key    : 키 값.
 * @param     uint n      : 모듈러 n 값.
 * @return    uint result : 암복호화에 결과값
 * @todo      과제 안내 문서의 제한사항을 참고하여 작성한다.
 */
uint miniRSA(uint data, uint key, uint n) {
    uint result = ModPow(data,key,n);
    return result;
}



int main(int argc, char* argv[]) {
    byte plain_text[4] = {0x12, 0x34, 0x56, 0x78};
    uint plain_data, encrpyted_data, decrpyted_data;
    uint seed = time(NULL);

    memcpy(&plain_data, plain_text, 4); // 0x78563412 = 2018915346 
    
    //난수 생성기 시드값 설정
    seed = time(NULL);
    InitWELLRNG512a(&seed);

    // RSA 키 생성
    miniRSAKeygen(&p, &q, &e, &d, &n);
    printf("0. Key generation is Success!\n ");
    printf("p : %u\n q : %u\n e : %u\n d : %u\n N : %u\n\n", p, q, e, d, n);


    // uint ep,eq,ee,ed,en, einput = 88;    
    // ep = 54623, eq = 62189, ee = 3152570619, ed = 3028275219, en = 3396949747;
    // encrpyted_data = miniRSA(einput, 7, 187);
    // decrpyted_data = miniRSA(encrpyted_data, 23, 187);
    //  printf("TEST : %u\n", einput); 
    //  printf("TEST : %u\n\n", encrpyted_data);
    //  printf("TEST : %u\n\n", decrpyted_data);
    // 소수인지 테스트
    // uint c = 100, k = 0, pp = 0;
    //     while(k<500){
    //     if(IsPrime(c,0)){
    //         printf("%3d, ",c);
    //         pp++;
            
    //     }else{
    //         //printf("%d IS NOT PRIME\n",c);
    //     }
    //     if(pp % 20 == 0) printf("\n");
    //     k++;
    //     c++;
    // }
    //printf("@VV  %u \n",ModInv(3152570619,54622 * 62188));
    
    // RSA 암호화 테스트
    encrpyted_data = miniRSA(plain_data, e, n);
    printf("1. plain text : %u\n", plain_data);    
    printf("2. encrypted plain text : %u\n\n", encrpyted_data);

    // RSA 복호화 테스트
    decrpyted_data = miniRSA(encrpyted_data, d, n);
    printf("3. cipher text : %u\n", encrpyted_data);
    printf("4. Decrypted plain text : %u\n\n", decrpyted_data);

    // 결과 출력
    printf("RSA Decryption: %s\n", (decrpyted_data == plain_data) ? "SUCCESS!" : "FAILURE!");

    return 0;
}
