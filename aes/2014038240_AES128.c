/*  ======================================================================== *

                                    주 의 사 항


    1. 구현은 다양한 방식으로 이뤄질 수 있음
    2. AES128(...) 함수의 호출과 리턴이 여러번 반복되더라도 메모리 누수가 생기지 않게 함
    3. AddRoundKey 함수를 구현할 때에도 파라미터 rKey는 사전에 선언된 지역 배열을 가리키도록 해야 함
       (정확한 구현을 위해서는 포인터 개념의 이해가 필요함)
    4. 배열의 인덱스 계산시 아래에 정의된 KEY_SIZE, ROUNDKEY_SIZE, STATE_SIZE를 이용해야 함
       (상수 그대로 사용하면 안됨. 예로, 4, 16는 안되고 KEY_SIZE/4, STATE_SIZE로 사용해야 함)

 *  ======================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "2014038240_AES128.h"

#define KEY_SIZE 32
#define ROUNDKEY_SIZE 240
#define STATE_SIZE 16

/* 기타 필요한 전역 변수 추가 선언 */

static const BYTE FSb[256] = //Forward S-box
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16     
};
static const BYTE RSb[256] = //Reverse S-box
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};
/* 기타 필요한 함수 추가 선언 및 정의 */
BYTE bitshift(BYTE x, int mode){ // 좌측으로 한칸 비트시프트 수행함수
      
    switch(mode){
        case 1:
            return x;
        case 2:
            if(x & 0x80) return x << 1 ^ 0x1b; // 첫비트가 1일 경우 시프트 수행 후 00011011 과 XOR
            else return x << 1;
        case 3:
            return bitshift(x, 2) ^ x;
        case 4:
            return bitshift(bitshift(x, 2), 2);
        case 8:
            return bitshift(bitshift(x, 4), 2);
        case 9:
            return bitshift(x, 8) ^ x;
        case 0x0B:
            return bitshift(x, 8) ^ bitshift(x, 2) ^ x; 
        case 0x0D:
            return bitshift(x, 8) ^ bitshift(x, 4) ^ x; 
        case 0x0E:
            return bitshift(x, 8) ^ bitshift(x, 4) ^ bitshift(x, 2); 
        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
}

/*  <키스케줄링 함수>
 *   
 *  key         키스케줄링을 수행할 16바이트 키
 *  roundKey    키스케줄링의 결과인 176바이트 라운드키가 담길 공간
 */
void expandKey(BYTE *key, BYTE *roundKey){

    /* 추가 구현 */
    BYTE temp[KEY_SIZE/4]; // 이전블럭의 4바이트 임시 저장 변수
    BYTE p; // Rot를 위한 임시 저장 변수
    BYTE Rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36}; // 라운드 상수

    for (int i = 0; i < ROUNDKEY_SIZE/4; i++){
        for (int j = 0; j < KEY_SIZE/4; j++){
            if(i < 4) roundKey[i*4+j] = key[i*4+j];
            else {
                if(j == 0) {
                    memcpy(temp, &roundKey[(i-1)*4], sizeof(BYTE)*KEY_SIZE/4);
                    p = FSb[temp[0]];
                }
                if(i % 4 == 0){
                    if(j < 3) temp[j] = FSb[temp[j+1]];
                    if(j == 0) temp[0] ^= Rcon[i/4];
                    if(j == 3) temp[3] = p;
                }
                roundKey[i*4+j] = roundKey[(i-4)*4+j] ^ temp[j];
            }
        }
     }
    /*
    printf(" - ROUND KEYS : ");
        for(int i = 0; i < ROUNDKEY_SIZE; i++) { //#64
            if(i % 16 == 0) printf("\n");
                printf("%02x ", roundkey[i]);
        }
        printf("\n");
    */
}



/*  <SubBytes 함수>
 *   
 *  state   SubBytes 수행할 16바이트 state. 수행 결과는 해당 배열에 바로 반영
 *  mode    SubBytes 수행 모드
 */
 BYTE* subBytes(BYTE *state, int mode){

    /* 필요하다 생각하면 추가 선언 */

    switch(mode){

        case ENC:
            
            /* 추가 구현 */
            for(int i = 0; i < STATE_SIZE; i++){
                state[i] = FSb[state[i]];
            }
            break;

        case DEC:

            /* 추가 구현 */
            for(int i = 0; i < STATE_SIZE; i++){
                state[i] = RSb[state[i]];
            }
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return state;
}


/*  <ShiftRows 함수>
 *   
 *  state   ShiftRows 수행할 16바이트 state. 수행 결과는 해당 배열에 바로 반영
 *  mode    ShiftRows 수행 모드
 */
BYTE* shiftRows(BYTE *state, int mode){ 

    /* 필요하다 생각하면 추가 선언 */   

    switch(mode){

        case ENC:
            
            /* 추가 구현 */
            for(int i = 0; i < STATE_SIZE/4; i++){
                BYTE temp[STATE_SIZE/4];
                memcpy(temp, &state[i*4], sizeof(BYTE)*STATE_SIZE/4);
                for(int j = 0; j < STATE_SIZE/4; j++){
                    state[i*4+j] = temp[(j+i)%4]; //row만큼 우측으로이동시킨다. 모듈러로 인덱스 오버 해결
                }
            }
            break;

        case DEC:

            /* 추가 구현 */
            for(int i = 0; i < STATE_SIZE/4; i++){
                BYTE temp[STATE_SIZE/4];
                memcpy(temp, &state[i*4], sizeof(BYTE)*STATE_SIZE/4);
                for(int j = 0; j < STATE_SIZE/4; j++){
                    state[i*4+j] = temp[(j+(4-i))%4]; //row만큼 좌측으로이동시킨다. 모듈러로 인덱스 오버 해결
                }
            }
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return state;
}


/*  <MixColumns 함수>
 *   
 *  state   MixColumns을 수행할 16바이트 state. 수행 결과는 해당 배열에 바로 반영
 *  mode    MixColumns의 수행 모드
 */
BYTE* mixColumns(BYTE *state, int mode){    

    /* 필요하다 생각하면 추가 선언 */
    BYTE result[STATE_SIZE]; // 행렬 연산결과를 저장할 변수 
    BYTE MixC[STATE_SIZE] = {0x2, 0x3, 0x1, 0x1,
                             0x1, 0x2, 0x3, 0x1,
                              0x1, 0x1, 0x2, 0x3, 
                              0x3, 0x1, 0x1, 0x2}; // 암호화 행렬
    BYTE IMixC[STATE_SIZE] = {0x0E, 0x0B, 0x0D, 0x09,
                             0x09, 0x0E, 0x0B, 0x0D,
                              0x0D, 0x09, 0x0E, 0x0B, 
                              0x0B, 0x0D, 0x09, 0x0E}; // 복호화 행렬
   
    switch(mode){

        case ENC:
    
            /* 추가 구현 */
            
            for(int i = 0; i < 4; i++){
                for(int j = 0; j < KEY_SIZE/4; j++){
                    for(int k = 0; k < KEY_SIZE/4; k++){
                        if(k==0) result[i*4+j] = bitshift(state[k*4+j],MixC[i*4+k]);
                        else result[i*4+j] ^= bitshift(state[k*4+j],MixC[i*4+k]);
                    }
                }
            }   
            memcpy(state, result, sizeof(BYTE)*STATE_SIZE);
            break;

        case DEC:

            /* 추가 구현 */
            for(int i = 0; i < 4; i++){
                for(int j = 0; j < KEY_SIZE/4; j++){
                    for(int k = 0; k < KEY_SIZE/4; k++){
                        if(k==0) result[i*4+j] = bitshift(state[k*4+j],IMixC[i*4+k]);
                        else result[i*4+j] ^= bitshift(state[k*4+j],IMixC[i*4+k]);
                    }
                }
            }   
            memcpy(state, result, sizeof(BYTE)*STATE_SIZE);
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return state;
}


/*  <AddRoundKey 함수>
 *   
 *  state   AddRoundKey를 수행할 16바이트 state. 수행 결과는 해당 배열에 반영
 *  rKey    AddRoundKey를 수행할 16바이트 라운드키
 */
BYTE* addRoundKey(BYTE *state, BYTE *rKey){

    /* 추가 구현 */ 
    
    
    for(int i = 0; i < STATE_SIZE; i++){
        state[i] = state[i] ^ rKey[i]; // 같은 행열 값과 XOR
    }

    return state;
}


/*  <128비트 AES 암복호화 함수>
 *  
 *  mode가 ENC일 경우 평문을 암호화하고, DEC일 경우 암호문을 복호화하는 함수
 *
 *  [ENC 모드]
 *  input   평문 바이트 배열
 *  result  결과(암호문)이 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 *
 *  [DEC 모드]
 *  input   암호문 바이트 배열
 *  result  결과(평문)가 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 */
void AES128(BYTE *input, BYTE *result, BYTE *key, int mode){


    BYTE state[STATE_SIZE]; // 행열을 뒤집은 원문을 저장할 변수
    BYTE mix_key[KEY_SIZE]; // 행열을 뒤집은 키를 저장할 변수
    BYTE mix_round_key[KEY_SIZE]; // 행열을 뒤집은 한라운드 키를 저장할 변수
    BYTE roundkey[ROUNDKEY_SIZE]; // 전체 라운드 키를 저장할 변수
    
    expandKey(key, roundkey); // 라운드키 생성
    
    printf(" - ROUND KEYS : ");
        for(int i = 0; i < ROUNDKEY_SIZE; i++) { //#64
            if(i % 16 == 0) printf("\n");
                printf("%02x ", roundkey[i]);
        }
        printf("\n");
    printf("%d\n",mode);

    if(mode == ENC){
        
         for(int i = 0; i < STATE_SIZE/4; i++){
            for(int j = 0; j < STATE_SIZE/4; j++){
                state[i*4+j] = input[i+j*4];
            } // 원문의 행열을 뒤집어 STATE의 저장
        }
        for(int i = 0; i < KEY_SIZE/4; i++){
            for(int j = 0; j < KEY_SIZE/4; j++){
                mix_key[i*4+j] = key[i+j*4];
            } // 키의 행열을 뒤집어 MIX_KEY의 저장
        }
        
        addRoundKey(state, mix_key); // 0라운드 XOR
        
        for(int r = 0; r < 9; r++){  // 9라운드 반복     
            subBytes(state, ENC);
            shiftRows(state, ENC);
            mixColumns(state, ENC);
            
            memcpy(mix_round_key, &roundkey[(r+1)*16], sizeof(BYTE)*STATE_SIZE); // 이번 라운드에서 필요한 키를 카피
            for(int i = 0; i < KEY_SIZE/4; i++){
                for(int j = 0; j < KEY_SIZE/4; j++){
                    mix_key[i*4+j] = mix_round_key[i+j*4]; // 이번 라운드에서 사용할 키를 행열을 뒤집음
                }
            }
            addRoundKey(state, mix_key); 
        }
        // 10라운드
        subBytes(state, ENC);
        shiftRows(state, ENC);
        memcpy(mix_round_key, &roundkey[(10)*16], sizeof(BYTE)*STATE_SIZE);
        for(int i = 0; i < KEY_SIZE/4; i++){
            for(int j = 0; j < KEY_SIZE/4; j++){
                mix_key[i*4+j] = mix_round_key[i+j*4];
            }
        }
        addRoundKey(state, mix_key); 

        // 행과 열을 뒤집어 결과 변수에 저장 
        for(int i = 0; i < STATE_SIZE/4; i++){
            for(int j = 0; j < STATE_SIZE/4; j++){
                result[i*4+j] = state[i+j*4];
            }
        }//memcpy(result, state, sizeof(BYTE)*STATE_SIZE);
        
        

    }else if(mode == DEC){
        
        /* 추가 작업이 필요하다 생각하면 추가 구현 */
        
        // 0라운드 XOR
        addRoundKey(input, &roundkey[(10)*16]);
        
        for(int i = 0; i < STATE_SIZE/4; i++){
            for(int j = 0; j < STATE_SIZE/4; j++){
                state[i*4+j] = input[i+j*4];
            } // 원문의 행열을 뒤집어 STATE의 저장
        }
        //ROUNDKEY_SIZE = 176 / 4 = 44 / 4 - 2
        for(int r = ROUNDKEY_SIZE/16-2; r > 0; r--){ // 9라운드 반복
            shiftRows(state, DEC);
            subBytes(state, DEC);
        
            memcpy(mix_round_key, &roundkey[(r)*16], sizeof(BYTE)*STATE_SIZE); // 이번 라운드에서 사용할 키를 카피
            for(int i = 0; i < KEY_SIZE/4; i++){
                for(int j = 0; j < KEY_SIZE/4; j++){
                    mix_key[i*4+j] = mix_round_key[i+j*4];
                } // 이번 라운드에서 사용할 키를 행열을 뒤집음
            }
            
            addRoundKey(state, mix_key); 
            mixColumns(state, DEC);
        }
        shiftRows(state, DEC);
        subBytes(state, DEC);
        

        for(int i = 0; i < STATE_SIZE/4; i++){
            for(int j = 0; j < STATE_SIZE/4; j++){
                input[i*4+j] = state[i+j*4];
            } // 행과 열을 뒤집어 결과 변수에 저장 
        };
        // 10라운드
        // addRoundKey(input, &roundkey[(0)*16]) //State
       memcpy(result, addRoundKey(input, &roundkey[(0)*16]), sizeof(BYTE)*STATE_SIZE);    
    }else{
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
}