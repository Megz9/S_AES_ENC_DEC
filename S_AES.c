#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char uint8_t;
uint8_t mixColMatrix[4]={0x1,0x4,0x4,0x1};
uint8_t sbox[16]={0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7};

//inverse values
uint8_t invMixColMatrix[4]={0x9,0x2,0x2,0x9};
uint8_t invSbox[16]={0xA,0x5,0x9,0xB,0x1,0x7,0x8,0xF,0x6,0x0,0x2,0x3,0xC,0x4,0xD,0xE};

// Define a Nibble data type
typedef struct {
    uint8_t value : 4; // 4-bit value
    uint8_t b3 : 1; // 1-bit value
    uint8_t b2 : 1; // 1-bit value
    uint8_t b1 : 1; // 1-bit value
    uint8_t b0 : 1; // 1-bit value
} nibble;

/***AES FUNCTIONS***/
void addRoundKey(nibble* data,nibble* key);
void shiftRows(nibble* data);
void mixColumn(nibble* data);
void nibbleSubstitution(nibble * data);
uint8_t galoisMultiply4(uint8_t a,uint8_t b);
nibble oneNibbleSubstitution(nibble data);

void invMixColumn(nibble* data);
void invNibbleSubstitution(nibble * data);
/***Key Expansion***/
void generateKeys(nibble* key, nibble* key1, nibble* key2);

/***DEALING WITH BITS***/
void calculateBits(nibble* data);
void calculateNum(nibble* data);
void print_bin(nibble data);
void print_16bit_bin(nibble* data);
void print_16bit_hex(nibble* data);



/***ENCRYPT FUNCTION***/
void enc(nibble* data, nibble* key);
void enc(nibble* data, nibble* key){
    nibble key1 [4];
    nibble key2 [4];
    generateKeys(key,key1,key2);
    addRoundKey(data,key);

    nibbleSubstitution(data);
    shiftRows(data);
    mixColumn(data);
    addRoundKey(data,key1);

    nibbleSubstitution(data);
    shiftRows(data);
    addRoundKey(data,key2);
}

/***DECRYPT FUNCTION***/
void dec(nibble* data, nibble* key);
void dec(nibble* data, nibble* key){
    nibble key1 [4];
    nibble key2 [4];
    generateKeys(key,key1,key2);
    addRoundKey(data,key2);

    shiftRows(data); //inverse shift same as shift
    invNibbleSubstitution(data);
    addRoundKey(data,key1);
    invMixColumn(data);

    shiftRows(data); //inverse shift same as shift
    invNibbleSubstitution(data);
    addRoundKey(data,key);
}

int main(int argc, char * argv[]) {

    if(argc != 4){
        printf("invalid number of parameters.\nExpects:\n\t%s  ENC|DEC  key  data\n", argv[0]);
        return 1;
    }

    nibble data[4];
    data[0].value=0xD;
    data[1].value=0x7;
    data[2].value=0x2;
    data[3].value=0x8;

    nibble key[4];
    key[0].value=0x4;
    key[1].value=0xA;
    key[2].value=0xF;
    key[3].value=0x5;
if(argc == 4) {

for(int i=0;i<4;i++) {
// Treat the character as a hexadecimal value
    if ('0' <= argv[2][i] && argv[2][i] <= '9') {
        key[i].value = argv[2][i] - '0';
    } else if ('a' <= argv[2][i] && argv[2][i] <= 'f') {
        key[i].value = argv[2][i] - 'a' + 10;
    } else if ('A' <= argv[2][i] && argv[2][i] <= 'F') {
        key[i].value = argv[2][i] - 'A' + 10;
    } else {
        printf("Invalid hexadecimal character\n");
        return 1; // Exit with an error code
    }
}
    for(int i=0;i<4;i++) {
// Treat the character as a hexadecimal value
        if ('0' <= argv[3][i] && argv[3][i] <= '9') {
            data[i].value = argv[3][i] - '0';
        } else if ('a' <= argv[3][i] && argv[3][i] <= 'f') {
            data[i].value = argv[3][i] - 'a' + 10;
        } else if ('A' <= argv[3][i] && argv[3][i] <= 'F') {
            data[i].value = argv[3][i] - 'A' + 10;
        } else {
            printf("Invalid hexadecimal character\n");
            return 1; // Exit with an error code
        }
    }
        if (strcmp(argv[1], "enc") == 0 || strcmp(argv[1], "ENC") == 0 || strcmp(argv[1], "Enc") == 0) {
//            printf("Cipher Text:\n");
            enc(data, key);
//            print_16bit_bin(data);
            print_16bit_hex(data);
        } else if (strcmp(argv[1], "dec") == 0 || strcmp(argv[1], "DEC") == 0 || strcmp(argv[1], "Dec") == 0) {
//            printf("Plain Text:\n");
            dec(data, key);
//            print_16bit_bin(data);
            print_16bit_hex(data);
        } else {
            printf("invalid operation \n\tAllowed argument \"DEC\" or \"ENC\"");
        }
    }

    /* representation
     * data[0] data[2]
     * data[1] data[3]
     */

    return 0;
}
/***Generating KEY***/
void generateKeys(nibble* key, nibble* key1, nibble* key2){
    // Making key 1
    for (int i = 0; i < 4; ++i) {
        key1[i].value = key[i].value;
    }
    //rotate key is equivalent to swapping
    nibble temp =key1[2];
    key1[2].value=key1[3].value;
    key1[3].value=temp.value;

    key1[2] = oneNibbleSubstitution(key1[2]);
    key1[3] = oneNibbleSubstitution(key1[3]);

    key1[0].value = key1[0].value ^ 0x8 ^ key1[2].value; //xor with RCON
    key1[1].value = key1[1].value ^ 0x0 ^ key1[3].value; //xor with RCON
    key1[2].value = key1[0].value ^ key[2].value;
    key1[3].value = key1[1].value ^ key[3].value;

    // Making key 2
    for (int i = 0; i < 4; ++i) {
        key2[i].value = key1[i].value;
    }
    //rotate key is equivalent to swapping
    temp =key2[2];
    key2[2].value=key2[3].value;
    key2[3].value=temp.value;

    key2[2] = oneNibbleSubstitution(key2[2]);
    key2[3] = oneNibbleSubstitution(key2[3]);

    key2[0].value = key2[0].value ^ 0x3 ^ key2[2].value; //xor with RCON
    key2[1].value = key2[1].value ^ 0x0 ^ key2[3].value; //xor with RCON
    key2[2].value = key2[0].value ^ key1[2].value;
    key2[3].value = key2[1].value ^ key1[3].value;

    //calculateBits for both keys
    calculateBits(key1);
    calculateBits(key2);
}

/***AES FUNCTIONS***/
uint8_t galoisMultiply4(uint8_t a,uint8_t b){
    uint8_t result = 0;
    uint8_t hiBitSet;

    for(int i=0;i<4;i++){
        if(b & 1){
            result ^= a;
        }
        //check the leftmost bit of a
        hiBitSet = a & 0x8;

        //left shift a
        a <<= 1;
        //to continue with 4 bits only
        a = a & 0x0F;
        if(hiBitSet){
            a ^= 0x03; //from x^4+x+1 -->0b0011
        }
        b >>= 1;
    }
    //make sure output is 4 bits to be stored in nibble
    return result & 0x0F;
}
void mixColumn(nibble* data){
    nibble res[4];
    res[0].value= galoisMultiply4(mixColMatrix[0],data[0].value) ^ galoisMultiply4(mixColMatrix[2],data[1].value);
    res[1].value= galoisMultiply4(mixColMatrix[1],data[0].value) ^ galoisMultiply4(mixColMatrix[3],data[1].value);
    res[2].value= galoisMultiply4(mixColMatrix[0],data[2].value) ^ galoisMultiply4(mixColMatrix[2],data[3].value);
    res[3].value= galoisMultiply4(mixColMatrix[1],data[2].value) ^ galoisMultiply4(mixColMatrix[3],data[3].value);

    data[0].value=res[0].value;
    data[1].value=res[1].value;
    data[2].value=res[2].value;
    data[3].value=res[3].value;
    calculateBits(data);
}
void addRoundKey(nibble* data,nibble* key){
    nibble res[4];
    for (int i = 0; i < 4; i++) {
        data[i].value = data[i].value ^ key[i].value;
    }
    calculateBits(data);
}
void shiftRows(nibble* data){
    nibble temp;
    temp= data[1];
    data[1]=data[3];
    data[3] =temp;
}
void nibbleSubstitution(nibble * data){
    for (int i = 0; i < 4; i++) {
        data[i].value= sbox[data[i].value];
    }
}

nibble oneNibbleSubstitution(nibble data){
    data.value= sbox[data.value];
    return data;
}

void invMixColumn(nibble* data){
    nibble res[4];
    res[0].value= galoisMultiply4(invMixColMatrix[0],data[0].value) ^ galoisMultiply4(invMixColMatrix[2],data[1].value);
    res[1].value= galoisMultiply4(invMixColMatrix[1],data[0].value) ^ galoisMultiply4(invMixColMatrix[3],data[1].value);
    res[2].value= galoisMultiply4(invMixColMatrix[0],data[2].value) ^ galoisMultiply4(invMixColMatrix[2],data[3].value);
    res[3].value= galoisMultiply4(invMixColMatrix[1],data[2].value) ^ galoisMultiply4(invMixColMatrix[3],data[3].value);

    data[0].value=res[0].value;
    data[1].value=res[1].value;
    data[2].value=res[2].value;
    data[3].value=res[3].value;
    calculateBits(data);
}
void invNibbleSubstitution(nibble * data){
    for (int i = 0; i < 4; i++) {
        data[i].value= invSbox[data[i].value];
    }
}
/***DEALING WITH BITS***/
void calculateBits(nibble* data) {
    for (int i = 0; i < 4; i++) {
        data[i].b3 = (data[i].value >> 3) & 1;
        data[i].b2 = (data[i].value >> 2) & 1;
        data[i].b1 = (data[i].value >> 1) & 1;
        data[i].b0 = (data[i].value     ) & 1;

    }
}
void calculateNum(nibble* data) {
    for (int i = 0; i < 4; i++) {
        data[i].value =0;
        data[i].value |= data[i].b3<<3 ;
        data[i].value |= data[i].b2<<2 ;
        data[i].value |= data[i].b1<<1 ;
        data[i].value |= data[i].b0    ;
    }
}

void print_bin(nibble data){
    char bit=0;
    for (int i = sizeof(char)*3; i >= 0; i--) {
        bit=(data.value & (1<<i))>>i ;
        printf("%d",bit );
    }
}

void print_16bit_bin(nibble* data){
    for (int i = 0; i < 4; i++) {
        print_bin(data[i]);
        if(i !=3)printf("_");
    }
    printf("\n");
}

void print_16bit_hex(nibble* data){
    for (int i = 0; i < 4; i++) {
        printf("%X",data[i].value);
    }
    printf("\n");
}
