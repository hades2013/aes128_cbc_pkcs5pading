#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/ssl.h>

#define BLOCK_SIZE 16
#define BUF_LEN  1024 

static const char encodeCharacterTable[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char decodeCharacterTable[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    ,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
    ,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1
};


void base64_encode(unsigned char *input, unsigned input_length, unsigned char *output)
{
    char buff1[3];
    char buff2[4];
    unsigned char i=0, j;
    unsigned input_cnt=0;
    unsigned output_cnt=0;

    while(input_cnt<input_length)
    {
        buff1[i++] = input[input_cnt++];
        if (i==3)
        {
            output[output_cnt++] = encodeCharacterTable[(buff1[0] & 0xfc) >> 2];
            output[output_cnt++] = encodeCharacterTable[((buff1[0] & 0x03) << 4) + ((buff1[1] & 0xf0) >> 4)];
            output[output_cnt++] = encodeCharacterTable[((buff1[1] & 0x0f) << 2) + ((buff1[2] & 0xc0) >> 6)];
            output[output_cnt++] = encodeCharacterTable[buff1[2] & 0x3f];
            i=0;
        }
    }
    if (i)
    {
        for(j=i;j<3;j++)
        {
            buff1[j] = '\0';
        }
        buff2[0] = (buff1[0] & 0xfc) >> 2;
        buff2[1] = ((buff1[0] & 0x03) << 4) + ((buff1[1] & 0xf0) >> 4);
        buff2[2] = ((buff1[1] & 0x0f) << 2) + ((buff1[2] & 0xc0) >> 6);
        buff2[3] = buff1[2] & 0x3f;
        for (j=0;j<(i+1);j++)
        {
            output[output_cnt++] = encodeCharacterTable[buff2[j]];
        }
        while(i++<3)
        {
            output[output_cnt++] = '=';
        }
    }
    output[output_cnt] = 0;
}

void base64_decode(unsigned char *input, unsigned input_length, unsigned char *output)
{
    char buff1[4];
    char buff2[4];
    unsigned char i=0, j;
    unsigned input_cnt=0;
    unsigned output_cnt=0;

    while(input_cnt<input_length)
    {
        buff2[i] = input[input_cnt++];
        if (buff2[i] == '=')
        {
            break;
        }
        if (++i==4)
        {
            for (i=0;i!=4;i++)
            {
                buff2[i] = decodeCharacterTable[buff2[i]];
            }
            output[output_cnt++] = (char)((buff2[0] << 2) + ((buff2[1] & 0x30) >> 4));
            output[output_cnt++] = (char)(((buff2[1] & 0xf) << 4) + ((buff2[2] & 0x3c) >> 2));
            output[output_cnt++] = (char)(((buff2[2] & 0x3) << 6) + buff2[3]);
            i=0;
        }
    }
    if (i)
    {
        for (j=i;j<4;j++)
        {
            buff2[j] = '\0';
        }
        for (j=0;j<4;j++)
        {
            buff2[j] = decodeCharacterTable[buff2[j]];
        }
        buff1[0] = (buff2[0] << 2) + ((buff2[1] & 0x30) >> 4);
        buff1[1] = ((buff2[1] & 0xf) << 4) + ((buff2[2] & 0x3c) >> 2);
        buff1[2] = ((buff2[2] & 0x3) << 6) + buff2[3];
        for (j=0;j<(i-1); j++)
        {
            output[output_cnt++] = (char)buff1[j];
        }
    }
    output[output_cnt] = 0;
}

int aes_encrypt_PKCS5Padding(unsigned char *sz_in_buff, int sz_in_len, unsigned char *key,unsigned char *iv, unsigned char *sz_out_buff)
{
    EVP_CIPHER_CTX ctx;
    
    int len=0,isSuccess = 0;
    unsigned char in[BLOCK_SIZE];  
    int outl = 0;   
        int outl_total = 0; 
    
    EVP_CIPHER_CTX_init(&ctx);  
   
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);

    while(sz_in_len >=BLOCK_SIZE)
    {
        memcpy(in, sz_in_buff, BLOCK_SIZE);  
            sz_in_len -= BLOCK_SIZE;  
            sz_in_buff += BLOCK_SIZE;  
        isSuccess = EVP_EncryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, BLOCK_SIZE);  
            if(!isSuccess)  
            {  
                    printf("EVP_EncryptUpdate() failed");  
                    EVP_CIPHER_CTX_cleanup(&ctx);  
                    return 0;  
            }  
            outl_total += outl;  
    }
    
     if(sz_in_len > 0)  
        {  
            memcpy(in, sz_in_buff, sz_in_len); 
            isSuccess = EVP_EncryptUpdate(&ctx,sz_out_buff + outl_total, &outl, in, sz_in_len);  
            outl_total += outl;  
    
        isSuccess = EVP_EncryptFinal_ex(&ctx,sz_out_buff + outl_total,&outl);  
            if(!isSuccess)  
            {  
                printf("EVP_EncryptFinal_ex() failed");  
                EVP_CIPHER_CTX_cleanup(&ctx);  
                return 0;  
            }  
            outl_total += outl;  
        }     
        
        EVP_CIPHER_CTX_cleanup(&ctx); 
    return outl_total;
}


int aes_decrypt_PKCS5Padding(unsigned char *sz_in_buff, int sz_in_length, unsigned char *key,unsigned char *iv, unsigned char *sz_out_buff)
{
    unsigned char in[BLOCK_SIZE];  
        int outl = 0;  
        int outl_total = 0;  
        int isSuccess;  
  
        EVP_CIPHER_CTX ctx;     

    //初始化ctx，加密算法初始化  
        EVP_CIPHER_CTX_init(&ctx);  
        isSuccess = EVP_DecryptInit_ex(&ctx,EVP_aes_128_cbc(),NULL,key,iv);  
    if(!isSuccess)  
        {  
            printf("EVP_DecryptInit_ex() failed");  
            EVP_CIPHER_CTX_cleanup(&ctx);  
            return 0;  
        }  

    //解密数据  
        while(sz_in_length >BLOCK_SIZE)  
        {  
            memcpy(in, sz_in_buff, BLOCK_SIZE);  
            sz_in_length -= BLOCK_SIZE;  
            sz_in_buff += BLOCK_SIZE;  
  
            isSuccess = EVP_DecryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, BLOCK_SIZE);  
            if(!isSuccess)  
            {  
                    printf("EVP_DecryptUpdate() failed");  
                    EVP_CIPHER_CTX_cleanup(&ctx);  
                    return 0;  
            }  
            outl_total += outl;  
        }

    
    if(sz_in_length > 0)  
        {  
            memcpy(in, sz_in_buff, sz_in_length);  
            isSuccess = EVP_DecryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, sz_in_length);  
            outl_total += outl;  
        } 
        
    /*解密数据块不为16整数倍时执行 */
     if(sz_in_length % BLOCK_SIZE != 0)  
        {  
            isSuccess = EVP_DecryptFinal_ex(&ctx, sz_out_buff + outl_total, &outl);  
            if(!isSuccess)  
            {  
                printf("EVP_DecryptFinal_ex() failed\n");  
                    EVP_CIPHER_CTX_cleanup(&ctx);  
                    return 0;  
            }  
            outl_total += outl;  
        }  
      
        EVP_CIPHER_CTX_cleanup(&ctx);  
        return outl_total;  
}

// main entrypoint
int main(int argc, char **argv)
{
    unsigned char ivec[16] = "0000000000000000";
    unsigned char sz_sharekey[16]="1234567887654321";
    char aesJson[512] = "{\"person\":{\"firstName\":\"xu\",\"lastName\":\"hades\",\"email\":\"hades@qq.com\",\"age\":\"25\",\"height\":\"180\"}}";
    char base64_out[BUF_LEN]={0};
    char out_buff[512]={0};
    char decode[512]={0};
    int length = 0;

    printf("aesJson: %s\nlength:%d\n", aesJson, strlen(aesJson));
    memset(out_buff, 0, sizeof(out_buff));
    length = aes_encrypt_PKCS5Padding(aesJson, strlen(aesJson), sz_sharekey, ivec, out_buff);
    if(length < 0){
        printf("error AES_encrypt\n");
        return -1;
    }
    printf("encode length: %d\n", length);
    base64_encode(out_buff, length, base64_out);
    printf("base64_out: %s\nlength: %d\n", base64_out, strlen(base64_out));
    aes_decrypt_PKCS5Padding(out_buff, length, sz_sharekey, ivec, decode);
    printf("decode: %s\nlength: %d\n", decode, strlen(decode));
    return 0;
}