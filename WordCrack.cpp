// *******************************************************
// *Project1 of Computer organization and design,ISEE ZJU*
// *******************************************************
// *                 Han,Xiao   3160101136               *
// *******************************************************

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sha1.h"          // https://github.com/clibs/sha1
#include "sha1.c"
#include <math.h>
#include <algorithm>
#include <iostream>
#include <vector>
#include <omp.h>
#include "b64.h"           // https://github.com/littlstar/b64.c
#include "decode.c"
#include "AES128.c"
#include <time.h>
#define max_size 500
 

// Variable type definition
using namespace std;
typedef unsigned char u8;
typedef unsigned int u32;
#define NUM_THREADS 5

// Function declaration
int issame(char *p1,char *p2);
int findit(char *p1,char *p2,int t);
char *getfileall(char *fname);
int Parameter_extraction(void);
void SaveResult(u32 result);
void u8Tou32(u8 *Array,u32* result,int length);
void u32Tou8(u32* Array,u8* result,int length);
u32 Tou8(u8 *Array);
int Validation();
void TryPwd();


// Global variables definition
char* saltValue=(char*)malloc(max_size*sizeof(char));
char* encryptedVerifierHashValue=(char*)malloc(max_size*sizeof(char));
char* encryptedVerifierHashInput=(char*)malloc(max_size*sizeof(char));

u32* saltTrue=(u32*)malloc(max_size*sizeof(char));
u32* Verifier=(u32*)malloc(max_size*sizeof(char));
u32* Verifier_1=(u32*)malloc(max_size*sizeof(char));
u32* Verifier_2=(u32*)malloc(max_size*sizeof(char));
u32* VerifierHashInput=(u32*)malloc(max_size*sizeof(char));
u32* VerifierHashValue=(u32*)malloc(max_size*sizeof(char));
u32* k1=(u32*)malloc(max_size*sizeof(char));//I am not sure?
u32* k2=(u32*)malloc(max_size*sizeof(char));
u32* MVerifier=(u32*)malloc(max_size*sizeof(char));
u32* VerifierHash=(u32*)malloc(max_size*sizeof(char));
u32* VerifierHash_1=(u32*)malloc(max_size*sizeof(char));
u32* VerifierHash_2=(u32*)malloc(max_size*sizeof(char));

u8* de_saltValue=(u8*)malloc(max_size*sizeof(char));
u8* de_encryptedVerifierHashValue=(u8*)malloc(max_size*sizeof(char));
u8* de_encryptedVerifierHashInput=(u8*)malloc(max_size*sizeof(char));
u8* lMVerifier=(u8*)malloc(max_size*sizeof(char));
u8* lVerifierHash=(u8*)malloc(max_size*sizeof(char));
u8* lVerifierHash_1=(u8*)malloc(max_size*sizeof(char));
u8* lVerifierHash_2=(u8*)malloc(max_size*sizeof(char));

int trypwd=0; 
int pwdTrue=0;

clock_t start1,end1,start2,end2; 

// *******************************************Control part*********************************************************

// The general idea is to determine whether the generated eigenvalues 
// are consistent with those extracted from the original file 
// by traversing all possible passwords and repeating the Word2010 encryption process
int main(void){

 	Parameter_extraction();
	TryPwd();
	
	// End the first timer until the correct password is to be saved
	end1=clock();
	printf("total running time=%fs\n",(double)(end1-start1)/CLK_TCK);  

	SaveResult(pwdTrue);
	
	free(saltTrue);
	free(saltValue);
	free(encryptedVerifierHashInput);
	free(encryptedVerifierHashValue);
	free(de_saltValue);
	free(de_encryptedVerifierHashInput);
	free(de_encryptedVerifierHashValue);
	
	getchar();

}

// Try the password generation function
// which generates Numbers from 000 to 999 for the next function to verify
void TryPwd(){
	int flag=0;
	//#pragma omp parallel for
	for(trypwd=0;trypwd<1000;trypwd++){
		printf("test: %03d\n",trypwd);
		if(Validation()==1){
			pwdTrue=trypwd;
			flag=1;
			putchar('\n');
			printf("Find it! Password is :%03u!\n",pwdTrue);
			break;
		}
	}
	if(!flag){
		putchar('\n');
	    printf("Not Found!\n");
	}
}

void SaveResult(u32 result)
{
	FILE *file;
	file = fopen("result.txt","w");
	if(file!=NULL){
		fprintf(file,"Password: %03u",result);
	}

}

// *******************************************Validation part******************************************************


// This function does the encryption method of word2010 for each generated password 
// and determining if it is the correct password
int Validation(){

	//Start of second timer function
	start2=clock();  

	u8 H1[21]={0};
	u8 pre_result[25]={0};
	u8 saltpwd[20]={0}; 
	u8 iteratorplus[4]={0};
	u32 iterator=0;

    //H0 = H(salt + unicode(password))
	for (int i=0;i<16;i++){
		saltpwd[i]=de_saltValue[i];
	}

    // The password connected to the salt value is converted from ASCII to UNICODE and stored in Little-Endian
    // Only 0-9 digits have been converted here, which is one of the limitations of this code
	saltpwd[17]=0x00;
	saltpwd[16]=0x30+trypwd/100;
	saltpwd[19]=0x00;
	saltpwd[18]=0x30+trypwd%100/10;
	saltpwd[21]=0x00;
	saltpwd[20]=0x30+trypwd%10;
	saltpwd[22]='\0';

	SHA1((char*)H1,(char*)saltpwd,22);
	
	// puts("H0: ");
	// for(int n=0;n<21;n++){
	// 	printf("%02x ", H1[n]);
	// }
	// putchar('\n');

	// Hn = H(iterator + Hn-1)
	// The number of iterations is also stored in Little-Endian
	for (int i = 0; i < 100000; i++){
        u32Tou8(&iterator,iteratorplus,1);
        for(int k=4; k<=24;k++){
           pre_result[k]=H1[k-4];
        }
        pre_result[0]=iteratorplus[3];
        pre_result[1]=iteratorplus[2];
        pre_result[2]=iteratorplus[1];
        pre_result[3]=iteratorplus[0];


		SHA1((char*)H1,(char*)pre_result,24);
		for (int j = 0; j <=20; j++){
			pre_result[j] = H1[j];
		}
		iterator++;

	}

	// puts("H1: ");	
	// for(int n=0;n<21;n++){
	// 	printf("%02x ", H1[n]);
	// }
	// putchar('\n');

	u8 encryptedVerifierHashInputBlockKey[8] = {0xfe,0xa7,0xd2,0x76,0x3b,0x4b,0x9e,0x79};
    u8 encryptedVerifierHashValueBlockKey[8] = {0xd7,0xaa,0x0f,0x6d,0x30,0x61,0x34,0x4e};
    u8 H1input[29]={0}; 
	u8 H1value[29]={0}; 
	u8 rkey1[21]={0};
	u8 rkey2[21]={0};


    //Hfinal = H(Hn + blockKey)
	for (int i=0;i<20;i++){
		H1input[i]=H1[i];
		H1value[i]=H1[i];
	}
	for (int i=20;i<28;i++){
		H1input[i]=encryptedVerifierHashInputBlockKey[i-20];
		H1value[i]=encryptedVerifierHashValueBlockKey[i-20];
	}
	H1input[28]='\0';
	H1value[28]='\0';

	SHA1((char*)rkey1,(char*)H1input,28);
	SHA1((char*)rkey2,(char*)H1value,28);

    // puts("rkey1: ");
	// for(int n=0;n<21;n++){
	// 	printf("%02x ", rkey1[n]);
	// }
	// putchar('\n');

    // puts("rkey2: ");
	// for(int n=0;n<21;n++){
	// 	printf("%02x ", rkey2[n]);
	// }
	// putchar('\n');


    u32* lrkey1=(u32*)malloc(max_size*sizeof(char));
	u32* lrkey2=(u32*)malloc(max_size*sizeof(char));
    u8Tou32(rkey1,lrkey1,20);
	u8Tou32(rkey2,lrkey2,20);

	// puts("lrkey1: ");
	// for(int n=0;n<5;n++){
	// 	printf("%08x ", lrkey1[n]);
	// }
	// putchar('\n');

	// puts("lrkey2: ");
	// for(int n=0;n<5;n++){
	// 	printf("%08x ", lrkey2[n]);
	// }
	// putchar('\n');

	// Because k1 is used for decryption, it needs to be reversed
	AES128_ExpandKey(lrkey2,k2,te0,te1,te2,te3,te4);
	AES128_ExpandKey(lrkey1,k1,te0,te1,te2,te3,te4);
	AES128_InvertKey(k1,td0,td1,td2,td3,td4,te0,te1,te2,te3,te4);
	
	// puts("k1: ");
	// for(int n=0;n<44;n++){
	// 	printf("%08x ", k1[n]);
	// }
	// putchar('\n');

	// puts("k2: ");
	// for(int n=0;n<44;n++){
	// 	printf("%08x ", k2[n]);
	// }
	// putchar('\n');


	AES128_decrypt(VerifierHashInput,MVerifier,k1,td0,td1,td2,td3,td4);
	// puts("MVerifier: ");
	// for(int n=0;n<4;n++){
	// 	printf("%08x ", MVerifier[n]);
	// }
	// putchar('\n');

	u8Tou32(de_saltValue,saltTrue,16);
	// puts("saltTrue: ");
	// for(int n=0;n<4;n++){
	// 	printf("%08x ", saltTrue[n]);
	// }
	// putchar('\n');

    // The AES128 decryption algorithm needs to make its output XOR with the IV(initial vector) 
    // in this case, the IV is salt
	MVerifier[0]=saltTrue[0]^MVerifier[0];
	MVerifier[1]=saltTrue[1]^MVerifier[1];
	MVerifier[2]=saltTrue[2]^MVerifier[2];
	MVerifier[3]=saltTrue[3]^MVerifier[3];
   
    u32Tou8(MVerifier,lMVerifier,4);
	// puts("lMVerifier: ");
	// for(int n=0;n<16;n++){
	// 	printf("%02x ", lMVerifier[n]);
	// }
	// putchar('\n');
    
    SHA1((char*)lVerifierHash,(char*)lMVerifier,16);
    
    for(int i=0;i<16;i++){
    	lVerifierHash_1[i]=lVerifierHash[i];
    }
    for(int i=0;i<4;i++){
		lVerifierHash_2[i]=lVerifierHash[i+16];
    }
    for(int i=4;i<16;i++){
		lVerifierHash_2[i]=0x00;
    }

	u8Tou32(lVerifierHash_1,VerifierHash_1,16);
	u8Tou32(lVerifierHash_2,VerifierHash_2,16);

	// puts("VerifierHash_1:");
	// for(int i=0;i<4;i++){
	// 	printf("%08x ",VerifierHash_1[i]);
	// }
	// putchar('\n');

	// puts("VerifierHash_2:");
	// for(int i=0;i<4;i++){
	// 	printf("%08x ",VerifierHash_2[i]);
	// }
	// putchar('\n');

    // Similarly,the AES128 decryption algorithm needs to make its input XOR with the IV
    // Since the input here is over 128 bits, we need the piecewise operation for AES128 algorithm
	VerifierHash_1[0]=saltTrue[0]^VerifierHash_1[0];
	VerifierHash_1[1]=saltTrue[1]^VerifierHash_1[1];
	VerifierHash_1[2]=saltTrue[2]^VerifierHash_1[2];
	VerifierHash_1[3]=saltTrue[3]^VerifierHash_1[3];
	AES128_encrypt(VerifierHash_1,Verifier_1,k2,te0,te1,te2,te3,te4);

	VerifierHash_2[0]=Verifier_1[0]^VerifierHash_2[0];
	VerifierHash_2[1]=Verifier_1[1]^VerifierHash_2[1];
	VerifierHash_2[2]=Verifier_1[2]^VerifierHash_2[2];
	VerifierHash_2[3]=Verifier_1[3]^VerifierHash_2[3];
	AES128_encrypt(VerifierHash_2,Verifier_2,k2,te0,te1,te2,te3,te4);

	// Then remember to connect the results of the piecewise operation 
	// and compare them with the values extracted from the original file
	for(int i=0;i<4;i++){
		Verifier[i]=Verifier_1[i];
	}
	for(int i=4;i<8;i++){
		Verifier[i]=Verifier_2[i-4];
	}

    // puts("Verifier:");
	// for(int i=0;i<8;i++){
	// 	printf("%08x ",Verifier[i]);
	// }
	// putchar('\n');

    int judge=1;
    for (int i = 0; i < 8; i++){
    	if(Verifier[i]!=VerifierHashValue[i]){
    		judge=0;
    		break;
    	}
    }

	free(k1);
	free(k2);
	free(lrkey1);
    free(lrkey2);
	free(VerifierHashInput);
	free(VerifierHashValue);
	free(MVerifier);
	free(VerifierHash);
	free(VerifierHash_1);
	free(VerifierHash_2);
	free(Verifier);
	free(Verifier_1);
	free(Verifier_2);
	free(lMVerifier);
	free(lVerifierHash);
	free(lVerifierHash_1);
	free(lVerifierHash_2);

    //The second timer function ends and the result is accurate to milliseconds
	end2=clock();  
    printf("single password testing time=%fs\n",(double)(end2-start2)/CLK_TCK);  

	return judge;

}

// Since different functions require different input and output formats
// we need some functions to do type conversion of u32 and u8
// These operations are based on binary
// Transfer u32 to u8,ie. unsigned int to char:4-->16;1-->4
void u32Tou8(u32* Array,u8* result,int length){
    if(length == 4){
    	result[0]=(Array[0]>>24)&(0x000000ff);
    	result[1]=(Array[0]>>16)&(0x000000ff);
    	result[2]=(Array[0]>>8)&(0x000000ff);
    	result[3]=(Array[0])&(0x000000ff);
    	result[4]=(Array[1]>>24)&(0x000000ff);
    	result[5]=(Array[1]>>16)&(0x000000ff);
    	result[6]=(Array[1]>>8)&(0x000000ff);
    	result[7]=(Array[1])&(0x000000ff);
    	result[8]=(Array[2]>>24)&(0x000000ff);
    	result[9]=(Array[2]>>16)&(0x000000ff);
    	result[10]=(Array[2]>>8)&(0x000000ff);
    	result[11]=(Array[2])&(0x000000ff);
    	result[12]=(Array[3]>>24)&(0x000000ff);
    	result[13]=(Array[3]>>16)&(0x000000ff);
    	result[14]=(Array[3]>>8)&(0x000000ff);
    	result[15]=(Array[3])&(0x000000ff);
    }
    else if(length == 1){
    	result[0]=(Array[0]>>24)&(0x000000ff);
    	result[1]=(Array[0]>>16)&(0x000000ff);
    	result[2]=(Array[0]>>8)&(0x000000ff);
    	result[3]=(Array[0])&(0x000000ff);
    }

}

//Transfer u8 to u32,ie. unsigned char to int:20-->5;32-->8;16-->4
void u8Tou32(u8 *Array,u32* result,int length){
	if(length == 20){
		u8 temp[5][4]={0};
		for(int i=0;i<4;i++){
			temp[0][i] = Array[i];
			temp[1][i] = Array[i+4];
			temp[2][i] = Array[i+8];
			temp[3][i] = Array[i+12];
			temp[4][i] = Array[i+16];
		}
		result[0]=Tou8(temp[0]);
		result[1]=Tou8(temp[1]);
		result[2]=Tou8(temp[2]);
		result[3]=Tou8(temp[3]);
		result[4]=Tou8(temp[4]);
	}
	else if(length == 32){
		u8 temp[8][4]={0};
		for(int i=0;i<4;i++){
			temp[0][i] = Array[i];
			temp[1][i] = Array[i+4];
			temp[2][i] = Array[i+8];
			temp[3][i] = Array[i+12];
			temp[4][i] = Array[i+16];
			temp[5][i] = Array[i+20];
			temp[6][i] = Array[i+24];
			temp[7][i] = Array[i+28];
		}
		result[0]=Tou8(temp[0]);
		result[1]=Tou8(temp[1]);
		result[2]=Tou8(temp[2]);
		result[3]=Tou8(temp[3]);
		result[4]=Tou8(temp[4]);
		result[5]=Tou8(temp[5]);
		result[6]=Tou8(temp[6]);
		result[7]=Tou8(temp[7]);
	}
	else if(length == 4){
	    result[0]=Tou8(Array);
	}
	else if(length == 16){
		u8 temp[4][4]={0};
		for(int i=0;i<4;i++){
			temp[0][i] = Array[i];
			temp[1][i] = Array[i+4];
			temp[2][i] = Array[i+8];
			temp[3][i] = Array[i+12];
		}
		result[0]=Tou8(temp[0]);
		result[1]=Tou8(temp[1]);
		result[2]=Tou8(temp[2]);
		result[3]=Tou8(temp[3]);
	}
}

u32 Tou8(u8 *Array){
	u32 Intu8 = 0x00000000;
	Intu8 = Intu8 | Array[0];
	Intu8 = Intu8 << 8;
	Intu8 = Intu8 | Array[1];
	Intu8 = Intu8 << 8;
	Intu8 = Intu8 | Array[2];
	Intu8 = Intu8 << 8;
	Intu8 = Intu8 | Array[3];
	return Intu8;
}

// ****************************************Parameter extraction part***********************************************

//File read and parameter extraction
int Parameter_extraction(void){
    
	int bias;
	FILE* docFile;
	FILE* New;
	// You can define the string you want to extract here
	// but these three values are sufficient for cracking Word 2010
	char wordsalt[] = "saltValue";
	char wordvalue[] = "encryptedVerifierHashValue";
	char wordinput[] = "encryptedVerifierHashInput";
	char str[200];
	char* fname;
	char* info;
	char* rewrite; 

    // When the input path is wrong, we can re-enter without exiting
    while(1){
    	printf("Input: \n");
		cin.getline(str,200);
		fname = str;
		docFile = fopen(str,"rb+");
		if(docFile == NULL) 
			printf("error!\n\n");
		else 
		    break;
		fclose(docFile);
    }

    // Timing starts after the user enters the correct file path
    start1=clock();
	
    // I found that I could read the information in the word document directly through the fread function
    // without first unzipping the file to read the OPENXml format
    // But there are always some headers that you can't read with the fread function
    // so we need to put the info of Word in a temporary.txt
    rewrite = getfileall(fname);
    New = fopen("temporary.txt","w+");
    fputs(rewrite,New);
    fclose(New);

    fname = "temporary.txt";      
	docFile = fopen(fname,"rb+");
	info = getfileall(fname);
//    if (info!=NULL) 
//	   puts(info);
//	printf("\n");
//	printf("%d",strlen(info)); 
	
	// We used method of string matching to find the offset for each keyword 
	// and read from the beginning of the file each time
	bias = findit(info,wordsalt,1)+2;
    fseek(docFile,bias+strlen(wordsalt),SEEK_SET);
	fread(saltValue,sizeof(char),24,docFile);
	saltValue = saltValue + '\0';
	
	bias = findit(info,wordinput,0)+2;
    fseek(docFile,bias+strlen(wordinput),SEEK_SET);
	fread(encryptedVerifierHashInput,sizeof(char),24,docFile);
	encryptedVerifierHashInput = encryptedVerifierHashInput + '\0';
	
	bias = findit(info,wordvalue,0)+2;
    fseek(docFile,bias+strlen(wordvalue),SEEK_SET);
	fread(encryptedVerifierHashValue,sizeof(char),44,docFile);
	encryptedVerifierHashValue = encryptedVerifierHashValue + '\0';

	de_saltValue = b64_decode(saltValue,strlen(saltValue));
	de_encryptedVerifierHashInput = b64_decode(encryptedVerifierHashInput,strlen(encryptedVerifierHashInput));
	de_encryptedVerifierHashValue = b64_decode(encryptedVerifierHashValue,strlen(encryptedVerifierHashValue));

	u8Tou32(de_encryptedVerifierHashInput,VerifierHashInput,16);
	u8Tou32(de_encryptedVerifierHashValue,VerifierHashValue,32);

	// puts("VerifierHashInput: ");
	// for(int n=0;n<4;n++){
	// 	printf("%08x ", VerifierHashInput[n]);
	// }
	// putchar('\n');

	// puts("VerifierHashValue: ");
	// for(int n=0;n<8;n++){
	// 	printf("%08x ", VerifierHashValue[n]);
	// }
	// putchar('\n');

 
	// printf("%s\n", saltValue);
	// printf("%s\n", encryptedVerifierHashInput);
	// printf("%s\n", encryptedVerifierHashValue);
	// putchar('\n');

    //  puts("Base64_decode: ");
	// for (int n = 0; n < 16; n++)
	// 	printf("%02x ", de_saltValue[n]);
	// putchar('\n');
	// for (int n = 0; n < 16; n++)
	// 	printf("%02x ", de_encryptedVerifierHashInput[n]);
	// putchar('\n');
	// for (int n = 0; n < 32; n++)
	// 	printf("%02x ", de_encryptedVerifierHashValue[n]);
	// putchar('\n');

}

// String matching function
int issame(char *p1,char *p2){
    int i=0;
    for(i=0;;i++){
        if (p2[i]=='\0') return 1;
        if (p1[i]=='\0') return 0;
        if (p1[i]!=p2[i]) return 0;
    }
    return 0;
}
int findit(char *p1,char *p2,int t){

    int count = 0;
    int findpoint = 0;
	 
    for(int i=0;p1[i]!='\0';i++)   
        if (issame(p1+i,p2)==1){
            findpoint = i;
            count++;
            if(t==0)break;
            if(count==2&&t==1)break;
        }
    return findpoint;
}

// Reads all the information in the file into a string
char *getfileall(char *fname)
{
	FILE *fp;
	char *str;
	char txt[1000];
	int filesize;
	int i=0;
	if ((fp=fopen(fname,"rb+"))==NULL){
		printf("open file %s error!\n",fname);
		return NULL;
	}
 
	fseek(fp,0,SEEK_END); 
 
	filesize = ftell(fp);
	str=(char *)malloc(filesize);
	str[0]=0;
 
	rewind(fp);

    while((fgets(txt,50,fp))!=NULL){
		strcat(str,txt);
	}
	fclose(fp);
	return str;
}
