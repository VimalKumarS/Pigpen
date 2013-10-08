#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <stdlib.h>

long long RotKeyLen =0;
long long RotKeyLen1 =0;
char pair1[]="UW";
char pair2[]="LA";
char pair3[]="ET";
char Cipher[]= "UHLEQFVTCPPWMPDOREERRIODIWLTUAREREHTAAFBAENO"
	"FERAEYHYOZIPVCYOSFKOYTESGHQPOTQNMDAPSTMGYIBO"
	"QRPFESTTLPAAFEEUHTSBFTNKTSVVSUIWTOGYSTEFMHFRO"
	"WOFZHERERPEUHTSBFTNKTSLHTUOTDLHTLPHSYQTGGVT";//"VBECOBE";
char originalAlphabet[] ="BCDFGHIJKMNOPQRSVXYZUWLAET";//"ABCDEFGHIJKLMNOPQRSTUVWXYZ";//"BCDFGHIJKMNOPQRSVXYZ";//ANBOCPDQERFSGTHUIVJWKXLYMZ
char keyInit[]="0123"; // to generate the random key
long dscore[676];  // score based on number of diagram
char *pattern[676];
//char Rotat[6][5]={"AGIC","BDHF","JPRL","KMQO","STVU","WXZY"};  // taken as anti clock wise
//char Rotat1[2]={'E','N'};

int key[]={1,2,1,0,0,3,3};//{0,0,0,0,0,0}; //,0  add one more 0 for key length of 7  {1,2,1,0,0,3,3};
char Rotat[6][5]={"????","????","????","????","????","????"};//{"UW??","LA??","ET??","????","????","????"};  // taken as anti clock wise   move backword
char Rotat1[2]={'?','?'};
long long Total=0;
char line[16];
int keyLen =6; // checking for key lenght of 7
double score=0;
int scoreSet=0;  // 1 initial score is set and 0 not set
char *originalMessage;	


char DecyptPigPen(char (*Rotat)[5],char (*Rotat1),int key[5], char* CipherText,int keyLen,char msg[177])
{
	char oMessage[177];
	int i=0,k=0,pos=0,ky,newPos,flag;
	unsigned int msgLength = strlen(CipherText);
	int ch;
	char *m;
	char *originalMessage1;
	int txtLen = strlen(CipherText);
	//originalMessage1=NULL;
	//oMessage=NULL;
	//oMessage=NULL;
	//oMessage = (char *)malloc((strlen(Cipher))+1) ;

	for(i=0; i<txtLen;i++) // for each text character
	{
		ch=CipherText[i];
		flag=0;
		for(k=0; k<6;k++) // for 6 rotat key - combination
		{

			m = strchr(Rotat[k], ch);
			if(m != NULL)
			{
				flag=1;
				pos=m-Rotat[k]; // get the position of the character
				ky=key[i % keyLen];
				newPos=pos-ky;
				if(newPos==0)
				{
					oMessage[i]=Rotat[k][newPos];
				}
				else
				{
					if(newPos>0)
					{
						oMessage[i]=Rotat[k][newPos];
					}
					else
					{
						oMessage[i]=Rotat[k][4+newPos];
					}
				}
				//printf("char %c" ,*m);
				break;
			}

		}
		if(flag==0)
		{
			for(k=0; k<2;k++)
			{
				if(ch==Rotat1[k])
					oMessage[i]=ch;

				//m = strchr(Rotat1[k], ch);
				//if(m != NULL)
				//{
				//	originalMessage[i]=*m;
				//}
			}
		}
		m=NULL;

	}
	oMessage[msgLength] = '\0';
	for ( i=0; i<177; i++ )
	{

		msg[i]=oMessage[i];
		//free(dMessage);
	}

	//oMessage=originalMessage1;

	//free(originalMessage1);

}

void EncyptPigPen(char (*Rotat)[5],char (*Rotat1),int *key, char* plainText,char *encryptMessage,int keyLen)
{
	int i=0,k=0,pos=0,ky,newPos,flag;
	unsigned int msgLength = strlen(plainText);
	int ch;
	char *m;

	int txtLen = strlen(plainText);

	for(i=0; i<txtLen;i++) // for each text character
	{
		ch=plainText[i];
		flag=0;
		for(k=0; k<6;k++) // for 6 rotat key - combination
		{

			m = strchr(Rotat[k], ch);
			if(m != NULL)
			{
				flag=1;
				pos=m-Rotat[k]; // get the position of the character
				ky=key[i % keyLen];
				newPos=pos+ky;
				if(newPos==0)
				{
					encryptMessage[i]=Rotat[k][newPos];
				}
				else
				{
					if(newPos>3)
					{
						encryptMessage[i]=Rotat[k][newPos-4];
					}
					else
					{
						encryptMessage[i]=Rotat[k][newPos];
					}
				}
				//printf("char %c" ,*m);
				break;
			}

		}
		if(flag==0)
		{
			for(k=0; k<2;k++)
			{
				if(ch==Rotat1[k])
					encryptMessage[i]=ch;

				//m = strchr(Rotat1[k], ch);
				//if(m != NULL)
				//{
				//	encryptMessage[i]=*m;
				//}
			}
		}
		m=NULL;

	}
	encryptMessage[msgLength] = '\0';
}
void swap (char *x, char *y)
{
	char temp;
	temp = *x;
	*x = *y;
	*y = temp;
}

int CheckForKey(char (*Rotat)[5],char * hpair)
{
	int k,flag=0;
	char *m;
	char ch=hpair[0];
	for(k=0; k<6;k++) // for 6 rotat key - combination
	{
		m = strchr(Rotat[k], ch);
		if(m != NULL)
		{
			ch=hpair[1];
			m = strchr(Rotat[k], ch);
			if(m!=NULL)
			{
				return 1;
			}
		}
	}
	return 0;
}
int fillValidateRotatKey(char (*Rotat)[5],char *a)
{
	//set up the key
	int i,k,t=0;
	int flag=0;
	for(i=0;i<6;i++)
	{
		for(k=0;k<4;k++)
		{
			Rotat[i][k]=a[t];
			t++;
		}
		Rotat[i][k]='\0';
	}


	//Now match the key group if that map our criteria
	if(CheckForKey(Rotat,pair1)==1 )
	{
		if( CheckForKey(Rotat,pair2)==1  )
		{
			if(CheckForKey(Rotat,pair3)==1)
			{
				return 1;
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}



}

int FillinRotKey(char (*Rotat)[5],char *a)
{
	int i,t=0;
	int k=6;
	int flag=0;
	Rotat[0][2]=a[0];
	Rotat[0][3]=a[1];
	Rotat[0][4]='\0';

	Rotat[1][2]=a[2];
	Rotat[1][3]=a[3];
	Rotat[1][4]='\0';

	Rotat[2][2]=a[4];
	Rotat[2][3]=a[5];
	Rotat[1][4]='\0';

	for(i=3;i<6;i++)
	{
		for (t=0;t<4;t++)
		{
			Rotat[i][t]=a[k];
			k++;
		}
		Rotat[i][t]='\0';
	}
	Rotat1[0]=a[k];
	Rotat1[1]=a[++k];

	return 1;
}

int identifyDefaultKey(char (*Rotat)[5],char * hpair)
{
	int i,k,key=0;
	int flag=0;
	char *m;
	char *p;
	char ch=hpair[0];
	for(k=0;k<6;k++)
	{
		m = strchr(Rotat[k], ch);  // positon of u
		if(m != NULL)
		{
			ch=hpair[1];
			p = strchr(Rotat[k], ch);  // position of w
			if(p>m)
			{
				key=p-m;
			}
			else
			{
				if(m-p==3)
				{
					key=1;
				}
				else if( m-p==1)
				{
					key=3;
				}
				else
				{
					key=2;
				}
			}
			break;
		}

	}
	return 4-key;
}

int compare (const void * a, const void * b)
{
	return ( *(char *)a - *(char *)b );
}
void permuteWithRepRecur (char *str, char* data, char (**KeyPer),int last, int index)
{
	int i, len = strlen(str);

	// One by one fix all characters at the given index and recur for the
	// subsequent indexes
	for ( i=0; i<len; i++ )
	{
		// Fix the ith character at index and if this is not the last index
		// then recursively call for higher indexes
		data[index] = str[i] ;

		// If this is the last index then print the string stored in data[]
		if (index == last)
		{
			KeyPer[RotKeyLen] = (char *) malloc(sizeof(char)*5); 
			strcpy(KeyPer[RotKeyLen],data);  //  printf("%d%s\n", i,a);
			RotKeyLen++;
			KeyPer[RotKeyLen] = (char *) malloc(sizeof(char)*5); 
			KeyPer[RotKeyLen][5]='\0';
			//printf("%s\n", data);
		}
		else // Recur for higher indexes
			permuteWithRepRecur (str, data,KeyPer, last, index+1);
	}
}
/*long fact(int n){
if(n==1)
return 1;
else
return(n*fact(n-1));
}*/
void generateAllPermuteWithRep(char *str,char (**KeyPer))
{
	int len = strlen (str) ;

	// Create a temp array that will be used by allLexicographicRecur()
	char *data = (char *) malloc (sizeof(char) * (len + 1)) ;
	data[len] = '\0';

	// Sort the input string so that we get all output strings in
	// lexicographically sorted order
	qsort(str, len, sizeof(char), compare);

	// Now print all permutaions
	permuteWithRepRecur (str, data,KeyPer, len-1, 0);

	// Free data to avoid memory leak
	free(data);
}
long SearchForScore(char txt[], char* pattern[], long* dscore)
{
	int i;
	int count= sizeof(dscore) /8;

	for (i = 0; i < 676; i++)
	{
		if(strcmp(pattern[i],txt)==0)
		{
			return dscore[i];
		}
	}
	return 0;

}
double GetScore(char *text, long long Total, char* pattern[], long * dscore)
{
	long textLen=0,j;
	int i;
	char ptrn[3];
	long double prob;
	double intscore=0;
	textLen= strlen(text);

	for(i=0; i<textLen;i++)
	{
		if(i+1<textLen)
		{
			ptrn[0]=text[i];
			ptrn[1]=text[i+1];
			ptrn[2]='\0';
			//printf("%s",ptrn);
			j=SearchForScore(ptrn,pattern,dscore);
			if(j!=0)
			{
				prob=0;
				prob=((double)j)/Total;
				intscore=intscore+(log10(prob));
			}
		}
	}
	return intscore;
}
void setOriginalMessage(char *dMessage)
{
	int len=strlen(Cipher);
	int i=0;
	originalMessage=NULL;
	originalMessage = (char *)malloc((strlen(Cipher))+1) ;
	for ( i=0; i<len; i++ )
	{

		originalMessage[i]=dMessage[i];
		//free(dMessage);
	}
	originalMessage[len]='\0';
}
// once the key is set up validate the score
void verifyThePermutation(char *a,char **KeyPer)
{
	int flag=0;
	int k=0;
	int i;
	FILE *fptxt;
	//int key[]={0,0,0,0,0,0};
	//char Rotat[6][5];  // taken as anti clock wise
	//char Rotat1[2] ; //={'E','N'};9
	double ParentScore;
	//char *dMessage;	
	char dMessage[177];
	char tempMsg[177];
	flag=fillValidateRotatKey(Rotat,a); // validating that pair are in correct group

	//flag=FillinRotKey(Rotat,a); 

	Rotat1[0]=a[24]; //18
	Rotat1[1]=a[25]; //19
	//Rotat1[2]='\0';

	if(flag==1)
	{
		key[0]=identifyDefaultKey(Rotat,pair1); //UW
		key[1]=0; // for H
		key[2]=identifyDefaultKey(Rotat,pair2); // LA
		key[3]=identifyDefaultKey(Rotat,pair3); //ET

		//dMessage=NULL;
		//dMessage = (char *)malloc((strlen(Cipher))+1) ;

		for(k=0; k<16;k++)  // 64 for key length of 7 else 16 for key length of 6
		{
			key[4]=KeyPer[k][2]-48;  //k[1]
			key[5]=KeyPer[k][3]-48;  //2
			//key[6]=KeyPer[k][3]-48;
			// veryfy the score print the best score for that combination
			//Get the decoded message once with the current key parrtern
			// then calulate the score 
			// verify the score and repeat the iteration with other pattern


			// Decrypt using standard approach

			DecyptPigPen(Rotat,Rotat1,key,Cipher,keyLen,dMessage); // move back in the key group to get the correct key

			for ( i=0; i<177; i++ )
			{

				tempMsg[i]=dMessage[i];
				//free(dMessage);
			}

			ParentScore=GetScore(tempMsg, Total, pattern, dscore);

			if(score==0 && scoreSet==0)
			{
				score=ParentScore;
				scoreSet=1; // initial round of score is set
				free(originalMessage);
				setOriginalMessage(tempMsg);

				printf("\n Key : %d%d%d%d%d%d --- Score : %lf \n",key[0],key[1],key[2],key[3],key[4],key[5],score);
				printf("\n Rotation Key %s - %s - %s - %s - %s - %s - %c - %c\n",Rotat[0],Rotat[1],Rotat[2],Rotat[3],Rotat[4],Rotat[5],Rotat1[0],Rotat1[1]);
				printf(" Original message %s \n" , originalMessage);
				printf("--------------------------- \n");		
				//text to file
				fptxt=fopen("PigPen.txt","a+");
				fprintf( fptxt, "%d%d%d%d%d%d  Score : %lf \n", key[0],key[1],key[2],key[3],key[4],key[5],score);
				fprintf(fptxt,"%s%s%s%s%s%s",Rotat[0],Rotat[1],Rotat[2],Rotat[3],Rotat[4],Rotat[5]);
				fprintf(fptxt,"%c%c \n",Rotat1[0],Rotat1[1]);
				fprintf(fptxt," Original message %s \n" , originalMessage);
				fprintf(fptxt,"\n--------------------------- %c",'\n');
				fflush(stdin);
				fclose(fptxt);
			}
			if(score<ParentScore)
			{
				score=ParentScore;
				free(originalMessage);
				setOriginalMessage(tempMsg);
				//originalMessage=dMessage;
				//free(dMessage);


				//free(dMessage);
				//originalMessage=NULL;
				printf("\n Key : %d%d%d%d%d%d --- Score : %lf \n",key[0],key[1],key[2],key[3],key[4],key[5],score);
				printf("\n Rotation Key %s - %s - %s - %s - %s - %s - %c - %c\n",Rotat[0],Rotat[1],Rotat[2],Rotat[3],Rotat[4],Rotat[5],Rotat1[0],Rotat1[1]);
				printf(" Original message %s \n" , originalMessage);
				printf("--------------------------- \n");		
				//text to file
				fptxt=fopen("PigPen.txt","a+");
				fprintf( fptxt, "%d%d%d%d%d%d  Score : %lf \n", key[0],key[1],key[2],key[3],key[4],key[5],score);
				fprintf(fptxt,"%s%s%s%s%s%s",Rotat[0],Rotat[1],Rotat[2],Rotat[3],Rotat[4],Rotat[5]);
				fprintf(fptxt,"%c%c \n",Rotat1[0],Rotat1[1]);
				fprintf(fptxt," Original message %s \n" , originalMessage);
				fprintf(fptxt,"\n--------------------------- %c",'\n');
				fflush(stdin);
				fclose(fptxt);
			}
		}


	}

	//free(dMessage);
	return;
}

//Called from main 
void perAlphabet(char *a, int i, int n,char **KeyPer) 
{
	int j; 
	char c[5];
	if (i == n)
	{
		//KeyPer[RotKeyLen1] = (char *) malloc(sizeof(char)*26); 
		//strcpy(KeyPer[RotKeyLen1],a);  // 
		/*********************************/
		//printf("%s\n",a);
		verifyThePermutation(a,KeyPer);  // this is the calling point of the function 

		/******************/
		//	RotKeyLen1++;
		//KeyPer[RotKeyLen1] = (char *) malloc(sizeof(char)*26); 
		//KeyPer[RotKeyLen1][26]='\00000';  
	}
	else
	{
		for (j = i; j <= n; j++)
		{
			swap((a+i), (a+j));
			perAlphabet(a, i+1, n,KeyPer);
			swap((a+i), (a+j)); //backtrack
		}
	}

} 
// Move forward while encoding // move back word while decoding [to plain text]
int main()
{


	int i=0,len;
	//char CipherText1[] = "VBECOBE";
	//char PlainText[] = "THECODE";
	//int key[]={1,2,1,0,0,3,3};
	//int keyLen = sizeof(key)/ sizeof(key[0]);
	//char **KeyPerAlpha=(char **)malloc(sizeof(char *)*fact(20)) ;
	char **KeyPer; // generate 4*4*4*4 pairs but we will take the last 2 or 3 digit for substitution to make the key of length ogf 6 or 7
	char *p;

	//char *originalMessage;	
	FILE *fp=fopen( "english_bigrams.txt", "r" );
	// Decrypt using standard approach
	//originalMessage = (char *)malloc((strlen(CipherText1))+1) ;
	//originalMessage=DecyptPigPen(Rotat,Rotat1,key,CipherText1,7);
	//To Encrypt
	//originalMessage = (char *)malloc((strlen(PlainText))+1) ;
	//EncyptPigPen(Rotat,Rotat1,key,PlainText,originalMessage,keyLen);
	//	printf("Decrypted Text %s \n", originalMessage);

	//
	//RotKeyLen1=0;



	if(fp==NULL)
	{
		fclose(fp);
		printf("File not found!!!");
		printf("Press any key to exit");
		getch();
		exit(0);
	}
	printf("Reading english_bigrams.txt. \n");
	for(i=0; i<676; i++)
	{
		fscanf(fp, " %s %d\n", line, &dscore[i]);
		Total+=dscore[i];

		len=strlen(line);
		p= (char *)malloc(len+1);
		strcpy(p,line);
		pattern[i]=p;

	}
	fclose(fp);
	printf("Read complete.");

	KeyPer=(char **)malloc(sizeof(char *)*256);
	RotKeyLen=0;
	generateAllPermuteWithRep(keyInit,KeyPer);   // initialize the key
	//perAlphabet(originalAlphabet,0,19,KeyPer);
	perAlphabet(originalAlphabet,0,25,KeyPer);
	//RotKeyLen1++;
	//KeyPer[RotKeyLen1] = (char *) malloc(sizeof(char)*26); 
	//KeyPer[RotKeyLen1][26]='\00000';  
	//perAlphabet(keyInit,KeyPer,0,3);




	free(originalMessage);

	printf("Job Completed , Press any key to continue!!");

	getch();
}

