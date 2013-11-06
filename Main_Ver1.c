#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <stdlib.h>

#define trigramCount 17556
#define digramCount 676
#define MAXIteration 20000

long long RotKeyLen =0;
long long RotKeyLen1 =0;
char pair1[]="UW";
char pair2[]="LA";
char pair3[]="ET";

char Cipher[]= "UHLEQFVTCPPWMPDOREERRIODIWLTUAREREHTAAFBAENOFERAEYHYOZIPVCYOSFKOYTESGHQPOTQNMDAPSTMGYIBOQRPFESTTLPAAFEEUHTSBFTNKTSVVSUIWTOGYTSTEFMHFROWOFZHERERPEUHTSBFTNKTSLHTUOTDLHTLPHSYQTGGVT";//"VBECOBE";
char originalAlphabet[] ="FINVAQLGKCZBPETYOSHRWUMDXJ";//"GIHNKXJMOZPRTEVQWUFCLADYSB";//"OZPRTEVQKJMIGNHCXBLYSAWUFD";//"BCDFGHIJKMNOPQRSVXYZUWLAET";//"ANBOCPDQERFSGTHUIVJWKXLYMZ";//"BCDFGHIJKMNOPQRSVXYZUWLAET";//"ABCDEFGHIJKLMNOPQRSTUVWXYZ";//"BCDFGHIJKMNOPQRSVXYZ";//ANBOCPDQERFSGTHUIVJWKXLYMZ
char keyInit[]="0123"; // to generate the random key
long dscore[trigramCount];  // score based on number of diagram
char *pattern[trigramCount];
//char Rotat[6][5]={"AGIC","BDHF","JPRL","KMQO","STVU","WXZY"};  // taken as anti clock wise
//char Rotat1[2]={'E','N'};

int key[]={0,0,0,0,0,0,0};//{0,0,0,0,0,0}; //,0  add one more 0 for key length of 7  {1,2,1,0,0,3,3};
char RotatPattern[6][5]={"????","????","????","????","????","????"};//{"UW??","LA??","ET??","????","????","????"};  // taken as anti clock wise   move backword
char RotatPattern_Constant[2]={'?','?'};
long long Total=0; 
char line[16];
int keyLen =7; // checking for key lenght of 7 /6
double score=0;
int scoreSet=0;  // 1 initial score is set and 0 not set
char *originalMessage;	


/*Begin region  generate the key*/
void exchange2letters(char *key){
	int i = rand()%25;
	int j = rand()%25;
	char temp = key[i];
	key[i]= key[j];
	key[j] = temp;
}

void swap2rows(char *key){
	int i = rand()%5;
	int j = rand()%5;
	char temp;
	int k;
	for(k=0;k<5;k++){
		temp = key[i*5 + k];
		key[i*5 + k] = key[j*5 + k];
		key[j*5 + k] = temp;
	}
}

void swap2cols(char *key){
	int i = rand()%5;
	int j = rand()%5;
	char temp;
	int k;
	for(k=0;k<5;k++){
		temp = key[k*5 + i];
		key[k*5 + i] = key[k*5 + j];
		key[k*5 + j] = temp;
	}
}


void modifyKey(char *newKey,char *oldKey){
	int k,j,i = rand()%50;
	switch(i){
	case 0: strcpy(newKey,oldKey); swap2rows(newKey); break;
	case 1: strcpy(newKey,oldKey); swap2cols(newKey); break;       
	case 2: for(k=0;k<26;k++) newKey[k] = oldKey[25-k]; 
		//newKey[25] = '\0';
		break; // reverse whole keysquare
	case 3: for(k=0;k<5;k++) for(j=0;j<5;j++) newKey[k*5 + j] = oldKey[(4-k)*5+j]; // swap rows up-down
		//newKey[26] = '\0';
		break;
	case 4: for(k=0;k<5;k++) for(j=0;j<5;j++) newKey[j*5 + k] = oldKey[(4-j)*5+k]; // swap cols left-right
		//newKey[26] = '\0';
		break;
	default:strcpy(newKey,oldKey); 
		exchange2letters(newKey);
	}
}
/* endregion */

char DecyptPigPen(char (*RotatPattern)[5],char (*RotatPattern_Constant),int key[5], char* CipherText,int keyLen,char msg[177])
{
	char oMessage[177];
	int i=0,k=0,pos=0,ky,newPos,flag;
	unsigned int msgLength = strlen(CipherText);
	int ch;
	char *m;
	char *originalMessage1;
	int txtLen = strlen(CipherText);


	for(i=0; i<txtLen;i++) // for each text character
	{
		ch=CipherText[i];
		flag=0;
		for(k=0; k<6;k++) // for 6 rotat key - combination
		{

			m = strchr(RotatPattern[k], ch);
			if(m != NULL)
			{
				flag=1;
				pos=m-RotatPattern[k]; // get the position of the character
				ky=key[i % keyLen];
				newPos=pos-ky;
				if(newPos==0)
				{
					oMessage[i]=RotatPattern[k][newPos];
				}
				else
				{
					if(newPos>0)
					{
						oMessage[i]=RotatPattern[k][newPos];
					}
					else
					{
						oMessage[i]=RotatPattern[k][4+newPos];
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
				if(ch==RotatPattern_Constant[k])
					oMessage[i]=ch;

			
			}
		}
		m=NULL;

	}
	//oMessage[178] = '\0';
	for ( i=0; i<177; i++ )
	{

		msg[i]=oMessage[i];
		//free(dMessage);
	}
	msg[177]='\0';
	

}

//Validate the Rotation key pair contain - requried pair
int CheckForKey(char (*RotatPattern)[5],char * hpair)
{
	int k,flag=0;
	char *m;
	char ch=hpair[0];
	for(k=0; k<6;k++) // for 6 rotat key - combination
	{
		m = strchr(RotatPattern[k], ch);
		if(m != NULL)
		{
			ch=hpair[1];
			m = strchr(RotatPattern[k], ch);
			if(m!=NULL)
			{
				return 1;
			}
		}
		ch=hpair[0];
	}
	return 0;
}

//Fill in the rotation key based on the permutation of the alphabet
int fillValidateRotatKey(char (*RotatPattern)[5],char *a)
{
	//set up the key
	int i,k,t=0;
	int flag=0;
	for(i=0;i<6;i++)
	{
		for(k=0;k<4;k++)
		{
			RotatPattern[i][k]=a[t];
			t++;
		}
		RotatPattern[i][k]='\0';
	}


	//Now match the key group if that map our criteria
	if(CheckForKey(RotatPattern,pair1)==1 )
	{
		if( CheckForKey(RotatPattern,pair2)==1  )
		{
			if(CheckForKey(RotatPattern,pair3)==1)
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

// Check for particular rotation consist of requried pair
int identifyDefaultKey(char (*RotatPattern)[5],char * hpair)
{
	int i,k,key=0;
	int flag=0;
	char *m;
	char *p;
	char ch=hpair[0];
	for(k=0;k<6;k++)
	{
		m = strchr(RotatPattern[k], ch);  // positon of u
		if(m != NULL)
		{
			ch=hpair[1];
			p = strchr(RotatPattern[k], ch);  // position of w
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

//Called from generateAllPermuteWithRep method
int compare (const void * a, const void * b)
{
	return ( *(char *)a - *(char *)b );
}

//Called from generateAllPermuteWithRep method to generate the key value
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

// Generate the permutation for Rotation key number value
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

//Look for the score/frequency for an word from *gram file
long SearchForScore(char txt[], char* pattern[], long* dscore)
{
	int i;
	//int count= sizeof(dscore) /8;

	for (i = 0; i < trigramCount; i++)
	{
		if(strcmp(pattern[i],txt)==0)
		{
			return dscore[i];
		}
	}
	return 0;

}

//Compute the score for trigram word for the correponding cipher text
double GetScoreForTriGram(char *text, long long Total, char* pattern[], long * dscore)
{
	long textLen=0,j;
	int i;
	char ptrn[4];
	long double prob;
	double score=0;
	textLen= strlen(text);

	for(i=0; i<textLen;i++)
	{
		if(i+2<textLen)
		{
			ptrn[0]=text[i];
			ptrn[1]=text[i+1];
			ptrn[2]=text[i+2];
			ptrn[3]='\0';
			//printf("%s",ptrn);
			j=SearchForScore(ptrn,pattern,dscore);
			if(j!=0)
			{
				prob=0;
				prob=((double)j)/Total;
				score=score+(log10(prob));
			}
		}
		//free(ptrn);
	}
	return score;
}

void setOriginalMessage(char dMessages[177])
{
	int len=strlen(Cipher);
	int i=0;
	originalMessage=NULL;
	originalMessage = (char *)malloc((strlen(Cipher))+1) ;

	strcpy(originalMessage,dMessages);


}

//Verify the rotation permutation / store result in the file/ compute the score
void verifyThePermutation7(char *a,char **KeyPer)
{
	int flag=0;
	int k=0;
	int i;
	long iIteration=MAXIteration;
	FILE *fptxt;
	
	double ParentScore;
	char *dMessage;	
	
	//char testKey[26];
	//char maxKey[26];
	char *testKey;
	char *maxKey;
	testKey = (char *)malloc((strlen(originalAlphabet))+1) ;
	maxKey = (char *)malloc((strlen(originalAlphabet))+1) ;
	strcpy(testKey,a);
	strcpy(maxKey,a);
	dMessage = (char *)malloc((strlen(Cipher))+1) ;
	
	do
	{
		flag=fillValidateRotatKey(RotatPattern,testKey); // validating that pair are in correct group

		RotatPattern_Constant[0]=testKey[24]; //18
		RotatPattern_Constant[1]=testKey[25]; //19
		//Rotat1[2]='\0';

		if(flag==1)
		{
			key[0]=identifyDefaultKey(RotatPattern,pair1); //UW
			key[1]=0; // for H
			key[2]=identifyDefaultKey(RotatPattern,pair2); // LA
			key[3]=identifyDefaultKey(RotatPattern,pair3); //ET

			

			for(k=0; k<64;k++)  // 64 for key length of 7 else 16 for key length of 6
			{
				key[4]=KeyPer[k][1]-48;  //k[1]
				key[5]=KeyPer[k][2]-48;  //2
				key[6]=KeyPer[k][3]-48; // for key of length 7
				

				DecyptPigPen(RotatPattern,RotatPattern_Constant,key,Cipher,keyLen,dMessage); // move back in the key group to get the correct key

				ParentScore= GetScoreForTriGram(dMessage, Total, pattern, dscore);//

				if(score==0 && scoreSet==0)
				{
					score=ParentScore;
					scoreSet=1; // initial round of score is set
					free(originalMessage);
					setOriginalMessage(dMessage);

					printf("\n Key : %d%d%d%d%d%d%d --- Score : %lf \n",key[0],key[1],key[2],key[3],key[4],key[5],key[6],score);
					printf("\n Rotation Key %s - %s - %s - %s - %s - %s - %c - %c\n",RotatPattern[0],RotatPattern[1],RotatPattern[2],RotatPattern[3],RotatPattern[4],RotatPattern[5],RotatPattern_Constant[0],RotatPattern_Constant[1]);
					printf(" Original message %s \n" , originalMessage);
					printf("--------------------------- \n");		
					//text to file
					fptxt=fopen("PigPen.txt","a+");
					fprintf( fptxt, "%d%d%d%d%d%d%d  Score : %lf \n", key[0],key[1],key[2],key[3],key[4],key[5],key[6],score);
					fprintf(fptxt,"%s%s%s%s%s%s",RotatPattern[0],RotatPattern[1],RotatPattern[2],RotatPattern[3],RotatPattern[4],RotatPattern[5]);
					fprintf(fptxt,"%c%c \n",RotatPattern_Constant[0],RotatPattern_Constant[1]);
					fprintf(fptxt," Original message %s \n" , originalMessage);
					fprintf(fptxt,"\n--------------------------- %c",'\n');
					fflush(stdin);
					fclose(fptxt);
					//strcpy(maxKey,testKey);
				}
				if(score<ParentScore)
				{
					score=ParentScore;
					free(originalMessage);
					setOriginalMessage(dMessage);
					
					printf("\n Key : %d%d%d%d%d%d%d --- Score : %lf \n",key[0],key[1],key[2],key[3],key[4],key[5],key[6],score);
					printf("\n Rotation Key %s - %s - %s - %s - %s - %s - %c - %c\n",RotatPattern[0],RotatPattern[1],RotatPattern[2],RotatPattern[3],RotatPattern[4],RotatPattern[5],RotatPattern_Constant[0],RotatPattern_Constant[1]);
					printf(" Original message %s \n" , originalMessage);
					printf("--------------------------- \n");		
					//text to file
					fptxt=fopen("PigPen.txt","a+");
					fprintf( fptxt, "%d%d%d%d%d%d%d  Score : %lf \n", key[0],key[1],key[2],key[3],key[4],key[5],key[6],score);
					fprintf(fptxt,"%s%s%s%s%s%s",RotatPattern[0],RotatPattern[1],RotatPattern[2],RotatPattern[3],RotatPattern[4],RotatPattern[5]);
					fprintf(fptxt,"%c%c \n",RotatPattern_Constant[0],RotatPattern_Constant[1]);
					fprintf(fptxt," Original message %s \n" , originalMessage);
					fprintf(fptxt,"\n--------------------------- %c",'\n');
					fflush(stdin);
					fclose(fptxt);
					//strcpy(maxKey,testKey);
				}
			

			}


		}
		strcpy(maxKey,testKey);
		modifyKey(testKey,maxKey); 
		iIteration--;
	}while(iIteration>0 ); // After this analyse the result

	free(dMessage);
	free(testKey);
	return;
}

// Move forward while encoding // move back word while decoding [to plain text]
int main()
{


	int i=0,len;
	char **KeyPer; // generate 4*4*4*4 pairs but we will take the last 2 or 3 digit for substitution to make the key of length ogf 6 or 7
	char *p;

	//char *originalMessage;	
	FILE *fp=fopen( "english_trigrams.txt", "r" );  //english_bigrams.txt


	if(fp==NULL)
	{
		fclose(fp);
		printf("File not found!!!");
		printf("Press any key to exit");
		getch();
		exit(0);
	}
	printf("Reading english_trigrams.txt. \n");
	for(i=0; i<trigramCount; i++)
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
	
	verifyThePermutation7(originalAlphabet,KeyPer);

	free(originalMessage);

	printf("Job Completed , Press any key to continue!!");

	getch();
}

