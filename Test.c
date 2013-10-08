#include<stdio.h>
#include<string.h>
#include<conio.h>
#include<stdlib.h>
#include<math.h>
#include<time.h>

int count = 0;
//char **allKeys;
char allKeys[4096][7];
char cipherText[]="UHLEQFVTCPPWMPDOREERRIODIWLTUAREREHTAAFBAENO"
				"FERAEYHYOZIPVCYOSFKOYTESGHQPOTQNMDAPSTMGYIBO"
				"QRPFESTTLPAAFEEUHTSBFTNKTSVVSUIWTOGYSTEFMHFRO"
				"WOFZHERERPEUHTSBFTNKTSLHTUOTDLHTLPHSYQTGGVT";
char line[16];
long dscore[676];
long long totalScore = 0;
char *bigramPattern[676];
char key[] = "0123"; // considering length = 6, total combinations = 4^6 = 4096
// int rotationKeyLength = 0;
char originalAlphabet[] ="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
double score=0;
int scoreSet=0;  // 1 initial score is set and 0 not set
char *originalMessage;	
char pairUW[]="UW";
char pairLA[]="LA";
char pairET[]="ET";
char rotate[6][5]={"????","????","????","????","????","????"};//{"UW??","LA??","ET??","????","????","????"};  // taken as anti clock wise   move backword
char rotate1[2]={'?','?'};
int keyLength = 6;

/*************************************************************
	GLOBAL VARIABLES END
*************************************************************/

void swap (char *x, char *y)
{
	char temp;
	temp = *x;
	*x = *y;
	*y = temp;
}

int checkForKey(char (*rotate)[5], char * hpair)
{
	int k;
	char *m, *n;
	for(k = 0; k < 6; k++) // for 6 rotat key - combination
	{
		m = strchr(rotate[k], hpair[0]);
		n = strchr(rotate[k], hpair[1]);
		if(m != NULL && n != NULL)
		{
			return 1;
		}
	}
	return 0;
}

long searchForScore(char txt[], char* pattern[], long* dscore)
{
	int i;
	for (i = 0; i < 676; i++)
	{
		if(strcmp(pattern[i], txt) == 0)
		{
			return dscore[i];
		}
	}
	return 0;
}

double getScore(char *text, long long total, char* bPattern[], long * dscore)
{
	long textLen=0, j;
	int i;
	char ptrn[3];
	long double prob;
	double intscore=0;
	textLen = strlen(text);

	for( i = 0; i < textLen; i++)
	{
		if( i + 1 < textLen)
		{
			ptrn[0] = text[i];
			ptrn[1] = text[i+1];
			ptrn[2] = '\0';
			//printf("%s",ptrn);
			j= searchForScore(ptrn, bPattern, dscore);
			if(j != 0)
			{
				prob = 0;
				prob =((double)j)/total;
				intscore = intscore + (log10(prob));
			}
		}
	}
	return intscore;
}

void setOriginalMessage(char *dMessage)
{
	int len = strlen(cipherText);
	int i = 0;
	originalMessage = NULL;
	originalMessage = (char *)malloc((strlen(cipherText)) + 1) ;
	for ( i=0; i < len; i++ )
	{
		originalMessage[i]=dMessage[i];
	}
	originalMessage[len]='\0';
}

int fillValidateRotateKey(char (*rotate)[5], char *alphabets)
{
	//set up the key
	int i, k , t = 0;
	int flag = 0;
	for(i = 0; i < 6; i++)
	{
		for(k = 0; k < 4; k++)
		{
			rotate[i][k] = alphabets[t];
			t++;
		}
		rotate[i][k]='\0';
	}
	//Now match the key group if that map our criteria
	if(checkForKey(rotate, pairUW) == 1 && checkForKey(rotate, pairLA) == 1 && checkForKey(rotate, pairET) == 1)
	{
		return 1;
	} else {
		return 0;
	}

}

int identifyDefaultKey(char (*rotate)[5],char * hpair)
{
	int k, key = 0;
	int flag = 0;
	char *m, *p;
	for(k = 0; k < 6; k++)
	{
		m = strchr(rotate[k], hpair[0]);  // positon of u
		p = strchr(rotate[k], hpair[1]);  // position of w
		if(m != NULL && p != NULL)
		{
			if(p > m)
			{
				key = p - m;
			}
			else
			{
				key = 4 - (m - p);
			}
			break;
		}
	}
	return 4-key;  // why 4 - key? shouldn't it be key?
}

char* decryptPigPen(char (*rotate)[5],char (*rotate1),char key[5], char* cipherText, int keyLength)
{
	char oMessage[177];
	int i = 0, k = 0, pos = 0, ky, newPos, flag;
	unsigned int msgLength = strlen(cipherText);
	int ch;
	char *m;
	int txtLen = strlen(cipherText);

	for(i = 0; i < txtLen; i++) // for each text character
	{
		ch = cipherText[i];
		flag = 0;
		for(k = 0; k < 6; k++) // for 6 rotat key - combination
		{
			m = strchr(rotate[k], ch);
			if(m != NULL)
			{
				flag = 1;
				pos = m - rotate[k]; // get the position of the character
				ky = key[i % keyLength];
				newPos = pos-ky;
				if(newPos == 0)
				{
					oMessage[i] = rotate[k][newPos];
				}
				else
				{
					if(newPos > 0)
					{
						oMessage[i] = rotate[k][newPos];
					}
					else
					{
						oMessage[i] = rotate[k][ 4 + newPos];
					}
				}
				//printf("char %c" ,*m);
				break;
			}

		}
		if(flag == 0 )
		{
			for(k = 0; k < 2; k++)
			{
				if(ch == rotate1[k])
					oMessage[i] = ch;
			}
		}
		m = NULL;

	}
	oMessage[msgLength] = '\0';
	return oMessage;
}

// once the key is set up validate the score
void verifyThePermutation(char *alpha,char **keyPermuted)
{
	int flag = 0;
	int k = 0;
	int i;
	FILE *fptxt;
	//int key[]={0,0,0,0,0,0};
	//char Rotat[6][5];  // taken as anti clock wise
	//char Rotat1[2] ; //={'E','N'};9
	double parentScore;
	char *dMessage;	
	char tempMsg[177];
	flag = fillValidateRotateKey(rotate, alpha); // validating that pair are in correct group

	rotate1[0]= alpha[24]; //18
	rotate1[1]= alpha[25]; //19

	if(flag == 1)
	{
		key[0] = identifyDefaultKey(rotate, pairUW); //UW
		key[1] = 0; // for H
		key[2] = identifyDefaultKey(rotate, pairLA); // LA
		key[3] = identifyDefaultKey(rotate, pairET); //ET

		for(k = 0; k < 16; k++)  // 64 for key length of 7 else 16 for key length of 6
		{
			key[4] = keyPermuted[k][2] - 48;  //k[1]
			key[5] = keyPermuted[k][3] - 48;  //2
			//key[6]=KeyPer[k][3]-48;
			// veryfy the score print the best score for that combination
			//Get the decoded message once with the current key parrtern
			// then calulate the score 
			// verify the score and repeat the iteration with other pattern

			// Decrypt using standard approach
			dMessage = decryptPigPen(rotate, rotate1, key, cipherText, keyLength); // move back in the key group to get the correct key

			for ( i = 0; i < 177; i++ )
			{
				tempMsg[i] = dMessage[i];
				//free(dMessage);
			}

			parentScore = getScore(tempMsg, totalScore, bigramPattern, dscore);

			if(score == 0 && scoreSet == 0)
			{
				score = parentScore;
				scoreSet = 1; // initial round of score is set
				free(originalMessage);
				setOriginalMessage(tempMsg);
			}
			if(score < parentScore)
			{
				score=parentScore;
				free(originalMessage);
				setOriginalMessage(tempMsg);
			}
			printf("\n Key : %d%d%d%d%d%d --- Score : %lf \n", key[0], key[1], key[2], key[3], key[4], key[5], score);
			printf("\n Rotation Key %s - %s - %s - %s - %s - %s - %c - %c\n", rotate[0], rotate[1], rotate[2], rotate[3], rotate[4], rotate[5], rotate1[0], rotate1[1]);
			printf(" Original message %s \n" , originalMessage);
			printf("--------------------------- \n");		
			//text to file
			fptxt=fopen("PigPen.txt","a+");
			fprintf( fptxt, "%d%d%d%d%d%d  Score : %lf \n", key[0], key[1], key[2], key[3], key[4], key[5], score);
			fprintf(fptxt,"%s%s%s%s%s%s", rotate[0], rotate[1], rotate[2], rotate[3], rotate[4], rotate[5]);
			fprintf(fptxt,"%c%c \n", rotate1[0], rotate1[1]);
			fprintf(fptxt," Original message %s \n", originalMessage);
			fprintf(fptxt,"\n--------------------------- %c",'\n');
			fflush(stdin);
			fclose(fptxt);
		}
	}
	//free(dMessage);
	return;
}


void permuteAlphabet(char *alpha, int i, int n,char **keyPermuted) 
{
	int j; 
	if (i == n)
	{
		printf("Verifying with %s\n", alpha);
		verifyThePermutation(alpha, keyPermuted);  // this is the calling point of the function 
	}
	else
	{
		for (j = i; j <= n; j++)
		{
			swap((alpha + i), ( alpha + j));
			permuteAlphabet(alpha, i + 1, n, keyPermuted);
			swap((alpha + i), (alpha + j)); //backtrack
		}
	}
} 

void knuthShuffle(char *alpha, int size)
{
	int i;
	int index;
	char ch;

	if (size == 0 || size == 1)
      return;

	srand(time(NULL));

	for (i = size - 2; i >= 0; i--)
	{
		index = rand() % (i+1);
		//swap(&alpha[index], &alpha[i]);
		ch = alpha[index];
		alpha[index] = alpha[i];
		alpha[i] = ch;
	}
}


void allKeyCombinations(char *input, char *output, int n, int i, int k){
	int j;
	if (i == k){
		//printf("%d:\t%c%c%c%c%c%c", count++, output[0], output[1], output[2], output[3], output[4], output[5]);
		// printf("%s", *output);
		// output[7] = '\0';
		//allKeys[count] = (char*)malloc( sizeof(char) * 7);
		strcpy(allKeys[count], output);
		count++;
		printf("%d:\t%s", count, allKeys[count-1]);
		printf("\n");
	}
	else{
		for(j = 0; j < n; j++){
			output[i] = input[j];
			output[i + 1] = '\0';
			allKeyCombinations(input, output, n, (i+1), k);
		}
	}
}


int main(){
	int i = 0, n, k = 6, length;
	char input[] = {'0','1', '2', '3'}, output[7];
	char *p;
	char *fileName = "english_bigrams.txt";
	FILE *fp = fopen( fileName, "r");

	n = sizeof(input)/sizeof(input[0]);
	//allKeys = (char **)malloc(sizeof(char) * 4096);
	printf("Creating all key combinations...\n");
	allKeyCombinations(input, output, n, i ,k);
	printf("Done creating all key combinations...\n");

	if ( fp == NULL ) {
		printf("File not found. Program terminated.\n");
		getch();
		fclose(fp);
		exit(0);
	}

	printf("Reading file %s\n", fileName);

	for(i = 0; i < 676; i++)
	{
		fscanf(fp, " %s %d\n", line, &dscore[i]);
		totalScore += dscore[i];

		length = strlen(line);
		p = (char *)malloc( length + 1 );
		strcpy( p, line );
		bigramPattern[i] = p;

	}
	fclose(fp);
	printf("Finished reading %s\n", fileName);
	while( 1 ) {
		knuthShuffle(originalAlphabet, sizeof(originalAlphabet));
		verifyThePermutation(originalAlphabet, allKeys);
	}
	// permuteAlphabet(originalAlphabet, 0, 25, allKeys);

	getch();
	return(0);
}

