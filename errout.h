/*
  errout.h - Header file for common definitions.

  Jason Hood, 29 June to 3 July, 2011.
*/

#ifndef ERROUT_H
#define ERROUT_H

#ifndef UNICODE
# define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#ifdef _WIN64
#define _WIN32_WINNT 0x0600	// MinGW-w64 wants this defined for Wow64 stuff
#else
#define _WIN32_WINNT 0x0500	// MinGW wants this defined for OpenThread
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define lenof(array) (sizeof(array)/sizeof(*(array)))
#define TSIZE(size)  ((size) * sizeof(TCHAR))


struct Globals
{
  HANDLE hStdOut;	// the original stdout
  HANDLE hStdCon;	// direct to console
  HANDLE hFilOut;	// file for stdout
  HANDLE hFilErr;	// file for stderr
  HANDLE hFilCon;	// file for combined output
  WORD	 console;	// flags to write to the console
  WORD	 errcol;	// colour to use for stderr
};

typedef struct Globals Globals;


int  ProcessType( LPPROCESS_INFORMATION );
void InjectDLL32( LPPROCESS_INFORMATION );
#ifdef DO_IMPORT
__declspec(dllimport)
#else
__declspec(dllexport)
#endif
void InjectDLL64( LPPROCESS_INFORMATION );


#define CODE32SIZE   20
#define GLOBAL32SIZE (6*4)

#endif
