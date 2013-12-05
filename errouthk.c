/*
  errouthk.c - Send stderr to stdout.

  Jason Hood, 29 June to 3 July, 2011.

  This is the WriteFile hook, needed to maintain the order between stderr and
  stdout when redirecting both.

  API hooking derived from ANSI.xs by Jean-Louis Morel, from his Perl package
  Win32::Console::ANSI (this version ripped out of ANSICON v1.40).

  v1.10, 13 & 14 November, 2013:
  * use all the improvements made to ANSICON v1.66.
*/

#include "errout.h"
#include <tlhelp32.h>

#ifdef __GNUC__
#define SHARED __attribute__((dllexport, shared, section(".shared")))
#else
#pragma data_seg(".shared", "read,write,shared")
#pragma data_seg()
#define SHARED __declspec(dllexport allocate(".shared"))
#endif


SHARED Globals global =
{
  NULL, 	// the original stdout
  NULL, 	// direct to console
  NULL, 	// file for stdout
  NULL, 	// file for stderr
  NULL, 	// file for combined output
  0,		// don't also write to console
  -1,		// don't colour stderr
};


BOOL WINAPI MyWriteFile( HANDLE hFile, LPCVOID lpBuffer,
			 DWORD nNumberOfBytesToWrite,
			 LPDWORD lpNumberOfBytesWritten,
			 LPOVERLAPPED lpOverlapped )
{
  BOOL setcol = FALSE;
  WORD col = 0; // silence gcc
  BOOL rc;

  HANDLE hStdOut = GetStdHandle( STD_OUTPUT_HANDLE );
  HANDLE hStdErr = GetStdHandle( STD_ERROR_HANDLE );

  if (hFile == hStdOut || hFile == hStdErr)
  {
    if (hFile == hStdOut)
    {
      if (global.console & 1)
      {
	WriteFile( global.hStdCon, lpBuffer, nNumberOfBytesToWrite,
		   lpNumberOfBytesWritten, NULL );
      }
      if (global.hFilOut != NULL)
      {
	WriteFile( global.hFilOut, lpBuffer, nNumberOfBytesToWrite,
		   lpNumberOfBytesWritten, NULL );
      }
    }
    else // (hFile == hStdErr)
    {
      if (global.errcol != (WORD)-1)
      {
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo( global.hStdCon, &csbi );
	col = csbi.wAttributes;
	setcol = TRUE;
	SetConsoleTextAttribute( global.hStdCon, global.errcol );
      }
      if (global.console & 2)
      {
	WriteFile( global.hStdCon, lpBuffer, nNumberOfBytesToWrite,
		   lpNumberOfBytesWritten, NULL );
      }
      if (global.hFilErr != NULL)
      {
	WriteFile( global.hFilErr, lpBuffer, nNumberOfBytesToWrite,
		   lpNumberOfBytesWritten, NULL );
      }
    }
    if (global.hFilCon != NULL)
    {
      WriteFile( global.hFilCon, lpBuffer, nNumberOfBytesToWrite,
		 lpNumberOfBytesWritten, NULL );
    }
    hFile = global.hStdOut;
  }

  rc = WriteFile( hFile, lpBuffer, nNumberOfBytesToWrite,
		  lpNumberOfBytesWritten, lpOverlapped );

  if (setcol)
    SetConsoleTextAttribute( global.hStdCon, col );

  return rc;
}


// Everything else in this file is just to make the above work.


#ifdef _WIN64
SHARED DWORD LLW32;
#endif


// ========== Hooking API functions
//
// References about API hooking (and dll injection):
// - Matt Pietrek ~ Windows 95 System Programming Secrets.
// - Jeffrey Richter ~ Programming Applications for Microsoft Windows 4th ed.

// Macro for adding pointers/DWORDs together without C arithmetic interfering
#define MakeVA( cast, offset ) (cast)((DWORD_PTR)(pDosHeader)+(DWORD)(offset))


const char APIKernel[]	       = "kernel32.dll";
const char APIProcessThreads[] = "API-MS-Win-Core-ProcessThreads-";
const char APILibraryLoader[]  = "API-MS-Win-Core-LibraryLoader-";
const char APIFile[]	       = "API-MS-Win-Core-File-";

typedef struct
{
  PCSTR   name;
  DWORD   len;
  HMODULE base;
} API_DATA, *PAPI_DATA;

API_DATA APIs[] =
{
  { APIProcessThreads, sizeof(APIProcessThreads) - 1, NULL },
  { APILibraryLoader,  sizeof(APILibraryLoader) - 1,  NULL },
  { APIFile,	       sizeof(APIFile) - 1,	      NULL },
  { NULL,	       0,			      NULL }
};


HMODULE   hKernel;		// Kernel32 module handle
HINSTANCE hDllInstance; 	// Dll instance handle
TCHAR	  hDllName[MAX_PATH];	// Dll file name
#if defined(_WIN64) || defined(W32ON64)
LPTSTR	  hDllNameType; 	// pointer to process type within above
#endif

typedef struct
{
  PCSTR lib;
  PSTR	name;
  PROC	newfunc;
  PROC	oldfunc;
  PROC	apifunc;
} HookFn, *PHookFn;

HookFn Hooks[];

//-----------------------------------------------------------------------------
//   HookAPIOneMod
// Substitute a new function in the Import Address Table (IAT) of the
// specified module.
// Return FALSE on error and TRUE on success.
//-----------------------------------------------------------------------------

BOOL HookAPIOneMod(
    HMODULE hFromModule,	// Handle of the module to intercept calls from
    PHookFn Hooks,		// Functions to replace
    BOOL    restore		// Restore the original functions
    )
{
  PIMAGE_DOS_HEADER	   pDosHeader;
  PIMAGE_NT_HEADERS	   pNTHeader;
  PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
  PIMAGE_THUNK_DATA	   pThunk;
  PHookFn		   hook;

  // Tests to make sure we're looking at a module image (the 'MZ' header)
  pDosHeader = (PIMAGE_DOS_HEADER)hFromModule;
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return FALSE;

  // The MZ header has a pointer to the PE header
  pNTHeader = MakeVA( PIMAGE_NT_HEADERS, pDosHeader->e_lfanew );

  // One more test to make sure we're looking at a "PE" image
  if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
    return FALSE;

  // We now have a valid pointer to the module's PE header.
  // Get a pointer to its imports section.
  pImportDesc = MakeVA( PIMAGE_IMPORT_DESCRIPTOR,
			pNTHeader->OptionalHeader.
			 DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].
			  VirtualAddress );

  // Bail out if the RVA of the imports section is 0 (it doesn't exist)
  if (pImportDesc == (PIMAGE_IMPORT_DESCRIPTOR)pDosHeader)
    return TRUE;

  // Iterate through the array of imported module descriptors, looking
  // for the module whose name matches the pszFunctionModule parameter.
  for (; pImportDesc->Name; pImportDesc++)
  {
    BOOL kernel = TRUE;
    PSTR pszModName = MakeVA( PSTR, pImportDesc->Name );
    if (_stricmp( pszModName, APIKernel ) != 0)
    {
      PAPI_DATA lib;
      for (lib = APIs; lib->name; ++lib)
      {
	if (_strnicmp( pszModName, lib->name, lib->len ) == 0)
	{
	  if (lib->base == NULL)
	  {
	    lib->base = GetModuleHandleA( pszModName );
	    for (hook = Hooks; hook->name; ++hook)
	      if (hook->lib == lib->name)
		hook->apifunc = GetProcAddress( lib->base, hook->name );
	  }
	  break;
	}
      }
      if (lib->name == NULL)
	continue;
      kernel = FALSE;
    }

    // Get a pointer to the found module's import address table (IAT).
    pThunk = MakeVA( PIMAGE_THUNK_DATA, pImportDesc->FirstThunk );

    // Blast through the table of import addresses, looking for the ones
    // that match the original addresses.
    while (pThunk->u1.Function)
    {
      for (hook = Hooks; hook->name; ++hook)
      {
	PROC patch = 0;
	if (restore)
	{
	  if ((PROC)pThunk->u1.Function == hook->newfunc)
	    patch = (kernel) ? hook->oldfunc : hook->apifunc;
	}
	else if ((PROC)pThunk->u1.Function == hook->oldfunc ||
		 (PROC)pThunk->u1.Function == hook->apifunc)
	{
	  patch = hook->newfunc;
	}
	if (patch)
	{
	  DWORD flOldProtect, flNewProtect, flDummy;
	  MEMORY_BASIC_INFORMATION mbi;

	  // Get the current protection attributes.
	  VirtualQuery( &pThunk->u1.Function, &mbi, sizeof(mbi) );
	  // Take the access protection flags.
	  flNewProtect = mbi.Protect;
	  // Remove ReadOnly and ExecuteRead flags.
	  flNewProtect &= ~(PAGE_READONLY | PAGE_EXECUTE_READ);
	  // Add on ReadWrite flag
	  flNewProtect |= (PAGE_READWRITE);
	  // Change the access protection on the region of committed pages in the
	  // virtual address space of the current process.
	  VirtualProtect( &pThunk->u1.Function, sizeof(PVOID),
			  flNewProtect, &flOldProtect );

	  // Overwrite the original address with the address of the new function.
	  if (!WriteProcessMemory( GetCurrentProcess(),
				   &pThunk->u1.Function,
				   &patch, sizeof(patch), NULL ))
	  {
	    return FALSE;
	  }

	  // Put the page attributes back the way they were.
	  VirtualProtect( &pThunk->u1.Function, sizeof(PVOID),
			  flOldProtect, &flDummy );
	}
      }
      pThunk++; // Advance to next imported function address
    }
  }

  return TRUE;	// Function not found
}

//-----------------------------------------------------------------------------
//   HookAPIAllMod
// Substitute a new function in the Import Address Table (IAT) of all
// the modules in the current process.
// Return FALSE on error and TRUE on success.
//-----------------------------------------------------------------------------

BOOL HookAPIAllMod( PHookFn Hooks, BOOL restore )
{
  HANDLE	hModuleSnap;
  MODULEENTRY32 me;
  BOOL		fOk;

  // Take a snapshot of all modules in the current process.
  hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE,
					  GetCurrentProcessId() );

  if (hModuleSnap == INVALID_HANDLE_VALUE)
    return FALSE;

  // Fill the size of the structure before using it.
  me.dwSize = sizeof(MODULEENTRY32);

  // Walk the module list of the modules.
  for (fOk = Module32First( hModuleSnap, &me ); fOk;
       fOk = Module32Next( hModuleSnap, &me ))
  {
    // We don't hook functions in our own module.
    if (me.hModule != hDllInstance && me.hModule != hKernel)
    {
      // Hook this function in this module.
      if (!HookAPIOneMod( me.hModule, Hooks, restore ))
      {
	CloseHandle( hModuleSnap );
	return FALSE;
      }
    }
  }
  CloseHandle( hModuleSnap );
  return TRUE;
}


// ========== Child process injection

// Inject code into the target process to load our DLL.
void Inject( LPPROCESS_INFORMATION pinfo, LPPROCESS_INFORMATION lpi,
	     DWORD dwCreationFlags )
{
  int type = ProcessType( pinfo );
  if (type != 0)
  {
#ifdef _WIN64
    if (type == 32)
    {
      hDllNameType[0] = '3';
      hDllNameType[1] = '2';
      InjectDLL32( pinfo );
    }
    else
    {
      hDllNameType[0] = '6';
      hDllNameType[1] = '4';
      InjectDLL64( pinfo );
    }
#else
#ifdef W32ON64
    if (type == 64)
    {
      TCHAR args[64];
      STARTUPINFO si;
      PROCESS_INFORMATION pi;
      wcscpy( hDllNameType, L".exe" );
      wsprintf( args, L"errout -P%lu:%lu",
		      pinfo->dwProcessId, pinfo->dwThreadId );
      ZeroMemory( &si, sizeof(si) );
      si.cb = sizeof(si);
      if (CreateProcess( hDllName, args, NULL, NULL, FALSE, 0, NULL, NULL,
			 &si, &pi ))
      {
	WaitForSingleObject( pi.hProcess, INFINITE );
	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );
      }
      wcscpy( hDllNameType, L"32.dll" );
    }
    else
#endif
    InjectDLL32( pinfo );
#endif
  }

  if (!(dwCreationFlags & CREATE_SUSPENDED))
    ResumeThread( pinfo->hThread );

  if (lpi)
  {
    memcpy( lpi, pinfo, sizeof(PROCESS_INFORMATION) );
  }
  else
  {
    CloseHandle( pinfo->hProcess );
    CloseHandle( pinfo->hThread );
  }
}


BOOL WINAPI MyCreateProcessA( LPCSTR lpApplicationName,
			      LPSTR lpCommandLine,
			      LPSECURITY_ATTRIBUTES lpThreadAttributes,
			      LPSECURITY_ATTRIBUTES lpProcessAttributes,
			      BOOL bInheritHandles,
			      DWORD dwCreationFlags,
			      LPVOID lpEnvironment,
			      LPCSTR lpCurrentDirectory,
			      LPSTARTUPINFOA lpStartupInfo,
			      LPPROCESS_INFORMATION lpProcessInformation )
{
  PROCESS_INFORMATION pi;

  if (!CreateProcessA( lpApplicationName,
		       lpCommandLine,
		       lpThreadAttributes,
		       lpProcessAttributes,
		       bInheritHandles,
		       dwCreationFlags | CREATE_SUSPENDED,
		       lpEnvironment,
		       lpCurrentDirectory,
		       lpStartupInfo,
		       &pi ))
    return FALSE;

  Inject( &pi, lpProcessInformation, dwCreationFlags );

  return TRUE;
}


BOOL WINAPI MyCreateProcessW( LPCWSTR lpApplicationName,
			      LPWSTR lpCommandLine,
			      LPSECURITY_ATTRIBUTES lpThreadAttributes,
			      LPSECURITY_ATTRIBUTES lpProcessAttributes,
			      BOOL bInheritHandles,
			      DWORD dwCreationFlags,
			      LPVOID lpEnvironment,
			      LPCWSTR lpCurrentDirectory,
			      LPSTARTUPINFOW lpStartupInfo,
			      LPPROCESS_INFORMATION lpProcessInformation )
{
  PROCESS_INFORMATION pi;

  if (!CreateProcessW( lpApplicationName,
		       lpCommandLine,
		       lpThreadAttributes,
		       lpProcessAttributes,
		       bInheritHandles,
		       dwCreationFlags | CREATE_SUSPENDED,
		       lpEnvironment,
		       lpCurrentDirectory,
		       lpStartupInfo,
		       &pi ))
    return FALSE;

  Inject( &pi, lpProcessInformation, dwCreationFlags );

  return TRUE;
}


FARPROC WINAPI MyGetProcAddress( HMODULE hModule, LPCSTR lpProcName )
{
  PHookFn hook;
  FARPROC proc;

  proc = GetProcAddress( hModule, lpProcName );

  if (proc)
  {
    if (hModule == hKernel)
    {
      // Ignore LoadLibrary so other hooks continue to work (our version
      // might end up at a different address).
      if (proc == Hooks[0].oldfunc || proc == Hooks[1].oldfunc)
	return proc;

      for (hook = Hooks + 2; hook->name; ++hook)
      {
	if (proc == hook->oldfunc)
	  return hook->newfunc;
      }
    }
    else
    {
      PAPI_DATA api;
      for (api = APIs; api->name; ++api)
      {
	if (hModule == api->base)
	{
	  if (proc == Hooks[0].apifunc || proc == Hooks[1].apifunc)
	    return proc;
	  for (hook = Hooks + 2; hook->name; ++hook)
	  {
	    if (proc == hook->apifunc)
	      return hook->newfunc;
	  }
	  break;
	}
      }
    }
  }

  return proc;
}


HMODULE WINAPI MyLoadLibraryA( LPCSTR lpFileName )
{
  HMODULE hMod = LoadLibraryA( lpFileName );
  if (hMod && hMod != hKernel)
    HookAPIOneMod( hMod, Hooks, FALSE );
  return hMod;
}


HMODULE WINAPI MyLoadLibraryW( LPCWSTR lpFileName )
{
  HMODULE hMod = LoadLibraryW( lpFileName );
  if (hMod && hMod != hKernel)
    HookAPIOneMod( hMod, Hooks, FALSE );
  return hMod;
}


#define LOAD_LIBRARY_AS_DATA 0x62
// 0x02 LOAD_LIBRARY_AS_DATAFILE
// 0x20 LOAD_LIBRARY_AS_IMAGE_RESOURCE
// 0x40 LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE

HMODULE WINAPI MyLoadLibraryExA( LPCSTR lpFileName, HANDLE hFile,
				 DWORD dwFlags )
{
  HMODULE hMod = LoadLibraryExA( lpFileName, hFile, dwFlags );
  if (hMod && hMod != hKernel && !(dwFlags & LOAD_LIBRARY_AS_DATA))
    HookAPIOneMod( hMod, Hooks, FALSE );
  return hMod;
}


HMODULE WINAPI MyLoadLibraryExW( LPCWSTR lpFileName, HANDLE hFile,
				 DWORD dwFlags )
{
  HMODULE hMod = LoadLibraryExW( lpFileName, hFile, dwFlags );
  if (hMod && hMod != hKernel && !(dwFlags & LOAD_LIBRARY_AS_DATA))
    HookAPIOneMod( hMod, Hooks, FALSE );
  return hMod;
}


// ========== Initialisation

HookFn Hooks[] = {
  // These two are expected first; WriteFile is expected last!
  { APILibraryLoader,  "LoadLibraryA",   (PROC)MyLoadLibraryA,   NULL, NULL },
  { APILibraryLoader,  "LoadLibraryW",   (PROC)MyLoadLibraryW,   NULL, NULL },
  { APIProcessThreads, "CreateProcessA", (PROC)MyCreateProcessA, NULL, NULL },
  { APIProcessThreads, "CreateProcessW", (PROC)MyCreateProcessW, NULL, NULL },
  { APILibraryLoader,  "GetProcAddress", (PROC)MyGetProcAddress, NULL, NULL },
  { APILibraryLoader,  "LoadLibraryExA", (PROC)MyLoadLibraryExA, NULL, NULL },
  { APILibraryLoader,  "LoadLibraryExW", (PROC)MyLoadLibraryExW, NULL, NULL },
  { APIFile,	       "WriteFile",      (PROC)MyWriteFile,      NULL, NULL },
  { NULL, NULL, NULL, NULL }
};


#ifdef W32ON64
// Locate the globals placed by the 64-bit code and copy it for our 32-bit.
void CopyGlobals( void )
{
  char* ptr;
  MEMORY_BASIC_INFORMATION minfo;

  for (ptr = NULL;
       VirtualQuery( ptr, &minfo, sizeof(minfo) );
       ptr += minfo.RegionSize)
  {
    if (minfo.BaseAddress == minfo.AllocationBase &&
	!IsBadReadPtr( minfo.AllocationBase, minfo.RegionSize ))
    {
      if (wcscmp( (LPCWSTR)(ptr + CODE32SIZE + GLOBAL32SIZE), hDllName ) == 0)
      {
	memcpy( &global, ptr + CODE32SIZE, GLOBAL32SIZE );
	break;
      }
    }
  }
}
#endif


//-----------------------------------------------------------------------------
//   DllMain()
// Function called by the system when processes and threads are initialized
// and terminated.
//-----------------------------------------------------------------------------

BOOL WINAPI DllMain( HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved )
{
  BOOL	  bResult = TRUE;
  PHookFn hook;
  LPSTR   name;

  if (dwReason == DLL_PROCESS_ATTACH)
  {
#if defined(_WIN64) || defined(W32ON64)
    hDllNameType = hDllName - 6 +
#endif
    GetModuleFileName( hInstance, hDllName, lenof(hDllName) );

    hDllInstance = hInstance; // save Dll instance handle

    // Don't hook WriteFile in errout.exe (static load).
    name = Hooks[lenof(Hooks)-2].name;
    if (lpReserved != NULL)
      Hooks[lenof(Hooks)-2].name = NULL;

    // Get the entry points to the original functions.
    hKernel = GetModuleHandleA( APIKernel );
    for (hook = Hooks; hook->name; ++hook)
      hook->oldfunc = GetProcAddress( hKernel, hook->name );

    bResult = HookAPIAllMod( Hooks, FALSE );
    DisableThreadLibraryCalls( hInstance );

    Hooks[lenof(Hooks)-2].name = name;

#ifdef W32ON64
    if (global.hStdOut == NULL)
      CopyGlobals();
#endif
  }
  else if (dwReason == DLL_PROCESS_DETACH)
  {
    // Unhook if it's being unloaded, but not if the process is exiting.
    if (lpReserved == NULL)
      HookAPIAllMod( Hooks, TRUE );
  }

  return( bResult );
}
