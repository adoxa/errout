/*
  errout.c - Send stderr to stdout.

  Jason Hood, 29 June to 2 July, 2011.

  Set up a WriteFile hook to redirect both stdout & stderr, maintaining the
  order as you'd see it on the console (which "2>&1" doesn't necessarily do).

  v1.11, 5 December, 2013:
  - return the exit code of the program;
  * enable read sharing of the files.
*/

#define PVERS L"1.11"
#define PDATE L"5 December, 2013"

#define DO_IMPORT
#include "errout.h"
#include <locale.h>

#ifdef __MINGW32__
// I think it's a flaw in gcc that it doesn't read object files from its library
// directory, hence doing this rather than adding CRT_noglob.o.  Only necessary
// for MinGW32, TDM apparently doesn't do it by default (besides which, it uses
// _dowildcard, same as VC).
int _CRT_glob = 0;
#endif


#ifdef _WIN64
# define BITS L"64"
# define APPS L"Windows"
#else
# define BITS L"32"
# define APPS L"Win32"
#endif

__declspec(dllimport)
Globals global;

void   help( void );

LPWSTR skip_spaces( LPWSTR );
void   get_arg( LPWSTR, LPWSTR*, LPWSTR* );


DWORD CtrlHandler( DWORD event )
{
  return (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT);
}


int main( void )
{
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  SECURITY_ATTRIBUTES sa;
  HANDLE hStdErr;
  FILE*  stdcon;
  LPWSTR argv, arg, cmd;
  char	 cp[8];
  WCHAR  env[4];
  BOOL	 delay;
  int	 rc;

  rc   = 0;
  argv = GetCommandLine();
  arg  = malloc( wcslen( argv ) * sizeof(WCHAR) );
  get_arg( arg, &argv, &cmd );	// skip the program name
  get_arg( arg, &argv, &cmd );

  if (*arg == '\0' ||
      wcscmp( arg, L"/?" ) == 0 ||
      wcscmp( arg, L"--help" ) == 0)
  {
    help();
    free( arg );
    return rc;
  }
  if (wcscmp( arg, L"--version" ) == 0)
  {
    _putws( L"Errout (" BITS L"-bit) version " PVERS L" (" PDATE L")." );
    free( arg );
    return rc;
  }

#ifdef _WIN64
  if (*arg == '-' && arg[1] == 'P')
  {
    swscanf( arg + 2, L"%u:%u", &pi.dwProcessId, &pi.dwThreadId );
    pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    pi.hThread	= OpenThread( THREAD_ALL_ACCESS, FALSE, pi.dwThreadId );
    InjectDLL64( &pi );
    CloseHandle( pi.hThread );
    CloseHandle( pi.hProcess );
    return 0;
  }
#endif

  // Using "" for setlocale uses the system ANSI code page.
  sprintf( cp, ".%u", GetConsoleOutputCP() );
  setlocale( LC_CTYPE, cp );

  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;

  global.hStdOut = GetStdHandle( STD_OUTPUT_HANDLE );
  hStdErr = GetStdHandle( STD_ERROR_HANDLE );

  // If a pipe creates a new console (like TDE does), then CONOUT$ will (may?)
  // be created in that console, so use stderr (if it's not been redirected for
  // some reason) to keep -c in the original console.
  if (GetFileType( hStdErr ) == FILE_TYPE_CHAR)
  {
    // Can't just copy the handle, as we need to distinguish them.
    DuplicateHandle( GetCurrentProcess(), hStdErr,
		     GetCurrentProcess(), &global.hStdCon,
		     0, TRUE, DUPLICATE_SAME_ACCESS );
  }
  else
  {
    global.hStdCon = CreateFile( L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
					     FILE_SHARE_READ | FILE_SHARE_WRITE,
					     &sa, OPEN_EXISTING, 0, 0 );
  }

  // Unfortunately, the above doesn't change stdout, so create a console file.
  stdcon = _wfopen( L"con", L"w" );

  *env = '\0';
  GetEnvironmentVariable( L"ERROUTCOL", env, lenof(env) );
  if (*env != '\0')
  {
    LPWSTR end;
    long attr = wcstol( env, &end, 16 );
    if (end != env && *end == '\0' && attr < 256)
      global.errcol = (WORD)attr;
  }

  rc = -1;
  delay = FALSE;
  while (*arg == '-')
  {
    if (arg[1] == 'a')
    {
      LPWSTR end;
      long attr = wcstol( arg+2, &end, 16 );
      if (end == arg+2 || *end != '\0' || attr >= 256)
      {
	fwprintf( stdcon, L"Errout: Expecting one or two hex digits: \"%s\".\n", arg );
	goto tidy_up;
      }
      global.errcol = (WORD)attr;
    }
    else if (arg[1] == 'c')
    {
      if (arg[2] == '\0')
	global.console = 3;
      else
      {
	if (arg[2] == 'e')
	  global.console = 2;
	else if (arg[2] == 'o')
	  global.console = 1;
	if (global.console == 0 || arg[3] != '\0')
	{
	  fwprintf( stdcon, L"Errout: Expecting -c[e|o]: \"%s\".\n", arg );
	  goto tidy_up;
	}
      }
    }
    else if (arg[1] == 'd')
    {
      if (arg[2] != '\0')
      {
	fwprintf( stdcon, L"Errout: Not expecting anything: \"%s\".\n", arg );
	goto tidy_up;
      }
      delay = TRUE;
    }
    else
    {
      HANDLE* pFile;
      BOOL append = !(arg[1] & 0x20);
      switch (arg[1] | 0x20)
      {
	default:
	  fwprintf( stdcon, L"Errout: Unknown option: \"%s\".\n", arg );
	  goto tidy_up;

	case 'o': pFile = &global.hFilOut; break;
	case 'e': pFile = &global.hFilErr; break;
	case 'f': pFile = &global.hFilCon; break;
      }
      get_arg( arg, &argv, &cmd );
      *pFile = CreateFile( arg, GENERIC_WRITE, FILE_SHARE_READ, &sa,
			   (append) ? OPEN_ALWAYS : CREATE_ALWAYS, 0, 0 );
      if (*pFile == INVALID_HANDLE_VALUE)
      {
	fwprintf( stdcon, L"Errout: Unable to %s \"%s\".\n",
			  (append) ? L"open" : L"create", arg );
	goto tidy_up;
      }
      if (append)
	SetFilePointer( *pFile, 0, NULL, FILE_END );
    }
    get_arg( arg, &argv, &cmd );
  }

  // Ignore the color if stdout is redirected and -c hasn't been used - this
  // prevents a pipe writing to console from being inadvertently coloured.
  if (GetFileType( global.hStdOut ) != FILE_TYPE_CHAR && global.console == 0)
    global.errcol = -1;

  ZeroMemory( &si, sizeof(si) );
  si.cb = sizeof(si);
  if (!delay)
    SetStdHandle( STD_OUTPUT_HANDLE, global.hStdCon );
  if (CreateProcess( NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi ))
  {
    // Point stdout to the new console handle.	This is necessary to force the
    // combination of out & err, otherwise they still remain separate.	I think
    // this is due to the differing buffering characteristics of character &
    // file types.  I couldn't find a function to change that, hence the hook.
    // I originally did this earlier, but the whole reason I created this
    // program was so I could pipe a 7z archive and see the file names along
    // with the contents.  Of course, that was the last thing I tested and it
    // didn't work - "I won't extract data and program's messages to the same
    // terminal."  Well, now you will. :)
    if (delay)
      SetStdHandle( STD_OUTPUT_HANDLE, global.hStdCon );
    CloseHandle( pi.hThread );
    SetConsoleCtrlHandler( (PHANDLER_ROUTINE)CtrlHandler, TRUE );
    WaitForSingleObject( pi.hProcess, INFINITE );
    GetExitCodeProcess( pi.hProcess, (LPDWORD)&rc );
    CloseHandle( pi.hProcess );
  }
  else
  {
    get_arg( arg, &cmd, &cmd );
    fwprintf( stdcon, L"Errout: \"%s\" could not be executed.\n", arg );
    rc = -2;
  }

tidy_up:
  fclose( stdcon );
  if (global.hFilOut != NULL)
    CloseHandle( global.hFilOut );
  if (global.hFilErr != NULL)
    CloseHandle( global.hFilErr );
  if (global.hFilCon != NULL)
    CloseHandle( global.hFilCon );
  SetStdHandle( STD_OUTPUT_HANDLE, global.hStdOut );
  CloseHandle( global.hStdCon );
  free( arg );
  return rc;
}


// Return the first non-space character from arg.
LPWSTR skip_spaces( LPWSTR arg )
{
  while (*arg == ' ' || *arg == '\t')
    ++arg;

  return arg;
}


// Retrieve an argument from the command line.	cmd gets the existing argv; argv
// is ready for the next argument.
void get_arg( LPWSTR arg, LPWSTR* argv, LPWSTR* cmd )
{
  LPWSTR line = skip_spaces( *argv );
  *cmd = line;

  while (*line != ' ' && *line != '\t' && *line != '\0')
  {
    if (*line == '"')
    {
      while (*++line != '"' && *line != '\0')
	*arg++ = *line;
      if (*line != '\0')
	++line;
    }
    else
    {
      *arg++ = *line++;
    }
  }
  if (*line != '\0')
    ++line;
  *arg = '\0';
  *argv = line;
}


void help( void )
{
  _putws(
L"Errout by Jason Hood <jadoxa@yahoo.com.au>.\n"
L"Version " PVERS L" (" PDATE L").  Freeware.\n"
L"http://errout.adoxa.vze.com/\n"
L"\n"
L"Send standard error (stderr) to standard output (stdout) in " APPS L" console\n"
L"programs, and optionally to the console and/or files as well.\n"
L"\n"
L"errout [options] program [args]\n"
L"\n"
L"    -a[B]F\tset stderr to foreground F & background B (0 if absent)\n"
L"    -c[e|o]\talso output both, or just stderr/stdout, to the console\n"
L"    -d\t\tdelay the hook till after program is started\n"
L"    -e FILE\talso write stderr to FILE\n"
L"    -f FILE\talso write both to FILE\n"
L"    -o FILE\talso write stdout to FILE\n"
L"    program\trun the specified program with its arguments\n"
L"\n"
L"Lower case letter will create FILE; upper case will append.\n"
L"F & B are hex digits; see COLOR/? for the values.\n"
L"Set the environment variable ERROUTCOL=[B]F to use -a by default.\n"
L"Delay may be useful for some programs (notably 7z)."
	      );
}
