/*
  Test for a valid process.  This may sometimes detect GUI, even for a console
  process.  I think this is due to a DLL being loaded in the address space
  before the main image.  Ideally I could just use the base address directly,
  but that doesn't seem easy to do for another process - there doesn't seem to
  be a GetModuleHandle for another process.  The CreateRemoteThread trick won't
  work with 64-bit (exit code is DWORD) and setting it up to make it work
  hardly seems worth it.  There's GetModuleInformation, but passing in NULL just
  returns a base of NULL, so that's no help.  At the moment, 64/32 is
  sufficient, so don't worry about it.

  Update: ignore images characterised as DLL.
*/

#include "errout.h"


int ProcessType( LPPROCESS_INFORMATION pinfo )
{
  char* ptr;
  MEMORY_BASIC_INFORMATION minfo;
  IMAGE_DOS_HEADER dos_header;
  IMAGE_NT_HEADERS nt_header;
  SIZE_T read;

  for (ptr = NULL;
       VirtualQueryEx( pinfo->hProcess, ptr, &minfo, sizeof(minfo) );
       ptr += minfo.RegionSize)
  {
    if (minfo.BaseAddress == minfo.AllocationBase &&
	ReadProcessMemory( pinfo->hProcess, minfo.AllocationBase,
			   &dos_header, sizeof(dos_header), &read ))
    {
      if (dos_header.e_magic == IMAGE_DOS_SIGNATURE)
      {
	if (ReadProcessMemory( pinfo->hProcess, (char*)minfo.AllocationBase +
			       dos_header.e_lfanew, &nt_header,
			       sizeof(nt_header), &read ))
	{
	  if (nt_header.Signature == IMAGE_NT_SIGNATURE &&
	      (nt_header.FileHeader.Characteristics &
			 (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL))
			 == IMAGE_FILE_EXECUTABLE_IMAGE)
	  {
	    int subsys = nt_header.OptionalHeader.Subsystem;
	    if (subsys == IMAGE_SUBSYSTEM_WINDOWS_CUI ||
		subsys == IMAGE_SUBSYSTEM_WINDOWS_GUI)
	    {
	      if (nt_header.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	      {
		return 32;
	      }
#if defined(_WIN64) || defined(W32ON64)
	      if (nt_header.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	      {
		return 64;
	      }
#endif
	    }
	    return 0;
	  }
	}
      }
    }
#ifndef _WIN64
    // If a 32-bit process loads a 64-bit one, we may miss the base
    // address.  If the pointer overflows, assume 64-bit.
    if (((DWORD)ptr >> 12) + ((DWORD)minfo.RegionSize >> 12) > 0x80000)
    {
#ifdef W32ON64
      return 64;
#else
      return 0;
#endif
    }
#endif
  }

  return 0;
}
