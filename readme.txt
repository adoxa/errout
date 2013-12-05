				    Errout

			 Copyright 2011-2013 Jason Hood

			    Version 1.11.  Freeware


Description
===========

    There are occasions when you would like to redirect both standard output
    (stdout) and standard error (stderr).  The normal method to achieve this is
    ">file 2>&1" - send stdout to the file and duplicate stderr to stdout.  The
    problem with this method is it may change the order (as seen on the
    console) - you end up with all of stdout, followed by all of stderr.
    Errout really sends stderr to stdout, maintaining the order.


Requirements
============

    32-bit: Windows 2000 Professional and later (it won't work with NT or 9X).
    64-bit: Vista and later (it won't work with XP64 or Server 2003).


Installation
============

    Add "x86" (if your OS is 32-bit) or "x64" (if 64-bit) to your PATH, or copy
    the relevant files to a directory already on the PATH.

Upgrading
---------

    Delete "errout-LLW.exe", it is no longer used.


Usage
=====

    errout [options] program [args]

    -a[B]F

    Define the color (background and foreground) for stderr; if B is absent, it
    will default to 0 (black).	I'll cheat here and just point you to COLOR/?
    for the values.  The environment variable ERROUTCOL=[B]F may be set to
    provide -a by default.

    -c[e|o]

    In addition to sending output to stdout, this option will send it to the
    console (both stderr & stdout, or just one or the other).  This should
    really only be used if you redirect, as otherwise you'll get an echo.

    -d

    Delay the hook till after the program is started.  This may be useful for
    some programs.  The prime example is 7z (this program's raison detre),
    which will refuse to combine the streams without it.

    -o FILE
    -e FILE
    -f FILE

    In addition to sending output to stdout, these options will send stdout,
    stderr and/or both to file.  The lower case letter will always create the
    file; an upper case letter will append.

    program [args]

    The program and its arguments to run with stderr sent to stdout.


Version History
===============

    Legend: + added, - bug-fixed, * changed.

    1.11 - 5 December, 2013:
    - return the exit code of the program;
    * enable read sharing of the files.

    1.10 - 14 November, 2013:
    * improved compatibility (thanks to all the work done on ANSICON).


Contact
=======

    mailto:jadoxa@yahoo.com.au
    http://errout.adoxa.vze.com/
    https://github.com/adoxa/errout

    Jason Hood
    11 Buckle Street
    North Rockhampton
    Qld 4701
    Australia


Distribution
============

    The original zipfile can be freely distributed, by any means.  However, I
    would like to be informed if it is placed on a CD-ROM (other than an arch-
    ive compilation; permission is granted, I'd just like to know).  Modified
    versions may be distributed, provided it is indicated as such in the ver-
    sion text and a source diff is made available.  In particular, the supplied
    binaries are freely redistributable.  A formal license (zlib) is available
    in LICENSE.txt.


=============================
Jason Hood, 5 December, 2013.
