These tools are made to handle extended attributes on NTFS.

What is extended attribute?
It is an attribute called $EA, and it is thought to be there for compatibility with OS/2. It is constructed as a pair of name/value, where name is restricted as normal filenames on Windows, and the value part is anything binary. It can reside in both files and directories. It is restricted in size to 0xFFFF bytes per file/directory. There can be any number of pairs per object, but restricted by the total bytes of the attribute. The presence of $EA only has 1 effect worth noting. Apparently $EA and $REPARSE_POINT don't work together, so a file/directory can supposedly only have one or the other. This behavior has not been verified. Also it may worth noting that Windows does not contain any api that can be used to removed extended attributes. That means if we want to remove $EA from a file, we can:
* Delete the file altogether.
* Move the file to a non-NTFS volume and back again.
* Archive the file to a zip (for instance), delete the original file, and then unpack the zip back to the original location.
* Modify $MFT directly. This may work in certain circumstances.

Apparently, Symantec (and possibly others too) are struggling with $EA in their backup solutions; http://www.symantec.com/business/support/index?page=content&id=TECH167806 (ref reparse points mentioned above)

Some malware, like ZeroAccess, has got some attention lately due to data hiding in $EA; http://journeyintoir.blogspot.no/2012/12/extracting-zeroaccess-from-ntfs.html and http://www.symantec.com/connect/blogs/trojanzeroaccessc-hidden-ntfs-ea

Technical details
ZwCreateFile routine: http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
ZwSetEaFile routine: http://msdn.microsoft.com/en-us/library/windows/hardware/ff961908(v=vs.85).aspx
ZwQueryEaFile routine: http://msdn.microsoft.com/en-us/library/windows/hardware/ff625894(v=vs.85).aspx
FILE_FULL_EA_INFORMATION structure: http://msdn.microsoft.com/en-us/library/windows/hardware/ff545793(v=vs.85).aspx
ZwQueryInformationFile routine: http://msdn.microsoft.com/en-us/library/windows/hardware/ff567052(v=vs.85).aspx
FILE_EA_INFORMATION structure: http://msdn.microsoft.com/en-us/library/windows/hardware/ff545773(v=vs.85).aspx

As source code reveils, there are 2 ways of writing $EA:
1. NtCreateFile and simpel as that.
2. NtOpenFile and subsequent NtSetEaFile

The FILE_FULL_EA_INFORMATION structure holds the relevant data.


Usage examples EaInject:

Hiding a small file (10 kB) inside an existing file, and naming the EA "TEST":
EaInject.exe /Payload:C:\program.exe /Container:C:\tmp\file.txt /Mode:0 /Identifier:TEST

Hiding a bigger file above 65 kB and spreading the output across existing files inside the directory "C:\temp", naming the EA "something" and searching in non-recursive mode:
EaInject.exe /Payload:C:\bigfile.bin /Container:C:\temp /Mode:1 /Identifier:something /Filter:* /Recurse:0

Hiding a bigger file above 65 kB and spreading the out across existing txt files in the directory "C:\temp", naming the EA "testname", and searching in recursive mode:
EaInject.exe /Payload:C:\bigfile.bin /Container:C:\temp /Mode:1 /Identifier:testname /Filter:*.txt /Recurse:1

Hiding a bigger file above 65 kB and spreading the output into newly created files with random md5 names in the output directory C:\tmp, giving the EA name of "joke"
EaInject.exe /Payload:C:\bigfile.bin /Container:C:\tmp /Mode:2 /Identifier:joke


Usage examples EaQuery:

Scanning the current directory for $EA of any name in non-recursive mode in files by any extension, and verbose output on:
EaQuery.exe /Target:"%CD%" /Mode:0 /Verbose:1 /Identifier:* /Filter:* /Recurse:0

Scanning the directory "C:\Program Files" recursively for files by extension .exe and .dll, searching any EA name and displaying result to console in super verbose mode:
EaQuery.exe /Target:"C:\Program Files" /Mode:0 /Verbose:2 /Identifier:* /Filter:*.exe;*.dll /Recurse:1

Scanning the directory C:\WINDOWS\System32 recursively any file extension, extracting EA's detected to current directory, show no verbose output, and filter EA by name "something":
EaQuery.exe /Target:C:\WINDOWS\System32 /Mode:1 /Verbose:0 /Identifier:something /Filter:* /Recurse:1

Scan 1 file, C:\testfile.txt, extract any found EA and display super verbose output, including the EA data content in console:
EaQuery.exe /Target:C:\testfile.txt /Mode:2 /Verbose:2 /Identifier:* /Filter:* /Recurse:0
