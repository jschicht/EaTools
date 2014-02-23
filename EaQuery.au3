#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_Comment=Analyze extended attributes ($EA) on files on NTFS
#AutoIt3Wrapper_Res_Description=Analyze extended attributes ($EA) on files on NTFS
#AutoIt3Wrapper_Res_Fileversion=1.0.0.0
#AutoIt3Wrapper_Res_LegalCopyright=Joakim Schicht
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include <winapi.au3>
#include <_RecFileListToArray.au3>
Global Const $OBJ_CASE_INSENSITIVE = 0x00000040
Global Const $FILE_RANDOM_ACCESS = 0x00000800
Global Const $FILE_DIRECTORY_FILE = 0x00000002
Global Const $FILE_NON_DIRECTORY_FILE = 0x00000040
Global Const $tagOBJECTATTRIBUTES = "ulong Length;handle RootDirectory;ptr ObjectName;ulong Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
Global Const $tagUNICODESTRING = "ushort Length;ushort MaximumLength;ptr Buffer"
Global Const $tagFILE_EA_INFORMATION = "ulong EaSize"
Global Const $FILE_READ_EA = 8
Global Const $FileEaInformation = 7
Global Const $tagFILE_FULL_EA_INFORMATION1 = "ulong NextEntryOffset;byte Flags[1];byte EaNameLength[1];ushort EaValueLength"
Global Const $tagIOSTATUSBLOCK = "ptr Status;ptr Information"
Global $TargetPath, $Verbosity, $DoExtract, $TextIdentifier, $TargetIsDirectory, $SearchFilter, $RecursiveMode

ConsoleWrite("EaQuery v1.0.0.0" & @CRLF & @CRLF)
_ValidateInput()
If $TargetIsDirectory Then
	$TargetFile = _RecFileListToArray($TargetPath,$SearchFilter,0,$RecursiveMode)
	If @error Then
		ConsoleWrite("Error: Searching failed" & @CRLF)
		Exit
	EndIf
Else
	$TargetFile = StringSplit($TargetPath,";") ;Just choose something not valid inside a filename
EndIf

For $i = 1 To $TargetFile[0]
	If $TargetIsDirectory Then
		$TargetFileAndPath = $TargetPath&"\"&$TargetFile[$i]
	Else
		$TargetFileAndPath = $TargetFile[$i]
	EndIf
	$EaSize = _GetEaInformation($TargetFileAndPath)
	If $EaSize > 0 Then
		_ProcessEa($TargetFileAndPath,$TextIdentifier,Int($DoExtract),Int($Verbosity))
	Else
;		ConsoleWrite("No Ea found in: " & $TargetFileAndPath & @CRLF)
		ContinueLoop
	EndIf
Next


Func _ProcessEa($TargetFile,$NameIdentifier,$ExtractionMode,$VerboseLevel)
	Local $ReturnSingleEntry = 0, $RestartScan = 0, $NextEntryOffset = 0, $nBytes
	ConsoleWrite(@CRLF)
	$szName = DllStructCreate("wchar[260]")
	$sUS = DllStructCreate($tagUNICODESTRING)
	$sOA = DllStructCreate($tagOBJECTATTRIBUTES)
	$sISB = DllStructCreate($tagIOSTATUSBLOCK)
;	$buffer = DllStructCreate("byte["&$EaSize+16&"]")
	$buffer = DllStructCreate("byte["&65535&"]") ;Just oversize it to max possible Ea size
	DllStructSetData($szName, 1, "\??\"&$TargetFile)
;	If $VerboseLevel Then ConsoleWrite("TargetFile: " & $TargetFile & @CRLF)
	ConsoleWrite("TargetFile: " & $TargetFile & @CRLF)
	$ret = DllCall("ntdll.dll", "none", "RtlInitUnicodeString", "ptr", DllStructGetPtr($sUS), "ptr", DllStructGetPtr($szName))
	DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
	DllStructSetData($sOA, "RootDirectory", 0)
	DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
	DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
	DllStructSetData($sOA, "SecurityDescriptor", 0)
	DllStructSetData($sOA, "SecurityQualityOfService", 0)
	If StringInStr(FileGetAttrib($TargetFile),"D") Then
		$FileMode=$FILE_DIRECTORY_FILE
	Else
		$FileMode=$FILE_NON_DIRECTORY_FILE
	EndIf
	$ret = DllCall("ntdll.dll", "int", "NtOpenFile", "hwnd*", "", "dword", $GENERIC_READ, "ptr", DllStructGetPtr($sOA), "ptr", DllStructGetPtr($sISB), "ulong", $FILE_SHARE_READ, "ulong", BitOR($FileMode,$FILE_READ_EA,$FILE_RANDOM_ACCESS))
	If NT_SUCCESS($ret[0]) Then
;		ConsoleWrite("NtOpenFile: Success" & @CRLF)
	Else
		ConsoleWrite("TargetFile: " & $TargetFile & @CRLF)
		ConsoleWrite("NtOpenFile : 0x"&Hex($ret[0],8) &" "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return
	EndIf
	$hFile = $ret[1]
	$ret = DllCall("ntdll.dll", "handle", "NtQueryEaFile", "handle", $hFile, "ptr", DllStructGetPtr($sISB), "ptr", DllStructGetPtr($buffer), "ulong", DllStructGetSize($buffer), "bool", $ReturnSingleEntry, "ptr", 0, "ulong", 0, "ptr", 0, "bool", $RestartScan)
	If Not NT_SUCCESS($ret[0]) Then
		ConsoleWrite("TargetFile: " & $TargetFile & @CRLF)
		ConsoleWrite("NtQueryEaFile : 0x"&Hex($ret[0],8) &" "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return
	EndIf

	$pPointer = DllStructGetPtr($buffer)
	Do
		$sEaStruct = DllStructCreate($tagFILE_FULL_EA_INFORMATION1, $pPointer)
		$NextEntryOffset = DllStructGetData($sEaStruct, "NextEntryOffset")
		$Flags = DllStructGetData($sEaStruct, "Flags")
		$EaNameLength = DllStructGetData($sEaStruct, "EaNameLength")
		$EaNameLength = Dec(StringTrimLeft($EaNameLength,2))
		$EaValueLength = DllStructGetData($sEaStruct, "EaValueLength")
		$pPointer+=8
		$sEaStruct = DllStructCreate("char EaName["&$EaNameLength&"]", $pPointer)
		$EaName = DllStructGetData($sEaStruct, "EaName")
		$pPointer+=$EaNameLength
		$sEaStruct = DllStructCreate("byte EaValue["&$EaValueLength&"]", $pPointer)
		$EaValue = DllStructGetData($sEaStruct, "EaValue")
		If StringInStr($EaName,$NameIdentifier) Or $NameIdentifier = "*" Then
			If $VerboseLevel > 0 Then
				ConsoleWrite("NextEntryOffset: " & $NextEntryOffset & @CRLF)
				ConsoleWrite("Flags: " & $Flags & @CRLF)
				ConsoleWrite("EaNameLength: " & $EaNameLength & @CRLF)
				ConsoleWrite("EaName: " & $EaName & @CRLF)
				ConsoleWrite("EaValueLength: " & $EaValueLength & @CRLF)
				If $VerboseLevel = 2 Then
					ConsoleWrite("EaValue:" & @CRLF)
					ConsoleWrite(_HexEncode($EaValue) & @CRLF)
				EndIf
				ConsoleWrite(@CRLF)
			EndIf
			If $ExtractionMode Then
				If $VerboseLevel Then ConsoleWrite("Found " & $EaValueLength & " bytes in EA with matching name: " & $EaName & " in file: " & $TargetFile & @CRLF)
				$hFile2 = _WinAPI_CreateFile("\\.\" & @ScriptDir&"\EA_"&$EaName,1,6,7)
				If $hFile2=0 then
					ConsoleWrite("Error CreateFile returned: " & _WinAPI_GetLastErrorMessage() & @CRLF)
					Exit
				EndIf
				$tBuffer = DllStructCreate("byte[" & $EaValueLength & "]")
				DllStructSetData($tBuffer,1,$EaValue)
				$write = _WinAPI_WriteFile($hFile2, DllStructGetPtr($tBuffer), $EaValueLength, $nBytes)
				If $write = 0 then
					ConsoleWrite("Error WriteFile returned: " & _WinAPI_GetLastErrorMessage() & @CRLF)
					Exit
				Else
					ConsoleWrite("Successfully wrote " & $nBytes & " bytes to " & @ScriptDir&"\EA_"&$EaName & @CRLF)
				EndIf
				$tBuffer=0
				_WinAPI_CloseHandle($hFile2)
			EndIf
		EndIf
		$pPointer+=$NextEntryOffset-8-$EaNameLength
	Until $NextEntryOffset=0
	DllCall("ntdll.dll", "int", "NtClose", "hwnd", $hFile)
EndFunc

Func NT_SUCCESS($status)
    If 0 <= $status And $status <= 0x7FFFFFFF Then
        Return True
    Else
        Return False
    EndIf
EndFunc

Func _RtlNtStatusToDosError($Status)
    Local $aCall = DllCall("ntdll.dll", "ulong", "RtlNtStatusToDosError", "dword", $Status)
    If Not NT_SUCCESS($aCall[0]) Then
        ConsoleWrite("Error in RtlNtStatusToDosError: " & Hex($aCall[0], 8) & @CRLF)
        Return SetError(1, 0, $aCall[0])
    Else
        Return $aCall[0]
    EndIf
EndFunc

Func _TranslateErrorCode($ErrCode)
	Local $tBufferPtr = DllStructCreate("ptr")

	Local $nCount = _FormatMessage(BitOR($__WINAPICONSTANT_FORMAT_MESSAGE_ALLOCATE_BUFFER, $__WINAPICONSTANT_FORMAT_MESSAGE_FROM_SYSTEM), _
			0, $ErrCode, 0, $tBufferPtr, 0, 0)
	If @error Then Return SetError(@error, 0, "")

	Local $sText = ""
	Local $pBuffer = DllStructGetData($tBufferPtr, 1)
	If $pBuffer Then
		If $nCount > 0 Then
			Local $tBuffer = DllStructCreate("wchar[" & ($nCount + 1) & "]", $pBuffer)
			$sText = DllStructGetData($tBuffer, 1)
		EndIf
		_LocalFree($pBuffer)
	EndIf

	Return $sText
EndFunc

Func _FormatMessage($iFlags, $pSource, $iMessageID, $iLanguageID, ByRef $pBuffer, $iSize, $vArguments)
	Local $sBufferType = "struct*"
	If IsString($pBuffer) Then $sBufferType = "wstr"
	Local $aResult = DllCall("Kernel32.dll", "dword", "FormatMessageW", "dword", $iFlags, "ptr", $pSource, "dword", $iMessageID, "dword", $iLanguageID, _
			$sBufferType, $pBuffer, "dword", $iSize, "ptr", $vArguments)
	If @error Then Return SetError(@error, @extended, 0)
	If $sBufferType = "wstr" Then $pBuffer = $aResult[5]
	Return $aResult[0]
EndFunc

Func _LocalFree($hMem)
	Local $aResult = DllCall("kernel32.dll", "handle", "LocalFree", "handle", $hMem)
	If @error Then Return SetError(@error, @extended, False)
	Return $aResult[0]
EndFunc

Func _HexEncode($bInput)
    Local $tInput = DllStructCreate("byte[" & BinaryLen($bInput) & "]")
    DllStructSetData($tInput, 1, $bInput)
    Local $a_iCall = DllCall("crypt32.dll", "int", "CryptBinaryToString", _
            "ptr", DllStructGetPtr($tInput), _
            "dword", DllStructGetSize($tInput), _
            "dword", 11, _
            "ptr", 0, _
            "dword*", 0)

    If @error Or Not $a_iCall[0] Then
        Return SetError(1, 0, "")
    EndIf

    Local $iSize = $a_iCall[5]
    Local $tOut = DllStructCreate("char[" & $iSize & "]")

    $a_iCall = DllCall("crypt32.dll", "int", "CryptBinaryToString", _
            "ptr", DllStructGetPtr($tInput), _
            "dword", DllStructGetSize($tInput), _
            "dword", 11, _
            "ptr", DllStructGetPtr($tOut), _
            "dword*", $iSize)

    If @error Or Not $a_iCall[0] Then
        Return SetError(2, 0, "")
    EndIf

    Return SetError(0, 0, DllStructGetData($tOut, 1))

EndFunc  ;==>_HexEncode

Func _GetEaInformation($file)
    Local $szName = DllStructCreate("wchar[260]")
    Local $sUS = DllStructCreate($tagUNICODESTRING)
    Local $sOA = DllStructCreate($tagOBJECTATTRIBUTES)
    Local $sISB = DllStructCreate($tagIOSTATUSBLOCK)
    Local $buffer = DllStructCreate("byte[16384]")
	If StringInStr(FileGetAttrib($file),"D") Then
		$FileMode=$FILE_DIRECTORY_FILE
	Else
		$FileMode=$FILE_NON_DIRECTORY_FILE
	EndIf
    DllStructSetData($szName, 1, "\??\"&$file)
    $ret = DllCall("ntdll.dll", "none", "RtlInitUnicodeString", "ptr", DllStructGetPtr($sUS), "ptr", DllStructGetPtr($szName))
    DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
    DllStructSetData($sOA, "RootDirectory", 0)
    DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
    DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
    DllStructSetData($sOA, "SecurityDescriptor", 0)
    DllStructSetData($sOA, "SecurityQualityOfService", 0)
    $ret = DllCall("ntdll.dll", "int", "NtOpenFile", "hwnd*", "", "dword", $GENERIC_READ, "ptr", DllStructGetPtr($sOA), "ptr", DllStructGetPtr($sISB), "ulong", $FILE_SHARE_READ, "ulong", BitOR($FileMode, $FILE_RANDOM_ACCESS))
	If NT_SUCCESS($ret[0]) Then
;		ConsoleWrite("NtOpenFile: Success" & @CRLF)
	Else
		ConsoleWrite("TargetFile: " & $file & @CRLF)
		ConsoleWrite("NtOpenFile : 0x"&Hex($ret[0],8) &" "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return False
	EndIf
    Local $hFile = $ret[1]
    $ret = DllCall("ntdll.dll", "int", "NtQueryInformationFile", "ptr", $hFile, "ptr", DllStructGetPtr($sISB), "ptr", DllStructGetPtr($buffer), _
                                "int", 16384, "ptr", $FileEaInformation)

    If NT_SUCCESS($ret[0]) Then
        Local $pFSO = DllStructGetPtr($buffer)
        Local $sFSO = DllStructCreate($tagFILE_EA_INFORMATION, $pFSO)
        Local $EaSize = DllStructGetData($sFSO, "EaSize")
    Else
		ConsoleWrite("TargetFile: " & $file & @CRLF)
		ConsoleWrite("NtQueryInformationFile : 0x"&Hex($ret[0],8) &" "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
		Return False
    EndIf
    $ret = DllCall("ntdll.dll", "int", "NtClose", "hwnd", $hFile)
	Return $EaSize
EndFunc

Func _SwapEndian($iHex)
	Return StringMid(Binary(Dec($iHex,2)),3, StringLen($iHex))
EndFunc

Func _ValidateInput()
	Local $TargetAttributes
	Global $TargetPath, $Verbosity, $DoExtract, $TextIdentifier, $TargetIsDirectory, $SearchFilter, $RecursiveMode
	If $cmdline[0] < 3 Then
		ConsoleWrite("Error: Wrong number of parameters" & @CRLF)
		ConsoleWrite("Syntax is:" & @CRLF)
		ConsoleWrite("EaQuery.exe /Target:TargetPath /Mode:{0|1} /Verbose:{0|1|2} /Identifier:{*|SomeText} /Filter:Text /Recurse:boolean" & @CRLF)
		ConsoleWrite("	/Target can be file or directory" & @CRLF)
		ConsoleWrite("	/Mode 1 is just displaying result on console. Mode 2 is also extracting the data." & @CRLF)
		ConsoleWrite("	/Verbose level 0 show little information. Level 1 some more. Level 3 also dumps the data to console." & @CRLF)
		ConsoleWrite("	/Identifier is a filter for what EA names to parse. Default is '*'." & @CRLF)
		ConsoleWrite("	/Filter is for included results. Multiple filters separatet by ';'. Default is '*'." & @CRLF)
		ConsoleWrite("	/Recurse is a boolean value 0 or 1 for acivating/deactivating recursive mode. Default is off." & @CRLF)
		Exit
	EndIf
	For $i = 1 To $cmdline[0]
		If StringLeft($cmdline[$i],8) = "/Target:" Then $TargetPath = StringMid($cmdline[$i],9)
		If StringLeft($cmdline[$i],9) = "/Verbose:" Then $Verbosity = StringMid($cmdline[$i],10)
		If StringLeft($cmdline[$i],6) = "/Mode:" Then $DoExtract = StringMid($cmdline[$i],7)
		If StringLeft($cmdline[$i],12) = "/Identifier:" Then $TextIdentifier = StringMid($cmdline[$i],13)
		If StringLeft($cmdline[$i],8) = "/Filter:" Then $SearchFilter = StringMid($cmdline[$i],9)
		If StringLeft($cmdline[$i],9) = "/Recurse:" Then $RecursiveMode = StringMid($cmdline[$i],10)
	Next
	If $Verbosity <> 0 And $Verbosity <> 1 And $Verbosity <> 2 Or Not StringIsDigit($Verbosity) Then
		ConsoleWrite("Error: Verbosity not set correctly: " & $Verbosity & @CRLF)
		Exit
	EndIf
	If $DoExtract <> 0 And $DoExtract <> 1 Or Not StringIsDigit($DoExtract) Then
		ConsoleWrite("Error: Mode not set correctly: " & $DoExtract & @CRLF)
		Exit
	EndIf
	If FileExists($TargetPath) = 0 Then
		ConsoleWrite("Error: Target path does not exist: " & $TargetPath & @CRLF)
		Exit
	Else
		If StringRight($TargetPath,1)="\" Then $TargetPath = StringTrimRight($TargetPath,1)
	EndIf
	$TargetAttributes = FileGetAttrib($TargetPath)
	If @error Then
		ConsoleWrite("Error: Could not evaluate attributes of: " & $TargetPath & @CRLF)
		Exit
	EndIf
	If StringInStr($TargetAttributes,"D") Then
		$TargetIsDirectory = 1
	Else
		$TargetIsDirectory = 0
	EndIf
	If $TextIdentifier = "" Then $TextIdentifier = "*"
	If $RecursiveMode <> 0 And $RecursiveMode <> 1 And $RecursiveMode <> "False" And $RecursiveMode <> "True" Then
		ConsoleWrite("Error: Recursive was not boolean" & @CRLF)
		Exit
	ElseIf $RecursiveMode = 0 Or $RecursiveMode = "False" Then
		$RecursiveMode = 0
	ElseIf $RecursiveMode = 1 Or $RecursiveMode = "True" Then
		$RecursiveMode = 1
	ElseIf $RecursiveMode = "" Then
		$RecursiveMode = 0
	EndIf
	If $SearchFilter = "" Then $SearchFilter = "*"
EndFunc