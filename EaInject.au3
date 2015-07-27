#RequireAdmin
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseUpx=y
#AutoIt3Wrapper_Change2CUI=y
#AutoIt3Wrapper_Res_Comment=Inject data into the $EA attribute
#AutoIt3Wrapper_Res_Description=Inject data into the $EA attribute
#AutoIt3Wrapper_Res_Fileversion=1.0.0.1
#AutoIt3Wrapper_Res_LegalCopyright=Joakim Schicht
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include <winapi.au3>
#include <_RecFileListToArray.au3>
Global Const $tagOBJECTATTRIBUTES = "ulong Length;handle RootDirectory;ptr ObjectName;ulong Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
Global Const $tagUNICODESTRING = "ushort Length;ushort MaximumLength;ptr Buffer"
Global Const $tagIOSTATUSBLOCK = "ptr Status;ptr Information"
Global Const $FILE_WRITE_EA = 0x10
Global Const $FILE_NEED_EA = 0x00000080
;Global Const $FILE_NEED_NO_EA = 0
Global Const $MaxEaEntrySize = 65510
Global Const $OBJ_CASE_INSENSITIVE = 0x00000040
Global Const $FILE_RANDOM_ACCESS = 0x00000800
Global Const $FILE_DIRECTORY_FILE = 0x00000002
Global Const $FILE_NON_DIRECTORY_FILE = 0x00000040
Global $nBytes, $buffer, $TargetPayload, $RunMode, $TextIdentifier, $TargetIsDirectory, $TargetContainerPath, $SearchFilter, $RecursiveMode, $AccessAttempts=1, $TargetContainerParentPath, $EaFlag

ConsoleWrite("EaInject v1.0.0.1" & @CRLF & @CRLF)
_ValidateInput()
ConsoleWrite("TargetPayload: " & $TargetPayload & @CRLF)
$hFile0 = _WinAPI_CreateFile("\\.\" & $TargetPayload,2,6,7)
If $hFile0=0 then
	ConsoleWrite("Error CreateFile returned: " & _WinAPI_GetLastErrorMessage() & @CRLF)
	Exit
EndIf
$FileSize = _WinAPI_GetFileSizeEx($hFile0)
If @error Or $FileSize = 0 Then
	ConsoleWrite("Error: Payload contained no data. Nothing to do." & @CRLF)
	Exit
EndIf
If DriveSpaceFree(StringLeft($TargetContainerPath,3))*1024*1024 < $FileSize Then
	ConsoleWrite("Error: Not enough free space on volume" & @CRLF)
	Exit
EndIf
If $RunMode = 1 Then
	$TargetFile = _RecFileListToArray($TargetContainerPath,$SearchFilter,0,$RecursiveMode)
	If @error Then
		ConsoleWrite("Error: Searching failed" & @CRLF)
		Exit
	EndIf
ElseIf $RunMode = 0 Then
	$TargetFile = StringSplit($TargetContainerPath,";") ;Just choose something not valid inside a filename
EndIf

If $RunMode = 1 And $TargetFile[0] * $MaxEaEntrySize < $FileSize Then
	ConsoleWrite("Error: Not enough containers in target path to hide payload" & @CRLF)
	Exit
EndIf

If $RunMode = 0 Or $RunMode = 1 Then
	If $FileSize <= $MaxEaEntrySize Then
		$AccessAttempts = 0
		For $Counter = 0 To $TargetFile[0]-1
			Do
				$szName = DllStructCreate("wchar[260]")
				$sUS = DllStructCreate($tagUNICODESTRING)
				$sOA = DllStructCreate($tagOBJECTATTRIBUTES)
				$sISB = DllStructCreate($tagIOSTATUSBLOCK)
				If $RunMode = 1 Then
					$TargetFileAndPath = $TargetContainerPath&"\"&$TargetFile[$Counter+1]
				Else
					$TargetFileAndPath = $TargetFile[$Counter+1]
				EndIf
				DllStructSetData($szName, 1, "\??\"&$TargetFileAndPath)
				ConsoleWrite("Target is: " & $TargetFileAndPath & @CRLF)
				FileSetAttrib($TargetFileAndPath, "-R")
				If StringInStr(FileGetAttrib($TargetFileAndPath),"D") Then
					$FileMode=$FILE_DIRECTORY_FILE
				Else
					$FileMode=$FILE_NON_DIRECTORY_FILE
				EndIf
				$ret = DllCall("ntdll.dll", "none", "RtlInitUnicodeString", "ptr", DllStructGetPtr($sUS), "ptr", DllStructGetPtr($szName))
				DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
				DllStructSetData($sOA, "RootDirectory", 0)
				DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
				DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
				DllStructSetData($sOA, "SecurityDescriptor", 0)
				DllStructSetData($sOA, "SecurityQualityOfService", 0)

				$ret = DllCall("ntdll.dll", "int", "NtOpenFile", "hwnd*", "", "dword", BitOR($GENERIC_WRITE,$FILE_WRITE_EA), "ptr", DllStructGetPtr($sOA), "ptr", DllStructGetPtr($sISB), "ulong", BitOR($FILE_SHARE_READ,$FILE_SHARE_WRITE), "ulong", BitOR($FileMode,$FILE_RANDOM_ACCESS))
				If NT_SUCCESS($ret[0]) Then
					ConsoleWrite("NtOpenFile: Success" & @CRLF)
				Else
					ConsoleWrite("NtOpenFile : 0x"&Hex($ret[0],8) &" "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
					_GrantFileAccess($TargetFileAndPath)
				EndIf
				$AccessAttempts+=1
			Until $AccessAttempts = 2 Or $ret[1]
			If $Counter = $TargetFile[0]-1 And Not $ret[1] Then
				ConsoleWrite("Error: Could not hide data." & @CRLF)
				Exit
			EndIf
			If Not $ret[1] Then ContinueLoop
			If $ret[1] Then ExitLoop
		Next
		$hFile1 = $ret[1]
		$tBuffer = DllStructCreate("byte[" & $FileSize & "]")
		$tBuffer2 = DllStructCreate("byte[" & $FileSize & "]")
		$read = _WinAPI_ReadFile($hFile0, DllStructGetPtr($tBuffer), $FileSize, $nBytes)
		If $read = 0 then
			ConsoleWrite("Error ReadFile failed: " & _WinAPI_GetLastErrorMessage() & @CRLF)
			_WinAPI_CloseHandle($hFile0)
		EndIf
		$NextEntryOffset = 0
		$EaName = $TextIdentifier;&"1"
		$EaNameLength = StringLen($EaName)
		$EaValue = DllStructGetData($tBuffer,1)
;		ConsoleWrite(_HexEncode($EaValue) & @CRLF)
		$EaValueLength = BinaryLen($EaValue)
		$tagFILE_FULL_EA_INFORMATION = "ulong NextEntryOffset;byte Flags[1];byte EaNameLength[1];ushort EaValueLength;char EaName["&$EaNameLength&"];byte dummy[1];byte EaValue["&$EaValueLength+1&"]" ;
		$EaStruct = DllStructCreate($tagFILE_FULL_EA_INFORMATION)
		DllStructSetData($EaStruct,"NextEntryOffset",$NextEntryOffset)
		DllStructSetData($EaStruct,"Flags",$EaFlag)
		DllStructSetData($EaStruct,"EaNameLength",$EaNameLength)
		DllStructSetData($EaStruct,"EaValueLength",$EaValueLength+1)
		DllStructSetData($EaStruct,"EaName",$EaName)
		DllStructSetData($EaStruct,"EaValue",$EaValue)
		$testwrite = _NtSetEaFile($hFile1,$sISB,$EaStruct)
		If @error Then
			ConsoleWrite("Error in NtSetEaFile; " & $testwrite & @CRLF)
			DllCall("ntdll.dll", "int", "NtClose", "hwnd", $hFile1)
		Else
			ConsoleWrite("Wrote " & $EaValueLength & " bytes into $EA entry named: " & $EaName & @CRLF)
		EndIf
		Exit
	Else
		$Remainder = Mod($FileSize,$MaxEaEntrySize)
		$ExpectedLoops = Floor($FileSize/$MaxEaEntrySize)
		If $ExpectedLoops > $TargetFile[0] Then
			ConsoleWrite("Error: Could not find enough files to hide data in" & @CRLF)
			Exit
		EndIf
		$BufferSize = $MaxEaEntrySize
		$Counter = 0
		$Counter2 = 0
		$nBytes = 0
		$BytesProcessed = 0
		Do
			Do
				$szName = DllStructCreate("wchar[260]")
				$sUS = DllStructCreate($tagUNICODESTRING)
				$sOA = DllStructCreate($tagOBJECTATTRIBUTES)
				$sISB = DllStructCreate($tagIOSTATUSBLOCK)
				If $TargetIsDirectory Then
					$TargetFileAndPath = $TargetContainerPath&"\"&$TargetFile[$Counter2+1]
				Else
					$TargetFileAndPath = $TargetFile[1]
				EndIf
				DllStructSetData($szName, 1, "\??\"&$TargetFileAndPath)
				ConsoleWrite("Target is: " & $TargetFileAndPath & @CRLF)
				FileSetAttrib($TargetFileAndPath, "-R")
				If StringInStr(FileGetAttrib($TargetFileAndPath),"D") Then
					$FileMode=$FILE_DIRECTORY_FILE
				Else
					$FileMode=$FILE_NON_DIRECTORY_FILE
				EndIf
				$ret = DllCall("ntdll.dll", "none", "RtlInitUnicodeString", "ptr", DllStructGetPtr($sUS), "ptr", DllStructGetPtr($szName))
				DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
				DllStructSetData($sOA, "RootDirectory", 0)
				DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
				DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
				DllStructSetData($sOA, "SecurityDescriptor", 0)
				DllStructSetData($sOA, "SecurityQualityOfService", 0)
				$ret = DllCall("ntdll.dll", "int", "NtOpenFile", "hwnd*", "", "dword", BitOR($GENERIC_WRITE,$FILE_WRITE_EA), "ptr", DllStructGetPtr($sOA), "ptr", DllStructGetPtr($sISB), "ulong", BitOR($FILE_SHARE_READ,$FILE_SHARE_WRITE), "ulong", BitOR($FileMode,$FILE_RANDOM_ACCESS))
				If NT_SUCCESS($ret[0]) Then
;					ConsoleWrite("NtOpenFile: Success" & @CRLF)
				Else
					ConsoleWrite("NtOpenFile : 0x"&Hex($ret[0],8) &" "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
					_GrantFileAccess($TargetFileAndPath)
				EndIf
				$AccessAttempts+=1
			Until $AccessAttempts >= 3 Or $ret[1]
			If $Counter2 = $TargetFile[0]-1 And Not $ret[1] Then
				ConsoleWrite("Error: Could not hide data." & @CRLF)
				Exit
			EndIf
			If Not $ret[1] Then
				$Counter2+=1
				ContinueLoop
			EndIf
			$Counter2+=1
			$hFile1 = $ret[1]
			If $Counter=$ExpectedLoops Then $BufferSize=$Remainder
			$tBuffer = DllStructCreate("byte[" & $BufferSize & "]")
			$BytesProcessed+=$nBytes
			_WinAPI_SetFilePointer($hFile0, $BytesProcessed)
			$read = _WinAPI_ReadFile($hFile0, DllStructGetPtr($tBuffer), $BufferSize, $nBytes)
			If $read = 0 then
				ConsoleWrite("Error ReadFile failed: " & _WinAPI_GetLastErrorMessage() & @CRLF)
				_WinAPI_CloseHandle($hFile0)
				Exit
			EndIf
			$NextEntryOffset = 0
			$EaName = $TextIdentifier&$Counter
			$EaNameLength = StringLen($EaName)
			$EaValue = DllStructGetData($tBuffer,1)
;			ConsoleWrite(_HexEncode($EaValue) & @CRLF)
			$EaValueLength = BinaryLen($EaValue)
			$tagFILE_FULL_EA_INFORMATION = "ulong NextEntryOffset;byte Flags[1];byte EaNameLength[1];ushort EaValueLength;char EaName["&$EaNameLength&"];byte dummy[1];byte EaValue["&$EaValueLength+1&"]" ;
			$EaStruct = DllStructCreate($tagFILE_FULL_EA_INFORMATION)
			DllStructSetData($EaStruct,"NextEntryOffset",$NextEntryOffset)
			DllStructSetData($EaStruct,"Flags",$EaFlag)
			DllStructSetData($EaStruct,"EaNameLength",$EaNameLength)
			DllStructSetData($EaStruct,"EaValueLength",$EaValueLength+1)
			DllStructSetData($EaStruct,"EaName",$EaName)
			DllStructSetData($EaStruct,"EaValue",$EaValue)
			$testwrite = _NtSetEaFile($hFile1,$sISB,$EaStruct)
			If @error Then
				ConsoleWrite("Error in NtSetEaFile; " & $testwrite & @CRLF)
				DllCall("ntdll.dll", "int", "NtClose", "hwnd", $hFile1)
				$nBytes = 0
				DllCall("ntdll.dll", "int", "NtClose", "hwnd", $hFile1)
				ContinueLoop
			Else
				ConsoleWrite("Wrote " & $EaValueLength & " bytes into $EA entry named: " & $EaName & @CRLF)
			EndIf
			DllCall("ntdll.dll", "int", "NtClose", "hwnd", $hFile1)
			$Counter+=1
		Until $BytesProcessed+$nBytes >= $FileSize
	EndIf
ElseIf $RunMode = 2 Then
	If $FileSize <= $MaxEaEntrySize Then
		$TargetFile = "\??\" & $TargetContainerPath & "\" & _GenerateMd5String() & ".md5"
		$szName = DllStructCreate("wchar[260]")
		$sUS = DllStructCreate($tagUNICODESTRING)
		$sOA = DllStructCreate($tagOBJECTATTRIBUTES)
		$sISB = DllStructCreate($tagIOSTATUSBLOCK)
		DllStructSetData($szName, 1, $TargetFile)
		ConsoleWrite("Target is: " & StringTrimLeft($TargetFile,4) & @CRLF)
		FileSetAttrib(StringTrimLeft($TargetFile,4), "-R")
		If StringInStr(FileGetAttrib(StringTrimLeft($TargetFile,4)),"D") Then
			$FileMode=$FILE_DIRECTORY_FILE
		Else
			$FileMode=$FILE_NON_DIRECTORY_FILE
		EndIf
		$ret = DllCall("ntdll.dll", "none", "RtlInitUnicodeString", "ptr", DllStructGetPtr($sUS), "ptr", DllStructGetPtr($szName))
		DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
		DllStructSetData($sOA, "RootDirectory", 0)
		DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
		DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
		DllStructSetData($sOA, "SecurityDescriptor", 0)
		DllStructSetData($sOA, "SecurityQualityOfService", 0)
		$tBuffer = DllStructCreate("byte[" & $FileSize & "]")
		$tBuffer2 = DllStructCreate("byte[" & $FileSize & "]")
		$read = _WinAPI_ReadFile($hFile0, DllStructGetPtr($tBuffer), $FileSize, $nBytes)
		If $read = 0 then
			ConsoleWrite("Error ReadFile failed: " & _WinAPI_GetLastErrorMessage() & @CRLF)
			_WinAPI_CloseHandle($hFile0)
			Exit
		EndIf
		$NextEntryOffset = 0
		$EaName = $TextIdentifier&"1"
		$EaNameLength = StringLen($EaName)
		$EaValue = DllStructGetData($tBuffer,1)
;		ConsoleWrite(_HexEncode($EaValue) & @CRLF)
		$EaValueLength = BinaryLen($EaValue)
		$tagFILE_FULL_EA_INFORMATION = "ulong NextEntryOffset;byte Flags[1];byte EaNameLength[1];ushort EaValueLength;char EaName["&$EaNameLength&"];byte dummy[1];byte EaValue["&$EaValueLength+1&"]" ;
		$EaStruct = DllStructCreate($tagFILE_FULL_EA_INFORMATION)
		DllStructSetData($EaStruct,"NextEntryOffset",$NextEntryOffset)
		DllStructSetData($EaStruct,"Flags",$EaFlag)
		DllStructSetData($EaStruct,"EaNameLength",$EaNameLength)
		DllStructSetData($EaStruct,"EaValueLength",$EaValueLength+1)
		DllStructSetData($EaStruct,"EaName",$EaName)
		DllStructSetData($EaStruct,"EaValue",$EaValue)
		$ret = DllCall("ntdll.dll", "handle", "NtCreateFile", "hwnd*", "", "ulong", $GENERIC_ALL, "ptr", DllStructGetPtr($sOA), "ptr", DllStructGetPtr($sISB), "int64*", 0, "ulong", $FILE_ATTRIBUTE_NORMAL, "ulong", BitOR($FILE_SHARE_READ,$FILE_SHARE_WRITE), _
							"ulong", $CREATE_ALWAYS, "ulong", $FILE_NON_DIRECTORY_FILE, "ptr", DllStructGetPtr($EaStruct), "ulong", DllStructGetSize($EaStruct))
		If NT_SUCCESS($ret[0]) Then
;			ConsoleWrite("NtCreateFile: Success" & @CRLF)
		Else
			ConsoleWrite("NtCreateFile : 0x"&Hex($ret[0],8) &" "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
			Exit
		EndIf
		$BytesProcessed=0
		$hFile1 = $ret[1]
	Else
		$Remainder = Mod($FileSize,$MaxEaEntrySize)
		$ExpectedLoops = Floor($FileSize/$MaxEaEntrySize)
		$BufferSize = $MaxEaEntrySize
		$Counter = 0
		$nBytes = 0
		$BytesProcessed = 0
		Do
			$TargetFile = $TargetContainerPath & "\" & _GenerateMd5String() & ".md5"
			$szName = DllStructCreate("wchar[260]")
			$sUS = DllStructCreate($tagUNICODESTRING)
			$sOA = DllStructCreate($tagOBJECTATTRIBUTES)
			$sISB = DllStructCreate($tagIOSTATUSBLOCK)
			DllStructSetData($szName, 1, "\??\"&$TargetFile)
			ConsoleWrite("Target is: " & $TargetFile & @CRLF)
			$FileMode=$FILE_NON_DIRECTORY_FILE
			$ret = DllCall("ntdll.dll", "none", "RtlInitUnicodeString", "ptr", DllStructGetPtr($sUS), "ptr", DllStructGetPtr($szName))
			DllStructSetData($sOA, "Length", DllStructGetSize($sOA))
			DllStructSetData($sOA, "RootDirectory", 0)
			DllStructSetData($sOA, "ObjectName", DllStructGetPtr($sUS))
			DllStructSetData($sOA, "Attributes", $OBJ_CASE_INSENSITIVE)
			DllStructSetData($sOA, "SecurityDescriptor", 0)
			DllStructSetData($sOA, "SecurityQualityOfService", 0)
			If $Counter=$ExpectedLoops Then $BufferSize=$Remainder
			$tBuffer = DllStructCreate("byte[" & $BufferSize & "]")
			$tBuffer2 = DllStructCreate("byte[" & $BufferSize & "]")
			$BytesProcessed+=$nBytes
			_WinAPI_SetFilePointer($hFile0, $BytesProcessed)
			$read = _WinAPI_ReadFile($hFile0, DllStructGetPtr($tBuffer), $BufferSize, $nBytes)
			If $read = 0 then
				ConsoleWrite("Error ReadFile failed: " & _WinAPI_GetLastErrorMessage() & @CRLF)
				_WinAPI_CloseHandle($hFile0)
				Exit
			EndIf
			$NextEntryOffset = 0
			$EaName = $TextIdentifier&$Counter
			$EaNameLength = StringLen($EaName)
			$EaValue = DllStructGetData($tBuffer,1)
;			ConsoleWrite(_HexEncode($EaValue) & @CRLF)
			$EaValueLength = BinaryLen($EaValue)
			$tagFILE_FULL_EA_INFORMATION = "ulong NextEntryOffset;byte Flags[1];byte EaNameLength[1];ushort EaValueLength;char EaName["&$EaNameLength&"];byte dummy[1];byte EaValue["&$EaValueLength+1&"]" ;
			$EaStruct = DllStructCreate($tagFILE_FULL_EA_INFORMATION)
			DllStructSetData($EaStruct,"NextEntryOffset",$NextEntryOffset)
			DllStructSetData($EaStruct,"Flags",$EaFlag)
			DllStructSetData($EaStruct,"EaNameLength",$EaNameLength)
			DllStructSetData($EaStruct,"EaValueLength",$EaValueLength+1)
			DllStructSetData($EaStruct,"EaName",$EaName)
			DllStructSetData($EaStruct,"EaValue",$EaValue)
			$ret = DllCall("ntdll.dll", "handle", "NtCreateFile", "hwnd*", "", "ulong", $GENERIC_ALL, "ptr", DllStructGetPtr($sOA), "ptr", DllStructGetPtr($sISB), "int64*", 0, "ulong", $FILE_ATTRIBUTE_NORMAL, "ulong", BitOR($FILE_SHARE_READ,$FILE_SHARE_WRITE), _
							"ulong", $CREATE_ALWAYS, "ulong", $FILE_NON_DIRECTORY_FILE, "ptr", DllStructGetPtr($EaStruct), "ulong", DllStructGetSize($EaStruct))
			If NT_SUCCESS($ret[0]) Then
;				ConsoleWrite("NtCreateFile: Success" & @CRLF)
			Else
				ConsoleWrite("NtCreateFile : 0x"&Hex($ret[0],8) &" "& _TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))) & @CRLF)
				Exit
			EndIf
			$hFile1 = $ret[1]
			DllCall("ntdll.dll", "int", "NtClose", "hwnd", $hFile1)
;			If $Counter > $ExpectedLoops Then ExitLoop
			$Counter+=1
		Until $BytesProcessed+$nBytes >= $FileSize
	EndIf
EndIf
DllCall("ntdll.dll", "int", "NtClose", "hwnd", $hFile1)
_WinAPI_CloseHandle($hFile0)
ConsoleWrite("Success hiding " & $BytesProcessed+$nBytes & " bytes" & @CRLF)
Exit


Func _NtSetEaFile($handle,$statusblock,$struct)
	$ret = DllCall("ntdll.dll", "handle", "NtSetEaFile", "handle", $handle, "ptr", DllStructGetPtr($statusblock), "ptr", DllStructGetPtr($struct), "ulong", DllStructGetSize($struct))
	If Not NT_SUCCESS($ret[0]) Then
		Return SetError(1,0,_TranslateErrorCode(_RtlNtStatusToDosError("0x"&Hex($ret[0],8))))
	Else
		Return True
	EndIf
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

Func _GenerateMd5String()
	Local $MD5=""
	For $i = 1 To 16
		$a = Hex(Random(0,15,1),1)
		$MD5&=$a
	Next
	Return $MD5
EndFunc

Func _ValidateInput()
	Local $TargetAttributes
	Global $TargetPayload, $RunMode, $TextIdentifier, $EaFlag, $TargetIsDirectory, $TargetContainerPath, $SearchFilter, $RecursiveMode
	If $cmdline[0] < 4 Then
		ConsoleWrite("Error: Wrong number of parameters" & @CRLF)
		ConsoleWrite("Syntax is:" & @CRLF)
		ConsoleWrite("EaInject.exe /Payload:TargetPayload /Container:TargetContainer /Mode:{0|1|2} /Identifier:SomeText /Filter:Text /Recurse:boolean" & @CRLF)
		ConsoleWrite("	/Payload is the file with the data to hide" & @CRLF)
		ConsoleWrite("	/Container is the file or path to hide the payload in" & @CRLF)
		ConsoleWrite("	/Mode 0 uses 1 existing file. Mode 1 will search existing files. Mode 2 will create new files in path specified in Container" & @CRLF)
		ConsoleWrite("	/Identifier is some text to use for EA names." & @CRLF)
		ConsoleWrite("	/EaFlag is boolean 0 or 1. Default is 0. A value of 1 triggers setting FILE_NEED_EA flag (0x80) which means target file cannot be interpreted without understanding the associated extended attributes. Default is zero which means ignore." & @CRLF)
		ConsoleWrite("	/Filter is for included results in search. Multiple filters separatet by ';'. Default is '*'." & @CRLF)
		ConsoleWrite("	/Recurse is a boolean value 0 or 1 for acivating/deactivating recursive mode." & @CRLF)
		Exit
	EndIf
	For $i = 1 To $cmdline[0]
		If StringLeft($cmdline[$i],9) = "/Payload:" Then $TargetPayload = StringMid($cmdline[$i],10)
		If StringLeft($cmdline[$i],11) = "/Container:" Then $TargetContainerPath = StringMid($cmdline[$i],12)
		If StringLeft($cmdline[$i],6) = "/Mode:" Then $RunMode = StringMid($cmdline[$i],7)
		If StringLeft($cmdline[$i],12) = "/Identifier:" Then $TextIdentifier = StringMid($cmdline[$i],13)
		If StringLeft($cmdline[$i],8) = "/EaFlag:" Then $EaFlag = StringMid($cmdline[$i],9)
		If StringLeft($cmdline[$i],8) = "/Filter:" Then $SearchFilter = StringMid($cmdline[$i],9)
		If StringLeft($cmdline[$i],9) = "/Recurse:" Then $RecursiveMode = StringMid($cmdline[$i],10)
	Next
	If $RunMode <> 0 And $RunMode <> 1 And $RunMode <> 2 Or Not StringIsDigit($RunMode) Then
		ConsoleWrite("Error: Mode not set correctly: " & $RunMode & @CRLF)
		Exit
	Else
		$RunMode=Int($RunMode)
	EndIf
	If FileExists($TargetPayload) = 0 Or StringInStr(FileGetAttrib($TargetPayload),"D") Then
		ConsoleWrite("Error: Target payoad not valid: " & $TargetPayload & @CRLF)
		Exit
	EndIf
	If FileExists($TargetContainerPath) = 0  Then
		ConsoleWrite("Error: Target container/path does not exist: " & $TargetContainerPath & @CRLF)
		Exit
	EndIf
	$TargetAttributes = FileGetAttrib($TargetContainerPath)
	If @error Then
		ConsoleWrite("Error: Could not evaluate attributes of: " & $TargetContainerPath & @CRLF)
		Exit
	EndIf
	If StringInStr($TargetAttributes,"D") Then
		$TargetIsDirectory = 1
		If StringRight($TargetContainerPath,1)="\" Then $TargetContainerPath = StringTrimRight($TargetContainerPath,1)
		If $RunMode = 1 Then $TargetContainerParentPath = StringMid($TargetContainerPath,1,StringInStr($TargetContainerPath,"\",0,-1)-1)
	Else
		If $RunMode = 1 Or $RunMode = 2 Then
			ConsoleWrite("Error: Container must be a directory when using mode 1 or 2" & @CRLF)
			Exit
		EndIf
		$TargetIsDirectory = 0
	EndIf
	If $TextIdentifier = "" Then
		ConsoleWrite("Error: EA name can not be empty" & @CRLF)
		Exit
	EndIf
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
	If $EaFlag = "" Then
		$EaFlag = 0
	Else
		If $EaFlag <> 0 And $EaFlag <> 1 Then
			ConsoleWrite("Error: EaFlag is boolean and can only be 0 or 1." & @CRLF)
			Exit
		EndIf
		If $EaFlag = 1 Then
			$EaFlag = $FILE_NEED_EA
		EndIf
	EndIf
EndFunc

Func _GrantFileAccess($exe)
	If @OSBuild >= 6000 Then
		RunWait(@ComSpec & " /c " & @WindowsDir & '\system32\takeown.exe /f ' & $exe, "", @SW_HIDE)
		RunWait(@ComSpec & " /c " & @WindowsDir & '\system32\icacls.exe ' & $exe & ' /grant *S-1-5-32-544:F', "", @SW_HIDE)
		Return
	EndIf
EndFunc