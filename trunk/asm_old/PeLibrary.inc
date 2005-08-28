;.======================================================
;| PeLibrary 0.3d by Pumqara <pumqara@abv.bg>
;'======================================================

plOpenFile PROTO :DWORD,:DWORD
plChangeEP PROTO :DWORD
plGetPeInfo PROTO :DWORD,:DWORD
plRVAToOffset	 PROTO :DWORD
plUpdatePeInfo	 PROTO :DWORD
plAboutLib 	 PROTO
plCloseFile	 PROTO
plZeroMemory	 PROTO :DWORD,:DWORD
plSaveToNewFile	 PROTO :DWORD,:DWORD
plInsertWatermark PROTO :DWORD
plDeleteSection	 PROTO :DWORD
plFindSection	 PROTO :DWORD
plGetSectionInfo PROTO :DWORD,:DWORD
plUpdateSectionInfo PROTO :DWORD,:DWORD
plSetFileSize	 PROTO :DWORD
plAddSection	 PROTO :DWORD,:DWORD,:DWORD,:DWORD
plEnumImportFunctions PROTO
plAddImportFunction PROTO :DWORD,:DWORD
plOffsetToRVA	 PROTO :DWORD
plEnumSections	 PROTO
plEnumExportFunctions PROTO
plMapOffsetToRVA PROTO :DWORD
plRVAToMapOffset PROTO :DWORD
plUpdateExportsInfo PROTO :DWORD
plGetExportsInfo PROTO :DWORD
plLocateMapOffset PROTO :DWORD
plLocateOffset	 PROTO :DWORD
plGetImportsInfo	PROTO :DWORD
plUpdateImportsInfo	PROTO :DWORD
plAddDescriptor PROTO :DWORD
plAddApi	PROTO :DWORD
plAddOrdinal	PROTO :DWORD
plUpdateImports PROTO
plCreateImportTable PROTO

.data

; STRiNGS
strAbout   db "PE Library 0.2 by +Pumqara <programs@mail.bg>",0
strAppName db "Pumqara's PE Library 0.2",0
strFilter  db "All Files",0,"*.*",0,0
strOrdinaryFormat db "%04X",0
strPumqara db "+Pumqara",0
             
; STRuCTuRES
ofn   OPENFILENAME <> 

.data?

; VALuES
valFileSize     dd ?
valFunctionsNum dd ?
valBase		dd ?
valBytesWritten dd ?

valNumOfDescriptors	dd ?
valReturnValue	dd ? 
valNumOfApis	dd ?

; HANDLeS
hFile 		dd ? 	 ; CreateFile
hMapFile 	dd ? 	 ; CreateFileMapping
hWriteHandle 	dd ?
hMemory 	dd ?
hSectionsList	dd ?	 ; EnumSections
hExportList	dd ?

; BuFFERS
strFileName 	db 512 dup(?)
strSaveFileName db 512 dup(?)
strImpOrdinal 	db 512 dup(?)

; POiNTERS
pPeFile 	dd ? 	; MapViewOfFile
pMemory		dd ?	
pMemory1	dd ?	; EnumImportFunctions
ptrNewSection	dd ?
ptrImportFunction dd ?
pSectionsList	dd ?	; EnumSections
pExportList	dd ?


ptrApis		dd ?
ptrThunks	dd ?
ptrIAT		dd ?
ptrDescriptors	dd ?
ptrDllNames	dd ?
ptrImportDir	dd ?

; OWN STRuCTuRES
PL_PEINFO struct
	plEntryPoint		DWORD	?
	plImageBase		DWORD	?
	plSizeOfImage		DWORD	?
	plSizeOfHeaders		DWORD	?
	plFileAlignment		DWORD	?
	plCheckSum		DWORD 	?
	plSectionAlignment	DWORD	?           	
	plNumberOfSections	WORD	?	
PL_PEINFO ends


PL_POINTERS struct
	plMZHeader		DWORD	?	
	plPeHeader		DWORD	?
	plSectionsStart		DWORD 	?	
	plOptionalHeader	DWORD	?
	plDirectoriesStart	DWORD 	?	
PL_POINTERS ends


PL_IMPORTS_INFO  struct
	plImportDirRVA		DWORD 	?
	plImportDirSize		DWORD 	?
	plPtrImportDir		DWORD	?
	
	plIATDirRVA		DWORD 	?
	plIATDirSize		DWORD 	?
	plPtrIATDir		DWORD	?
PL_IMPORTS_INFO ends



PL_SECTION_INFO struct
	plName			db 8h dup(?)		
	plVirtualSize		DWORD	?	
	plVirtualAddress	DWORD	?	
	plRawSize		DWORD	?	
	plRawAddress		DWORD	?	
	plCharacteristics	DWORD	?
	
	plPtrSection		DWORD  	?
PL_SECTION_INFO ends



PL_EXPORTS_INFO struc
	plAddrExportDir		DWORD	?
	plSizeOfExportDir	DWORD	?
	
	plBase			DWORD 	?
	plNumOfFunctions	DWORD 	?
	plNumOfNames		DWORD 	?
	plAddrOfFunctions	DWORD 	?
	plAddrOfNames		DWORD 	?
	plAddrOfOrdinals	DWORD 	?
	
	plPtrExportDir		DWORD	?
	plPtrFunctions		DWORD 	?
	plPtrNames		DWORD	?
	plPtrOrdinals		DWORD	?
PL_EXPORTS_INFO ends

comment ~
IMAGE_EXPORT_DIRECTORY STRUCT
  nName                     DWORD      ?
  nBase                     DWORD      ?
  NumberOfFunctions         DWORD      ?
  NumberOfNames             DWORD      ?
  AddressOfFunctions        DWORD      ?
  AddressOfNames            DWORD      ?
  AddressOfNameOrdinals     DWORD      ?
IMAGE_EXPORT_DIRECTORY ENDS

~

peinfostr 	 PL_PEINFO <>
ImportStruct     PL_IMPORTS_INFO <>
PointersStruc	 PL_POINTERS <>
ImportDescriptor IMAGE_IMPORT_DESCRIPTOR <>
ImportByName     IMAGE_IMPORT_BY_NAME <>
ExportStruc	 IMAGE_EXPORT_DIRECTORY <>


.const

cstMaxSize equ 512

PL_NO_OPEN_DIALOG equ 0
PL_USE_OPEN_DIALOG equ 1

PL_NO_SAVE_DIALOG equ 2
PL_USE_SAVE_DIALOG equ 3

PL_ALIGN equ 4
PL_NO_ALIGN equ 5

PL_NORMAL_SECTION equ 0E0000060h


.code

; ===============================================================================================
; [ plOpenFile ]
;
; 	plStyle: (IN)
;		If PL_NO_OPEN_DIALOG -> No Open Dialog
;		If PL_USE_OPEN_DIALOG -> With Open Dialog
;
;	plFileNameBuffer: (IN/OUT)
;		Buffer for the path and filename.
;		If PL_NO_OPEN_DIALOG -> Must contain path and filename.Else will receive it.	
;	
; Returns TRUE if all is ok.Else returns FALSE
; ==============================================================================================		

plOpenFile proc plStyle:DWORD, plFileNameBuffer:DWORD
	pushad
	
	cmp plStyle,PL_NO_OPEN_DIALOG
	je NO_OPEN_DIALOG
	
	mov ofn.lStructSize,SIZEOF ofn
	mov ofn.hWndOwner,NULL
	mov  ofn.hInstance,NULL
	push offset strFilter
	pop  ofn.lpstrFilter
	push plFileNameBuffer
	pop  ofn.lpstrFile
	mov  ofn.nMaxFile,cstMaxSize
	mov  ofn.Flags, OFN_FILEMUSTEXIST or \
             OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
             OFN_EXPLORER or OFN_HIDEREADONLY
	invoke GetOpenFileName, ADDR ofn
	.iF eax==TRUE
		
NO_OPEN_DIALOG:
	invoke lstrcpy,addr strFileName,plFileNameBuffer
	
		invoke CreateFile,plFileNameBuffer,\
                       GENERIC_READ or GENERIC_WRITE ,\
                       FILE_SHARE_READ or FILE_SHARE_WRITE,\
                       NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,\
                       NULL
                       
                .iF eax==-1
                	popad
                	mov eax,FALSE
                	ret 
                .ENDiF
                
		mov dword ptr [hFile],eax
		mov dword ptr [valFileSize],0000000000
		
		invoke GetFileSize,eax,valFileSize
		mov dword ptr [valFileSize],eax
		mov eax,dword ptr [hFile]
		invoke CreateFileMapping,hFile,NULL,PAGE_READWRITE,0,0,NULL
		mov hMapFile,eax
		invoke MapViewOfFile,hMapFile,FILE_MAP_ALL_ACCESS,0,0,0
		mov pPeFile,eax
		popad
		mov eax,TRUE
		
	.ELSE
		 mov eax,FALSE
		 popad
	.ENDiF	

	

	ret
plOpenFile endp


; ===============================================================================================
; [ plSaveFile ]
;
;	plStyle: (iN)
;		If PL_NO_SAVE_DIALOG -> No Save Dialog
;		If PL_USE_SAVE_DIALOG -> With Save Dialog
;
;	plFileNameBuffer:
;		Specifies the string with the filename to save.If used with Save Dialog it is being
;		filled with the saved filename string
;	
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================	

plSaveToNewFile proc plStyle:DWORD, plFileNameBuffer:DWORD

	pushad
	
	cmp plStyle,PL_NO_SAVE_DIALOG
	je NO_SAVE_DIALOG
	
	mov ofn.lStructSize,SIZEOF ofn
	mov ofn.hWndOwner,NULL
	mov  ofn.hInstance,NULL
	push offset strFilter
	pop  ofn.lpstrFilter
	push offset strSaveFileName
	pop  ofn.lpstrFile
	mov  ofn.nMaxFile,cstMaxSize
	mov  ofn.Flags, OFN_FILEMUSTEXIST or \
             OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
             OFN_EXPLORER or OFN_HIDEREADONLY
	invoke GetSaveFileName, ADDR ofn
	.iF eax==TRUE
	jmp skip_copy
	
NO_SAVE_DIALOG:
	invoke lstrcpy,addr strSaveFileName,plFileNameBuffer
   skip_copy:
       invoke CreateFile,ADDR strSaveFileName,\ 
                    GENERIC_READ or GENERIC_WRITE ,\ 
                    FILE_SHARE_READ or FILE_SHARE_WRITE,\ 
                    NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_ARCHIVE,\ 
                    NULL 
       mov dword ptr [hWriteHandle],eax      
       .iF eax==-1
       popad
       mov eax,FALSE
       ret 
        
       .ENDiF
                
        mov ebx,dword ptr [valFileSize]
        lea ecx,offset valBytesWritten
	invoke WriteFile,eax,pPeFile,ebx,ecx,NULL
	cmp eax,FALSE
	je write_error
	mov eax,dword ptr [hWriteHandle]
	invoke CloseHandle,eax
	
	popad
	mov eax,TRUE
	ret	
		
	.ELSE
write_error:
	mov eax,FALSE
	popad
	ret
	.ENDiF	

plSaveToNewFile endp


; ===============================================================================================
; [ plCloseFile ]
;
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================	

plCloseFile proc 
	pushad
	
	invoke UnmapViewOfFile,pPeFile
	.iF eax==0
                popad
                mov eax,FALSE
               	ret 
	.ENDiF
	
	mov pPeFile,0
	invoke CloseHandle,hMapFile
        mov    hMapFile,0
        invoke CloseHandle,hFile
        mov hFile,0
        invoke GlobalUnlock,pMemory
        mov pMemory,0
        invoke GlobalFree,hMemory 
	mov hMemory,0
	popad
	
	mov eax,TRUE
	ret
plCloseFile endp


; ===============================================================================================
; [ plChangeEP ]
;
;	plNewEP: (iN)
;		New Entry Point (Hex number)
;
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================	

plChangeEP proc plNewEP:DWORD
	pushad
	
	.iF pPeFile==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	
	mov eax,pPeFile
	add eax,3Ch
	mov eax,dword ptr [eax]
	mov ecx,pPeFile
	add ecx,eax
	add ecx,28h
	mov eax,plNewEP
	mov dword ptr [ecx],eax
	
	popad
	mov eax,TRUE
	ret
plChangeEP endp


; ===============================================================================================
; [ plGetPeInfo ]
;
;	plPL_PEINFO: 
;		Points to the PL_PEINFO structure, which will be filled.If NULL -> skipped
;
;	plPL_POINTERS:
;		Points to the PL_POINTERS structure, which will be filled.If NULL -> skipped
;
;
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================


	

plGetPeInfo proc plPL_PEINFO:DWORD, plPL_POINTERS:DWORD
	pushad
	
	.iF pPeFile==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	

comment ~

PL_POINTERS struct
	plMZHeader		DWORD	?	
	plPeHeader		DWORD	?
	plSectionsStart		DWORD 	?	
	plOptionalHeader	DWORD	?
	plDirectoriesStart	DWORD 	?	
PL_POINTERS ends
~	
	
	
	mov eax,pPeFile
	add eax,3Ch
	mov eax,dword ptr [eax]
	mov ecx,pPeFile
	add ecx,eax
	mov esi,ecx
	cmp plPL_POINTERS,0
	je skipPL_POINTERS
	
	
	mov edi,plPL_POINTERS
	assume edi:ptr PL_POINTERS 
	
	push pPeFile
	pop [edi].plMZHeader
	
	mov [edi].plPeHeader,ecx
	
	
	mov eax,ecx
	add eax,0f8h
	mov [edi].plSectionsStart,eax
	
	mov eax,ecx
	add eax,18h
	mov [edi].plOptionalHeader,eax
	
	mov eax,ecx
	add eax,78h
	mov [edi].plDirectoriesStart,eax
	
	
	
skipPL_POINTERS:
	
	cmp plPL_PEINFO,0
	je skipPL_PEINFO
	
; Fill PEINFO
comment ~

PL_PEINFO struct
	plEntryPoint		DWORD	?
	plImageBase		DWORD	?
	plSizeOfImage		DWORD	?
	plSizeOfHeaders		DWORD	?
	plFileAlignment		DWORD	?
	plCheckSum		DWORD 	?
	plSectionAlignment	DWORD	?           	
	plNumberOfSections	WORD	?	
PL_PEINFO ends

~	
	mov eax,pPeFile
	add eax,3Ch
	mov eax,dword ptr [eax]
	mov ecx,pPeFile
	add ecx,eax
	add ecx,28h
	mov eax,dword ptr [ecx]
	mov edi,plPL_PEINFO
	assume edi:ptr PL_PEINFO 
	mov [edi].plEntryPoint,eax
	
	mov ecx,esi
	
	mov eax,ecx
	add eax,34h
	mov eax,dword ptr [eax]
	mov [edi].plImageBase,eax
	
	mov eax,ecx
	add eax,50h
	mov eax,dword ptr [eax]
	mov [edi].plSizeOfImage,eax
	
	mov eax,ecx
	add eax,54h
	mov eax,dword ptr [eax]
	mov [edi].plSizeOfHeaders,eax
	
	mov eax,ecx
	add eax,3ch
	mov eax,dword ptr [eax]
	mov [edi].plFileAlignment,eax
	
	mov eax,ecx
	add eax,58h
	mov eax,dword ptr [eax]
	mov [edi].plCheckSum,eax
	
	mov eax,ecx
	add eax,38h
	mov eax,dword ptr [eax]
	mov [edi].plSectionAlignment,eax
	
	mov eax,ecx
	add eax,6h
	xor ebx,ebx
	mov bx,word ptr [eax]
	mov [edi].plNumberOfSections,bx
	
skipPL_PEINFO:

	
	popad
	mov eax,TRUE
	ret
plGetPeInfo endp


; ===============================================================================================
; [ plUpdatePeInfo ]
;
;	plPL_PEINFO:
;		Pointer to the updated PL_PEINFO struc, which will be injected in the file.
;
;
; Returns TRUE if all is ok, else returns FALSE.
; ===============================================================================================

plUpdatePeInfo proc plPL_PEINFO:DWORD 

	pushad
	
	.iF pPeFile==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF	
	
	.iF plPL_PEINFO==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF	

	
; Fill PEINFO
comment ~

PL_PEINFO struct
	plEntryPoint		DWORD	?
	plImageBase		DWORD	?
	plSizeOfImage		DWORD	?
	plSizeOfHeaders		DWORD	?
	plFileAlignment		DWORD	?
	plCheckSum		DWORD 	?
	plSectionAlignment	DWORD	?           	
	plNumberOfSections	WORD	?	
PL_PEINFO ends

~	
	mov eax,pPeFile
	add eax,3Ch
	mov eax,dword ptr [eax]
	mov ecx,pPeFile
	add ecx,eax
	
	mov esi,ecx
	
	
	add ecx,28h
	mov edi,plPL_PEINFO
	assume edi:ptr PL_PEINFO 
	push [edi].plEntryPoint
	pop dword ptr [ecx]
	
	mov ecx,esi
	
	mov eax,ecx
	add eax,34h
	push [edi].plImageBase
	pop dword ptr [eax]
	
	mov eax,ecx
	add eax,50h
	push [edi].plSizeOfImage
	pop dword ptr [eax]
	
	mov eax,ecx
	add eax,54h
	push [edi].plSizeOfHeaders
	pop dword ptr [eax]

	
	mov eax,ecx
	add eax,3ch
	push [edi].plFileAlignment
	pop dword ptr [eax]
	
	mov eax,ecx
	add eax,58h
	push [edi].plCheckSum
	pop dword ptr [eax]
	
	mov eax,ecx
	add eax,38h
	push [edi].plSectionAlignment
	pop dword ptr [eax]
	
	mov eax,ecx
	add eax,6h
	xor ebx,ebx
	push [edi].plNumberOfSections
	pop word ptr [eax]

	popad
	mov eax,TRUE
	ret

plUpdatePeInfo endp


; ===============================================================================================
; [ plRVAToOffset ]
;
;	plRVA:
;		Contains the RVA to be converted.
;
; Returns File Offset it EAX if all is ok, else returns FALSE
; ===============================================================================================


plRVAToOffset PROC plRVA:DWORD
	
	push ebx
	push ecx
	push edx
	push edi
	push esi
	
	mov esi,pPeFile
	assume esi:ptr IMAGE_DOS_HEADER
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	mov edi,plRVA
	mov edx,esi
	add edx,sizeof IMAGE_NT_HEADERS
	mov cx,[esi].FileHeader.NumberOfSections
	movzx ecx,cx
	assume edx:ptr IMAGE_SECTION_HEADER
	.while ecx>0	; check all sections
		.if edi>=[edx].VirtualAddress
			mov eax,[edx].VirtualAddress
			add eax,[edx].SizeOfRawData
			.if edi<eax	; The address is in this section
				mov eax,[edx].VirtualAddress
				sub edi,eax	; edi == difference between the specified RVA and the section's RVA
				mov eax,[edx].PointerToRawData
				add eax,edi	; eax == file offset
				pop esi
				pop edi
				pop edx
				pop ecx
				pop ebx
				ret
			.endif
		.endif
		add edx,sizeof IMAGE_SECTION_HEADER
		dec ecx
	.endw
	assume edx:nothing
	assume esi:nothing
	pop esi
	pop edi
	pop edx
	pop ecx
	pop ebx
	
	mov eax,FALSE
	
	ret
plRVAToOffset endp


; ===============================================================================================
; [ plZeroMemory ]
;
;	plAddress:
;		Points to the address from which the zeroing will begin.
;
;	plLenght:
;		Lenght to zero.
;	
; Returns TRUE if all is ok, else returns FALSE.
; ===============================================================================================

plZeroMemory proc  plAddress:DWORD, plLenght:DWORD
	pushad
	.IF plLenght==0
		popad
		mov eax,FALSE
		ret
	.ENDIF
	
	.IF plAddress==0
		popad
		mov eax,FALSE
		ret
	.ENDIF
	
	xor eax,eax
	mov ecx,plLenght
	mov edi,plAddress
	
	rep stosb
	
	popad
	mov eax,TRUE
	ret
plZeroMemory endp

; ===============================================================================================
; [ plInsertWatermark ]
;
;		Inserts a WaterMark overwriting the "This Program cannot be run in MSDOS"
;
;	plWaterMarkString:
;		Pointer to the string with the watermark.Lenght must be < 37h
;
; ===============================================================================================

plInsertWatermark proc plWaterMarkString:DWORD
	pushad
	
	.iF pPeFile==0
   lenght_error:
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	
	invoke lstrlen,plWaterMarkString
	cmp eax,37
	jg lenght_error
	
	mov eax,pPeFile
	add eax,4Eh
	invoke lstrcpy,eax,plWaterMarkString
	
	popad
	mov eax,TRUE
        ret 
plInsertWatermark endp


; ===============================================================================================
; [ plDeleteSection ]
;
;	plSectionNumber:
;		Specifies the number of section to delete
;
;	plAlign:
;		PL_ALIGN --> Align File
;		PL_NO_ALIGN --> Do not Align File
;
; Returns TRUE if all is ok, else -> FALSE
; ===============================================================================================

plDeleteSection proc plSectionNumber:DWORD;, plAlign:DWORD
	pushad
	
	.iF pPeFile==0

                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plSectionNumber==0
		
                popad
                mov eax,FALSE
                ret 
	.ENDiF

	invoke plGetPeInfo,addr peinfostr,NULL
	
	lea edi,offset peinfostr
	
	xor edx,edx
	mov dx,word ptr [edi+1Ch]

	mov edi,pPeFile
	add edi,3Ch
	mov eax,dword ptr [edi]
	mov edi,pPeFile
	add edi,eax
	add edi,sizeof IMAGE_NT_HEADERS 
	; Ve4e se namirame na Section table
	mov eax,plSectionNumber
	imul eax,eax,28h
	sub eax,28h
	add edi,eax 	; edi = sekciata za iztrivane
	
	assume edi:ptr IMAGE_SECTION_HEADER
	
	mov eax,plSectionNumber
	
	mov ecx,[edi].SizeOfRawData
	push ecx
	mov ebx,[edi].PointerToRawData
	
	mov esi,edi ; edi = sekciata za iztrivane
	push edi
	add esi,28h ; esi = sledva6tata sekcia
	
	sub edx,eax	; edx = broi sekcii sled tazi za triene

	mov eax,edx
	imul eax,eax,28h
	mov ecx,eax
	;add edi,28h
	rep movsb
	
	pop edi
	imul edx,edx,28h
	add edi,edx ; edi = kraia na premestenite sekcii
	
	invoke plZeroMemory,edi,edx
	
	pop ecx
	
	add ebx,pPeFile
	invoke plZeroMemory,ebx,ecx
	
	mov edi,pPeFile
	add edi,3Ch
	mov eax,dword ptr [edi]
	mov edi,pPeFile
	add edi,eax
	
	dec word ptr [edi+6]
	
	popad
	mov eax,TRUE
	ret
plDeleteSection endp

; ===============================================================================================
; [ plFindSection ]
;
;	plSectionName:
;		Specifies the name of the section to find
;
; Returns the number of the section if all is ok, else -> FALSE
; ===============================================================================================

plFindSection proc plSectionName:DWORD

	push ebx
	push ecx
	push edx
	push esi
	push edi
	
	.iF pPeFile==0

                pop edi
	   	pop esi
	   	pop edx
	   	pop ecx
	   	pop ebx	
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plSectionName==0
		
                pop edi
	   	pop esi
	   	pop edx
	   	pop ecx
	   	pop ebx	
                mov eax,FALSE
                ret 
	.ENDiF
	
	
	mov edi,pPeFile
	add edi,3Ch
	mov eax,dword ptr [edi]
	mov edi,pPeFile
	xor edx,edx
	add edi,eax
	mov dx,word ptr [edi+6]
	add edi,sizeof IMAGE_NT_HEADERS
	xor esi,esi
	
   find_section:
   	mov ecx,plSectionName
   	mov eax,dword ptr [edi]
   	mov ebx,dword ptr [ecx]
   	cmp eax,ebx
   	jne next_section
   	mov eax,dword ptr [edi+4]
   	mov ebx,dword ptr [ecx+4]
   	cmp eax,ebx
   	jne next_section
   	
   	jmp found_it
   	
   next_section:
	add edi,28h
	
	inc esi
	cmp esi,edx
	jne find_section
	mov eax,FALSE
	jmp end_search
	
   found_it:
   	inc esi
	mov eax,esi
  
  end_search:
   	
   	pop edi
   	pop esi
   	pop edx
   	pop ecx
   	pop ebx	
   	ret
plFindSection endp


; ===============================================================================================
; [ plGetSectionInfo ]
;
;	plPL_SECTION_INFO:
;		Ponter to the PL_SECTION_INFO structure to be filled.
;
;	plSectionNumber:
;		Number of section.		
;
; Returns TRUE if all is ok, else -> FALSE
; ===============================================================================================

plGetSectionInfo proc plPL_SECTION_INFO:DWORD, plSectionNumber:DWORD
	pushad
	
	.iF pPeFile==0

                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plSectionNumber==0
		
        sec_num_error:
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plPL_SECTION_INFO==0
		
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	invoke plGetPeInfo,addr peinfostr,NULL
	
	lea edi,offset peinfostr
	
	xor edx,edx
	mov dx,word ptr [edi+1Ch]

	mov edi,pPeFile
	add edi,3Ch
	mov eax,dword ptr [edi]
	mov edi,pPeFile
	add edi,eax
	add edi,sizeof IMAGE_NT_HEADERS 
	; Ve4e se namirame na Section table
	mov eax,plSectionNumber
	cmp eax,edx
	jg sec_num_error
	imul eax,eax,28h
	sub eax,28h
	add edi,eax 	; edi = sekciata
	assume edi:ptr IMAGE_SECTION_HEADER
comment ~
PL_SECTION_INFO struct
	plName			db 8h dup(?)		
	plVirtualSize		DWORD	?	
	plVirtualAddress	DWORD	?	
	plRawSize		DWORD	?	
	plRawAddress		DWORD	?	
	plCharacteristics	DWORD	?
	
	plPtrSection		DWORD  	?
PL_SECTION_INFO ends

~	
	mov esi,plPL_SECTION_INFO
	assume esi:ptr PL_SECTION_INFO
	
	push [edi].PointerToRawData
	pop [esi].plRawAddress
	
	mov eax,[edi].PointerToRawData
        mov ebx,pPeFile
        add ebx,eax
	mov [esi].plPtrSection,ebx
	
	push [edi].SizeOfRawData
	pop [esi].plRawSize
	
	push [edi].Characteristics
	pop [esi].plCharacteristics
	
	push [edi].Misc.VirtualSize
	pop [esi].plVirtualSize
	
	push [edi].VirtualAddress 
	pop [esi].plVirtualAddress
	
	mov eax,dword ptr [edi]
	mov dword ptr [esi],eax
	
	mov eax,dword ptr [edi+4]
	mov dword ptr [esi+4],eax
	
	
	popad
	mov eax,TRUE
	ret
plGetSectionInfo endp
	
	
; ===============================================================================================
; [ plUpdateSectionInfo ]
;
;	plPL_SECTION_INFO:
;		Ponter to the PL_SECTION_INFO structure.
;
;	plSectionNumber:
;		Number of section.		
;
; Returns TRUE if all is ok, else -> FALSE
; ===============================================================================================

plUpdateSectionInfo proc plPL_SECTION_INFO:DWORD, plSectionNumber:DWORD
	pushad
	
	.iF pPeFile==0

                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plSectionNumber==0
		
       sec_num: popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plPL_SECTION_INFO==0
		
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	invoke plGetPeInfo,addr peinfostr,NULL
	
	lea edi,offset peinfostr
	
	xor edx,edx
	mov dx,word ptr [edi+1Ch] ; num of sections

	mov edi,pPeFile
	add edi,3Ch
	mov eax,dword ptr [edi]
	mov edi,pPeFile
	add edi,eax
	add edi,sizeof IMAGE_NT_HEADERS 
	; Ve4e se namirame na Section table
	mov eax,plSectionNumber
	cmp eax,edx
	jg sec_num
	imul eax,eax,28h
	sub eax,28h
	add edi,eax 	; edi = sekciata
	assume edi:ptr IMAGE_SECTION_HEADER
comment ~
PL_SECTION_INFO struct
	plName			db 8h dup(?)		
	plVirtualSize		DWORD	?	
	plVirtualAddress	DWORD	?	
	plRawSize		DWORD	?	
	plRawAddress		DWORD	?	
	plCharacteristics	DWORD	?
	
	plPtrSection		DWORD  	?
PL_SECTION_INFO ends

~	
	mov esi,plPL_SECTION_INFO
	assume esi:ptr PL_SECTION_INFO
	
	push [esi].plRawAddress
	pop [edi].PointerToRawData
	
	mov eax,[edi].PointerToRawData
        mov ebx,pPeFile
        add ebx,eax
	mov [esi].plPtrSection,ebx
	
	push [esi].plRawSize
	pop [edi].SizeOfRawData
	
	push [esi].plCharacteristics
	pop [edi].Characteristics
	
	push [esi].plVirtualAddress
	pop [edi].VirtualAddress
	
	push [esi].plVirtualSize
	pop [edi].Misc.VirtualSize
	
	
	
	mov eax,dword ptr [esi]
	mov dword ptr [edi],eax
	
	mov eax,dword ptr [esi+4]
	mov dword ptr [edi+4],eax
	
	
	popad
	mov eax,TRUE
	ret
plUpdateSectionInfo endp	


; ===============================================================================================
; [ plSetFileSize ]
;
;	plFileSize:
;		Contains the FileSize value.
;
; Returns TRUE if all is ok, else FALSE
; ===============================================================================================

plSetFileSize proc plFileSize:DWORD
	pushad
	
	.iF pPeFile==0

                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,plFileSize
        mov  hMemory,eax 
        invoke GlobalLock,hMemory 
        mov  pMemory,eax 
	
	mov eax,plFileSize
	cmp eax,valFileSize	;  Future Size < Real Size  ?
	jle skip1
	
	mov ecx,valFileSize
	mov esi,pPeFile
	mov edi,pMemory
 
	rep movsb
	
	jmp continue1
	
skip1:
	mov ecx,plFileSize
	mov esi,pPeFile
	mov edi,pMemory
 
	rep movsb

continue1:

	invoke UnmapViewOfFile,pPeFile
	mov pPeFile,0
	invoke CloseHandle,hMapFile
	mov hMapFile,0

	invoke CreateFile,ADDR strFileName,\ 
                    GENERIC_READ or GENERIC_WRITE ,\ 
                    FILE_SHARE_READ or FILE_SHARE_WRITE,\ 
                    NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_ARCHIVE,\ 
                    NULL 
        push eax      
        lea ecx,offset valBytesWritten     
	invoke WriteFile,eax,pMemory,plFileSize,ecx,NULL
	
	
	pop eax
	push eax
	invoke CreateFileMapping,eax,NULL,PAGE_READWRITE,0,0,NULL
	mov hMapFile,eax
	invoke MapViewOfFile,hMapFile,FILE_MAP_ALL_ACCESS,0,0,0
	mov pPeFile,eax
	
	invoke GlobalUnlock,pMemory
        invoke GlobalFree,hMemory 
	
	pop eax
	invoke CloseHandle,eax
	
	push plFileSize
	pop dword ptr [valFileSize]
	
	popad
	mov eax,TRUE
	ret
plSetFileSize endp

; ===============================================================================================
; [ plAddSection ]
;
;	plName:
;		Points to a 8 bytes long buffer with the name of section.
;		Should be definied like this [ Section_Name db ".Sect",0,0,0,0]
;
;	plRawSize:
;		a
;	
;	plVirtualSize:
;		a
;		
;	plCharacteristics:
;		a		
;	
;
; Returns pointer to the section if all is ok, else FALSE
; ===============================================================================================

plAddSection proc plName:DWORD, plRawSize:DWORD, plVirtualSize:DWORD, plCharacteristics:DWORD
	pushad
	
	.iF pPeFile==0

                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plName==0

                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plRawSize==0

                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plVirtualSize==0

                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plCharacteristics==0

                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	invoke plGetPeInfo,addr peinfostr,NULL
	lea edi,offset peinfostr
	xor edx,edx
	mov dx,word ptr [edi+1Ch] ; num of sections
	inc dword ptr [edi+1Ch]
	mov edi,pPeFile
	add edi,3Ch
	mov eax,dword ptr [edi]
	mov edi,pPeFile
	add edi,eax
	add edi,sizeof IMAGE_NT_HEADERS 
	mov eax,edx
	imul eax,eax,28h
	add edi,eax 	; edi = sekciata
	
	push edi
	
	mov ecx,8h
	mov esi,plName
	rep movsb
	
	pop edi
	
	assume edi:ptr IMAGE_SECTION_HEADER
	
	mov [edi].PointerToRelocations,0
	mov [edi].PointerToLinenumbers,0
	mov [edi].NumberOfRelocations,0
	mov [edi].NumberOfLinenumbers,0
	
	push plRawSize
	pop [edi].SizeOfRawData
	
	push plVirtualSize
	pop [edi].Misc.VirtualSize
	
	push plCharacteristics
	pop [edi].Characteristics
	
	sub edi,28h	; predi6nata sekcia
	assume edi:ptr IMAGE_SECTION_HEADER
	
	mov eax,[edi].PointerToRawData
	mov ebx,[edi].VirtualAddress
	add eax,[edi].SizeOfRawData
	add ebx,[edi].Misc.VirtualSize
	
	
	
	lea esi,offset peinfostr
	assume esi:ptr PL_PEINFO
	
	mov ecx,plVirtualSize
	add [esi].plSizeOfImage,ecx
	
; Align Raw	
	xor edx,edx
	mov ecx,[esi].plFileAlignment
	div ecx
	push edx

	mul ecx
	
	pop edx
	cmp edx,0000000h
	je skip_filealign
	
	add eax,[esi].plFileAlignment
	
skip_filealign:	
	push eax
	
; Align Virtually
	mov eax,ebx	
	xor edx,edx
	mov ecx,[esi].plSectionAlignment
	div ecx
	push edx
	
	mul ecx
	
	pop edx
	cmp edx,0000000h
	je skip_section_align
	
	add eax,[esi].plSectionAlignment
	
skip_section_align:
	
	mov ebx,eax
	pop eax
	
	
	add edi,28h	; go to our new section
	
	assume edi:ptr IMAGE_SECTION_HEADER
	
	mov [edi].PointerToRawData,eax
	mov [edi].VirtualAddress,ebx
	
	
	sub edi,28h	; go back to previous
	assume edi:ptr IMAGE_SECTION_HEADER
	
	push eax
	sub eax,[edi].PointerToRawData
	add eax,[edi].SizeOfRawData
	add plRawSize,eax
	pop eax
	
	push eax
	
	invoke plUpdatePeInfo,addr peinfostr
	
	mov ecx,dword ptr [valFileSize]
	add ecx,plRawSize
	invoke plSetFileSize,ecx
	
	pop eax
	add eax,pPeFile
	mov dword ptr [ptrNewSection],eax
	;invoke plZeroMemory,eax,plRawSize
	
	popad
	mov eax,dword ptr [ptrNewSection]
	ret
plAddSection endp


; ===============================================================================================
; [ plEnumImportFunctions ]
;
;
; Returns pointer to a buffer with all names of imports, separated by 0Dh,0Ah bytes (new line
;, if all is ok, else FALSE
; ===============================================================================================

plEnumImportFunctions proc
	pushad

	.iF pPeFile==0
	
		popad
		mov eax,FALSE
		ret 
	.ENDiF

	invoke plGetImportsInfo, ADDR ImportStruct
	
	invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,5000h
	mov hMemory,eax
	invoke GlobalLock,hMemory
	mov pMemory,eax
	mov pMemory1,eax
	
	lea edi,offset ImportStruct
	assume edi:ptr PL_IMPORTS_INFO

	mov edi,[edi].plPtrImportDir
	assume edi:ptr IMAGE_IMPORT_DESCRIPTOR
	
   .while !([edi].OriginalFirstThunk==0 && [edi].TimeDateStamp==0 && [edi].ForwarderChain==0 && [edi].Name1==0 && [edi].FirstThunk==0)
	
	.if [edi].OriginalFirstThunk==0
		mov esi,[edi].FirstThunk
	.else
		mov esi,[edi].OriginalFirstThunk
	.endif

	invoke plRVAToOffset,esi
	add eax,pPeFile
	mov esi,eax


	.while dword ptr [esi]!=0

		test dword ptr [esi],IMAGE_ORDINAL_FLAG32
		jnz ImportByOrdinal
		
		invoke plRVAToOffset,dword ptr [esi]
		mov edx,eax
		add edx,pPeFile

		assume edx:ptr IMAGE_IMPORT_BY_NAME
		lea ecx,[edx].Name1
		
		
		push ecx
		invoke lstrcpy,pMemory1,ecx
		pop ecx
		invoke lstrlen,ecx


		mov ebx,pMemory1
		add ebx,eax
		mov byte ptr [ebx],0Dh
		mov byte ptr [ebx+1],0Ah
		add ebx,2h
		mov pMemory1,ebx
		
		jmp EnumLoop

	ImportByOrdinal:
		mov edx,dword ptr [esi]
		and edx,0FFFFh
		invoke wsprintf,addr strImpOrdinal,addr strOrdinaryFormat,edx
		
		lea ecx,offset strImpOrdinal
		push ecx
		invoke lstrcpy,pMemory1,ecx
		pop ecx
		invoke lstrlen,ecx
		
		mov ebx,pMemory1
		add ebx,eax
		mov byte ptr [ebx],0Dh
		mov byte ptr [ebx+1],0Ah
		add ebx,2h
		mov pMemory1,ebx
		
	EnumLoop:			
		add esi,4h
	.endw				
		add edi,sizeof IMAGE_IMPORT_DESCRIPTOR
   .endw


	popad
	mov eax,pMemory
	ret
plEnumImportFunctions endp

; ===============================================================================================
; [ plAddImportFunction ]
;
;	plModuleName:
;		Name of Library.
;
;	plFunctionName:
;		Name Of Function.		
;
; Returns The RVA of Function's address if all is ok, else -> FALSE
; To call function :  call dword ptr [Return Value]
; ===============================================================================================


plAddImportFunction proc plLibraryName:DWORD, plFunctionName:DWORD
	pushad
	
	.iF pPeFile==0
	
		popad
		mov eax,FALSE
		ret 
	.ENDiF
	
	invoke plGetImportsInfo,ADDR ImportStruct
	
	lea edi,offset ImportStruct
	assume edi:ptr PL_IMPORTS_INFO
	mov eax,[edi].plImportDirSize
	add eax,300h
	invoke plAddSection,addr strPumqara,eax,eax,PL_NORMAL_SECTION
	push eax
	
	sub eax,pPeFile
	invoke plOffsetToRVA,eax
	mov [edi].plImportDirRVA,eax
	
	
	pop eax
	
	lea esi,offset ImportStruct
	assume esi:ptr PL_IMPORTS_INFO
	mov edi,[esi].plPtrImportDir
	assume edi:ptr IMAGE_IMPORT_DESCRIPTOR
	xor ecx,ecx
   
   .while !([edi].OriginalFirstThunk==0 && [edi].TimeDateStamp==0 && [edi].ForwarderChain==0 && [edi].Name1==0 && [edi].FirstThunk==0)
	
		add ecx,sizeof IMAGE_IMPORT_DESCRIPTOR
		add edi,sizeof IMAGE_IMPORT_DESCRIPTOR
   .endw
	
	
	add ecx,sizeof IMAGE_IMPORT_DESCRIPTOR
	mov [esi].plImportDirSize,ecx
	
	sub ecx,sizeof IMAGE_IMPORT_DESCRIPTOR
	mov edi,eax
	mov esi,[esi].plPtrImportDir
	rep movsb
	
	lea ebx, offset ImportDescriptor
	assume ebx:ptr IMAGE_IMPORT_DESCRIPTOR
	
	mov [ebx].OriginalFirstThunk,0
	mov [ebx].TimeDateStamp,0
	mov [ebx].ForwarderChain,0
	
	mov ecx,edi
	add ecx,sizeof IMAGE_IMPORT_DESCRIPTOR
	add ecx,sizeof IMAGE_IMPORT_DESCRIPTOR
	add ecx,8h
	sub ecx,pPeFile
	invoke plOffsetToRVA,ecx
	add ecx,pPeFile
	mov [ebx].Name1,eax
	
	mov ecx,edi
	add ecx,sizeof IMAGE_IMPORT_DESCRIPTOR
	add ecx,sizeof IMAGE_IMPORT_DESCRIPTOR
	sub ecx,pPeFile
	invoke plOffsetToRVA,ecx
	add ecx,pPeFile
	
	mov [ebx].FirstThunk,eax
	
	pushad
	mov dword ptr [ptrImportFunction],eax
	invoke plGetPeInfo,addr peinfostr,NULL
	lea edi,offset peinfostr
	assume edi:ptr PL_PEINFO
	mov eax,dword ptr [ptrImportFunction]
	add eax,[edi].plImageBase
	mov dword ptr [ptrImportFunction],eax
	popad
	
	xor ecx,ecx
	mov ecx,sizeof IMAGE_IMPORT_DESCRIPTOR
	mov esi,ebx
	rep movsb
	
	; 2x Import_DESCRIPTOR
	; FirstThunk
	; 00000000
	; ModuleName
	; Import_By_Name
	
	add edi,sizeof IMAGE_IMPORT_DESCRIPTOR
	add edi,8h
	invoke lstrlen,plLibraryName
	mov ecx,eax
	mov esi,plLibraryName
	rep movsb
	
	push eax
	sub edi,pPeFile
	invoke plOffsetToRVA,edi
	add edi,pPeFile
	
	pop ebx
	mov ecx,edi
	sub ecx,ebx
	sub ecx,8h
	mov dword ptr [ecx],eax
	
	add edi,2h ; Hint = 0
	invoke lstrlen,plFunctionName
	mov ecx,eax
	mov esi,plFunctionName
	
	rep movsb 
	
	invoke plUpdateImportsInfo,addr ImportStruct
	
	popad
	mov eax,dword ptr [ptrImportFunction]
	ret
plAddImportFunction endp


; ===============================================================================================
; [ plOffsetToRVA ]
;
;	plOffset:
;		Contains the Offset to be converted.
;
; Returns RVA in EAX if all is ok, else returns FALSE
; ===============================================================================================


plOffsetToRVA PROC plOffset:DWORD
	
	push ebx
	push ecx
	push edx
	push edi
	push esi
	
	.iF pPeFile==0
	
		popad
		mov eax,FALSE
		ret 
	.ENDiF
	
	mov esi,pPeFile
	assume esi:ptr IMAGE_DOS_HEADER
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	mov edi,plOffset
	;sub edi,pPeFile
	mov edx,esi
	add edx,sizeof IMAGE_NT_HEADERS
	mov cx,[esi].FileHeader.NumberOfSections
	movzx ecx,cx
	assume edx:ptr IMAGE_SECTION_HEADER
	.while ecx>0	; check all sections
		.if edi>=[edx].PointerToRawData
			mov eax,[edx].PointerToRawData
			add eax,[edx].SizeOfRawData
			.if edi<eax	; The address is in this section
				mov eax,[edx].PointerToRawData
				sub edi,eax	; edi == Offset - PointerToRawData
				mov eax,[edx].VirtualAddress
				add eax,edi	; eax == Offset - PointerToRawData + VirtualAddress
				pop esi
				pop edi
				pop edx
				pop ecx
				pop ebx
				ret
			.endif
		.endif
		add edx,sizeof IMAGE_SECTION_HEADER
		dec ecx
	.endw
	assume edx:nothing
	assume esi:nothing
	pop esi
	pop edi
	pop edx
	pop ecx
	pop ebx
	
	mov eax,FALSE
	
	ret
plOffsetToRVA endp


; ===============================================================================================
; [ plEnumExportFunctions ]
;
;	Enumerates all Exported Functions, seperated by New Line.
; ===============================================================================================

plEnumExportFunctions proc
	pushad
	
	.iF pPeFile==0
	
		popad
		mov eax,FALSE
		ret 
	.ENDiF
	
	invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,5000h
	mov hExportList,eax
	invoke GlobalLock,hExportList
	mov pExportList,eax
	
	invoke plGetPeInfo,NULL,ADDR PointersStruc
	lea edi,offset PointersStruc
	assume edi:ptr PL_POINTERS
	
	mov eax,[edi].plPeHeader
	
	assume eax:ptr IMAGE_NT_HEADERS
	mov eax, [eax].OptionalHeader.DataDirectory.VirtualAddress 
	
	.if eax==0  ; No exports
  	 	popad
		mov eax,FALSE
		ret 
	.endif 
	
	invoke plRVAToOffset,eax
	add eax,pPeFile
	
	mov edi,eax
	
	assume edi:ptr IMAGE_EXPORT_DIRECTORY 
	push [edi].NumberOfNames
	pop valFunctionsNum
	
	invoke plRVAToOffset,[edi].AddressOfNames 
	add eax,pPeFile
	mov esi,eax 
	mov edi,pExportList
	
	.while valFunctionsNum>0
	   push esi 
	   invoke plRVAToOffset,dword ptr [esi]
	   add eax,pPeFile
	   push eax 
	   
	   invoke lstrlen,eax
	   mov ecx,eax
	   pop eax
	   mov esi,eax
	   rep movsb
	   mov byte ptr [edi],0Dh
	   mov byte ptr [edi+1],0Ah
	   add edi,2h
	   
	   pop esi
	   dec valFunctionsNum 
	   add esi,4 
	.endw 
	
	popad
	mov eax,pExportList
	ret
plEnumExportFunctions endp



; ===============================================================================================
; [ plEnumSections ]
;
;	Enumerates all sections, seperated by New Line.
; ===============================================================================================

plEnumSections proc
	pushad
	
	.iF pPeFile==0
	
		popad
		mov eax,FALSE
		ret 
	.ENDiF
	
	invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,200h
	mov hSectionsList,eax
	invoke GlobalLock,hSectionsList
	mov pSectionsList,eax
	
	mov esi,pPeFile
	assume esi:ptr IMAGE_DOS_HEADER
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	mov cx,[esi].FileHeader.NumberOfSections
	movzx edx,cx
	add esi,sizeof IMAGE_NT_HEADERS
	
	assume esi:ptr IMAGE_SECTION_HEADER
	
	mov edi,pSectionsList
	
	.while edx>0	; loop
		
		invoke lstrlen,esi
		mov ecx,eax
		rep movsb
		mov byte ptr [edi],0Dh
		mov byte ptr [edi+1],0Ah
		add edi,2h
		sub esi,eax
		
		add esi,sizeof IMAGE_SECTION_HEADER
		dec edx
	.endw
	
	popad
	mov eax,pSectionsList
	ret
plEnumSections endp
 
; ===============================================================================================
; [ plMapOffsetToRVA ]
;
;	plMapOffset
;		The Map offset
;
; ===============================================================================================
 
plMapOffsetToRVA proc plMapOffset:DWORD
	.iF pPeFile==0
	
		mov eax,FALSE
		ret 
	.ENDiF
	
	mov eax,plMapOffset
	sub eax,pPeFile
	
	invoke plOffsetToRVA,eax
	.iF eax==0

                mov eax,FALSE
                ret 
	.ENDiF
	ret
plMapOffsetToRVA endp


; ===============================================================================================
; [ plRVAToMapOffset ]
;
;	plRVA
;		The Rva
;
; ===============================================================================================

plRVAToMapOffset proc plRVA:DWORD
	
	.iF pPeFile==0
	
		mov eax,FALSE
		ret 
	.ENDiF
	
	invoke plRVAToOffset,plRVA
	.iF eax==0

                mov eax,FALSE
                ret 
	.ENDiF
	add eax,pPeFile
	ret
plRVAToMapOffset endp
 
 
 
; ===============================================================================================
; [ plAboutLib ]
;
;	Displays a messagebox with about information
; ===============================================================================================

plAboutLib proc
	pushad
	
	invoke MessageBox,0,addr strAbout,addr strAppName,0
	
	popad
	ret
plAboutLib endp


; ===============================================================================================
; [ plGetExportInfo ]
;
;	plPL_EXPORTS_INFO: 
;		Points to the PL_EXPORTS_INFO structure, which will be filled.
;
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================


	

plGetExportsInfo proc plPL_EXPORTS_INFO:DWORD
	pushad
	
	.iF pPeFile==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plPL_EXPORTS_INFO==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	

comment ~	
PL_EXPORTS_INFO STRUC
	plAddrExportDir		DWORD	?
	plSizeOfExportDir	DWORD	?
	
	plBase			DWORD 	?
	plNumOfFunctions	DWORD 	?
	plNumOfNames		DWORD 	?
	plAddrOfFunctions	DWORD 	?
	plAddrOfNames		DWORD 	?
	plAddrOfOrdinals	DWORD 	?
	
	plPtrExportDir		DWORD	?
	plPtrFunctions		DWORD 	?
	plPtrNames		DWORD	?
	plPtrOrdinals		DWORD	?
PL_EXPORTS_INFO ENDP


IMAGE_EXPORT_DIRECTORY STRUCT
  nBase                     DWORD      ?
  NumberOfFunctions         DWORD      ?
  NumberOfNames             DWORD      ?
  AddressOfFunctions        DWORD      ?
  AddressOfNames            DWORD      ?
  AddressOfNameOrdinals     DWORD      ?
IMAGE_EXPORT_DIRECTORY ENDS

~
	invoke plGetPeInfo,NULL,addr PointersStruc
	lea eax,offset PointersStruc
	assume eax:ptr PL_POINTERS
	
	mov eax,[eax].plDirectoriesStart
	assume eax:ptr IMAGE_DATA_DIRECTORY
	mov edi,[eax].isize
	
	.IF edi==0 ; No exports
		popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	mov esi,plPL_EXPORTS_INFO
	assume esi:ptr PL_EXPORTS_INFO
	mov [esi].plSizeOfExportDir,edi
	
	mov edi,eax
	assume edi:ptr IMAGE_DATA_DIRECTORY
	push [edi].VirtualAddress
	pop [esi].plAddrExportDir
	
	invoke plRVAToMapOffset,[edi].VirtualAddress
	mov [esi].plPtrExportDir,eax
	
	mov edi,eax
	assume edi:ptr IMAGE_EXPORT_DIRECTORY
	
	push [edi].nBase
	pop [esi].plBase
	
	push [edi].NumberOfFunctions
	pop [esi].plNumOfFunctions
	
	push [edi].NumberOfNames
	pop [esi].plNumOfNames
	
	push [edi].AddressOfFunctions
	pop [esi].plAddrOfFunctions
	
	invoke plRVAToMapOffset,[edi].AddressOfFunctions
	mov [esi].plPtrFunctions,eax
	
	push [edi].AddressOfNames
	pop [esi].plAddrOfNames
	
	invoke plRVAToMapOffset,[edi].AddressOfNames
	mov [esi].plPtrNames,eax
	
	push [edi].AddressOfNameOrdinals
	pop [esi].plAddrOfOrdinals
	
	invoke plRVAToMapOffset,[edi].AddressOfNameOrdinals
	mov [esi].plPtrOrdinals,eax
	
	popad
	mov eax,TRUE
	ret
plGetExportsInfo endp


; ===============================================================================================
; [ plUpdateExportInfo ]
;
;	plPL_EXPORTS_INFO: 
;		Points to the PL_EXPORTS_INFO structure, which ne used to update the file.
;
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================

plUpdateExportsInfo proc plPL_EXPORTS_INFO:DWORD
	pushad
	
	.iF pPeFile==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plPL_EXPORTS_INFO==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	
	invoke plGetPeInfo,NULL,addr PointersStruc
	lea eax,offset PointersStruc
	assume eax:ptr PL_POINTERS
	
	mov eax,[eax].plDirectoriesStart
	assume eax:ptr IMAGE_DATA_DIRECTORY
	mov edi,[eax].isize
	
	.IF edi==0 ; No exports
		popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	mov esi,plPL_EXPORTS_INFO
	assume esi:ptr PL_EXPORTS_INFO
	
	
	push [esi].plSizeOfExportDir
	pop [eax].isize
	
	mov edi,eax
	assume edi:ptr IMAGE_DATA_DIRECTORY
	push [esi].plAddrExportDir
	pop [edi].VirtualAddress
	
	
	invoke plRVAToMapOffset,[edi].VirtualAddress
	mov [esi].plPtrExportDir,eax
	
	mov edi,eax
	assume edi:ptr IMAGE_EXPORT_DIRECTORY
	
	push [esi].plBase
	pop [edi].nBase
	
	push [esi].plNumOfFunctions
	pop [edi].NumberOfFunctions
	
	push [esi].plNumOfNames
	pop [edi].NumberOfNames
	
	push [esi].plAddrOfFunctions
	pop [edi].AddressOfFunctions
	
	invoke plRVAToMapOffset,[edi].AddressOfFunctions
	mov [esi].plAddrOfFunctions,eax
	
	push [esi].plAddrOfNames
	pop [edi].AddressOfNames
	
	invoke plRVAToMapOffset,[edi].AddressOfNames
	mov [esi].plAddrOfNames,eax
	
	push [esi].plAddrOfOrdinals
	pop [edi].AddressOfNameOrdinals
	
	invoke plRVAToMapOffset,[edi].AddressOfNameOrdinals
	mov [esi].plAddrOfOrdinals,eax
	
	popad
	mov eax,TRUE
	ret
plUpdateExportsInfo endp


; ===============================================================================================
; [ plLocateMapOffset ]
;
;	plMapOffset: 
;		Contains the Map Offset.
;
; Returns Section Number if all is ok.Else returns FALSE
; ===============================================================================================


plLocateMapOffset PROC plMapOffset:DWORD
	
	push ebx
	push ecx
	push edx
	push edi
	push esi
	
	.iF pPeFile==0
	
		popad
		mov eax,FALSE
		ret 
	.ENDiF
	
	mov esi,pPeFile
	assume esi:ptr IMAGE_DOS_HEADER
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	mov edi,plMapOffset
	sub edi,pPeFile
	mov edx,esi
	add edx,sizeof IMAGE_NT_HEADERS
	mov cx,[esi].FileHeader.NumberOfSections
	movzx ecx,cx
	assume edx:ptr IMAGE_SECTION_HEADER
	xor esi,esi
	mov esi,00000001h
	.while ecx>0	; check all sections
		.if edi>=[edx].PointerToRawData
			mov eax,[edx].PointerToRawData
			add eax,[edx].SizeOfRawData
			.if edi<eax	; The address is in this section
				mov eax,esi
				
				pop esi
				pop edi
				pop edx
				pop ecx
				pop ebx
				ret
			.endif
		.endif
		add edx,sizeof IMAGE_SECTION_HEADER
		dec ecx
		inc esi
	.endw
	assume edx:nothing
	assume esi:nothing
	pop esi
	pop edi
	pop edx
	pop ecx
	pop ebx
	
	mov eax,FALSE
	
	ret
plLocateMapOffset endp


; ===============================================================================================
; [ plLocateOffset ]
;
;	plOffset: 
;		Contains the Offset.
;
; Returns Section Number if all is ok.Else returns FALSE
; ===============================================================================================


plLocateOffset PROC plOffset:DWORD
	
	push ebx
	push ecx
	push edx
	push edi
	push esi
	
	.iF pPeFile==0
	
		popad
		mov eax,FALSE
		ret 
	.ENDiF
	
	mov esi,pPeFile
	assume esi:ptr IMAGE_DOS_HEADER
	add esi,[esi].e_lfanew
	assume esi:ptr IMAGE_NT_HEADERS
	mov edi,plOffset
	;sub edi,pPeFile
	mov edx,esi
	add edx,sizeof IMAGE_NT_HEADERS
	mov cx,[esi].FileHeader.NumberOfSections
	movzx ecx,cx
	assume edx:ptr IMAGE_SECTION_HEADER
	xor esi,esi
	mov esi,00000001h
	.while ecx>0	; check all sections
		.if edi>=[edx].PointerToRawData
			mov eax,[edx].PointerToRawData
			add eax,[edx].SizeOfRawData
			.if edi<eax	; The address is in this section
				mov eax,esi
				
				pop esi
				pop edi
				pop edx
				pop ecx
				pop ebx
				ret
			.endif
		.endif
		add edx,sizeof IMAGE_SECTION_HEADER
		dec ecx
		inc esi
	.endw
	assume edx:nothing
	assume esi:nothing
	pop esi
	pop edi
	pop edx
	pop ecx
	pop ebx
	
	mov eax,FALSE
	
	ret
plLocateOffset endp


; ===============================================================================================
; [ plGetImportsInfo ]
;
;	plPL_IMPORTS_INFO: 
;		Points to the plPL_IMPORTS_INFO structure, which will be filled.
;
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================

plGetImportsInfo proc plPL_IMPORTS_INFO:DWORD
	pushad
	
	.iF pPeFile==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plPL_IMPORTS_INFO==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	mov eax,pPeFile
	add eax,3Ch
	mov eax,dword ptr [eax]
	mov ecx,pPeFile
	add ecx,eax
	mov esi,ecx
	mov eax,ecx
	
	comment ~

PL_IMPORTS_INFO  struct
	plImportDirSize		DWORD 	?
	plImportDirRVA		DWORD 	?
	
	plIATDirSize		DWORD 	?
	plIATDirRVA		DWORD 	?
	
	plPtrImportDir		DWORD	?
	plPtrIATDir		DWORD	?
PL_IMPORTS_INFO ends
~
	mov edi,plPL_IMPORTS_INFO
	assume edi:ptr PL_IMPORTS_INFO
	mov eax,ecx
	add eax,80h
	mov eax,dword ptr [eax]
	mov [edi].plImportDirRVA,eax
	
	invoke plRVAToOffset,eax
	mov ebx,pPeFile
	add ebx,eax
	mov [edi].plPtrImportDir,ebx
	
	mov eax,ecx
	add eax,84h
	mov eax,dword ptr [eax]
	mov [edi].plImportDirSize,eax
	
	mov eax,ecx
	add eax,0D8h
	mov eax,dword ptr [eax]
	mov [edi].plIATDirRVA,eax
	
	invoke plRVAToOffset,eax
	mov ebx,pPeFile
	add ebx,eax
	mov [edi].plPtrIATDir,ebx
	
	mov eax,ecx
	add eax,0DCh
	mov eax,dword ptr [eax]
	mov [edi].plIATDirSize,eax
	
	popad
	mov eax,TRUE
	ret
	
plGetImportsInfo endp

; ===============================================================================================
; [ plUpdateImportsInfo ]
;
;	plPL_IMPORTS_INFO: 
;		Points to the plPL_IMPORTS_INFO structure, which will be used to update the file.
;
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================

plUpdateImportsInfo proc plPL_IMPORTS_INFO:DWORD
	pushad
	
	.iF pPeFile==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	.iF plPL_IMPORTS_INFO==0
                popad
                mov eax,FALSE
                ret 
	.ENDiF
	
	mov eax,pPeFile
	add eax,3Ch
	mov eax,dword ptr [eax]
	mov ecx,pPeFile
	add ecx,eax	
	mov esi,ecx
	mov eax,ecx
		
	
comment ~

PL_IMPORTS_INFO  struct
	plImportDirSize		DWORD 	?
	plImportDirRVA		DWORD 	?
	
	plIATDirSize		DWORD 	?
	plIATDirRVA		DWORD 	?
	
	plPtrImportDir		DWORD	?
	plPtrIATDir		DWORD	?
PL_IMPORTS_INFO ends
~
	mov edi,plPL_IMPORTS_INFO
	assume edi:ptr PL_IMPORTS_INFO
	mov eax,ecx
	add eax,80h
	push [edi].plImportDirRVA
	pop dword ptr [eax]
	
	mov eax,[edi].plIATDirRVA
	invoke plRVAToOffset,eax
	mov ebx,pPeFile
	add ebx,eax
	mov [edi].plPtrImportDir,ebx
	
	mov eax,ecx
	add eax,84h
	push [edi].plImportDirSize
	pop dword ptr [eax]
	
	mov eax,ecx
	add eax,0D8h
	push [edi].plIATDirRVA
	pop dword ptr [eax]
	
	mov eax,[edi].plIATDirRVA
	invoke plRVAToOffset,eax
	mov ebx,pPeFile
	add ebx,eax
	mov [edi].plPtrIATDir,ebx
	
	mov eax,ecx
	add eax,0DCh
	push [edi].plIATDirSize
	pop dword ptr [eax]
		
	popad
	mov eax,TRUE
	ret
plUpdateImportsInfo endp


; ===============================================================================================
; [ plCreateImportTable ]
;
;	Will prepare the file and the Pe-Library for the new import table
;
;
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================


plCreateImportTable proc
	pushad
	
	invoke plGetPeInfo,addr peinfostr,NULL
	lea edi,offset peinfostr
	assume edi:ptr PL_PEINFO
	mov eax,dword ptr [ptrImportFunction]
	push [edi].plImageBase
	pop dword ptr [valImageBase]
	
	invoke plAddSection,addr strPumqara, 26000*5, 26000*5, PL_NORMAL_SECTION
	
	mov esi,eax
	mov dword ptr [ptrApis],esi
	add esi,19000*5
	mov dword ptr [ptrThunks],esi
	invoke plMapOffsetToRVA,esi
	add eax,8h
	mov dword ptr [ptrIAT],eax
	add esi,4000*5
	mov dword ptr [ptrDllNames],esi
	add esi,2000*5
	mov dword ptr [ptrDescriptors],esi
	invoke plMapOffsetToRVA,esi
	mov dword ptr [ptrImportDir],eax
	popad
	mov eax,TRUE
	ret
plCreateImportTable endp 

; ===============================================================================================
; [ plAddOrdinal ]
;
; Will add an ordinal function to the current Descriptor
;
;	plOrdinal:
;		The ordinal value
;
; Returns RVA to the thunk of the ordinal function in EAX
; ===============================================================================================

plAddOrdinal PROC plOrdinal:DWORD
	pushad
		
	
	mov eax,plOrdinal
	or eax,IMAGE_ORDINAL_FLAG32
	mov esi,dword ptr [ptrThunks]
	mov dword ptr [valReturnValue],esi
	mov dword ptr [esi],eax
	add dword ptr [ptrThunks],4h	; Update the Thunks Pointer
	
	inc dword ptr [valNumOfApis]
	
	mov esi,dword ptr [ptrThunks] 	; return thunk va in eax
	sub esi,4h
	invoke plMapOffsetToRVA,esi
	add eax,dword ptr [valImageBase]
	mov dword ptr [valReturnValue],eax
	
	popad
	mov eax,dword ptr [valReturnValue]
	ret
plAddOrdinal ENDP

; ===============================================================================================
; [ asAddApi ]
;
; Will add an api function to the current Descriptor
;
;	plApiName:
;		Pointer to the api name string
;
; Returns RVA to the thunk of the api function in EAX
; ===============================================================================================

plAddApi PROC plApiName:DWORD
	pushad
	
	; Copy the api name and set the new pointer to the api name strings
	
 	mov esi,plApiName
	invoke lstrlen,esi
	
	mov edi,dword ptr [ptrApis]
	push edi
	add edi,2h
	push eax
	invoke lstrcpy,edi,esi
	pop eax
	inc eax
	add eax,2h
	add dword ptr [ptrApis],eax
	
	
	; Add thunk
	
	pop edi
	invoke plMapOffsetToRVA,edi 	; Add thunk
	mov esi,dword ptr [ptrThunks]
	mov dword ptr [valReturnValue],esi
	mov dword ptr [esi],eax
	add dword ptr [ptrThunks],4h	; Update the Thunks Pointer
	
	inc dword ptr [valNumOfApis]
	
	mov esi,dword ptr [ptrThunks]	; return thunk rva in eax
	sub esi,4h
	invoke plMapOffsetToRVA,esi
	add eax,dword ptr [valImageBase]
	mov dword ptr [valReturnValue],eax
	
	popad
	mov eax,dword ptr [valReturnValue]
	ret
plAddApi ENDP


; ===============================================================================================
; [ plAddDescriptor ]
;
; Will add a descriptor.
;
;	plDllName:
;		Pointer to the .dll name string
;
; Returns TRUE
; ===============================================================================================

 plAddDescriptor PROC plDllName:DWORD
	pushad
	
	; Copy the dll name and set the new pointer to dll name strings
 	mov esi,plDllName
	invoke lstrlen,esi
	
	mov edi,dword ptr [ptrDllNames]
	push edi
	
	push eax
	invoke lstrcpy,edi,esi
	pop eax
	inc eax
	add dword ptr [ptrDllNames],eax
	
	
	; Update the ptrThunks to be ready for the new apis	
	
	add dword ptr [ptrThunks],8h
	
	
	; Create the Descriptor
	
	pop edi
	invoke plMapOffsetToRVA,edi 	; Convert pointer in mapped file of current dll name to RVA
	
	mov esi,dword ptr [ptrDescriptors]
	assume esi:ptr IMAGE_IMPORT_DESCRIPTOR
	
	mov [esi].Name1,eax
	
	push dword ptr [ptrThunks]
	call plMapOffsetToRVA
	mov [esi].FirstThunk,eax
	
		;IMAGE_IMPORT_DESCRIPTOR STRUCT
		;    union
		;        Characteristics dd      ?
		;        OriginalFirstThunk dd   ?
		;    ends
		;    TimeDateStamp dd    ?
		;    ForwarderChain dd   ?
		;    Name1 dd            ?
		;    FirstThunk dd       ?
		;IMAGE_IMPORT_DESCRIPTOR ENDS
	
	mov esi,sizeof IMAGE_IMPORT_DESCRIPTOR
	add dword ptr [ptrDescriptors],esi
	
	inc dword ptr [valNumOfDescriptors]
	
	popad
	mov eax,TRUE
	ret
plAddDescriptor ENDP

; ===============================================================================================
; [ plUpdateImports ]
;
;	Will update the file with the new imports table
;
;
; Returns TRUE if all is ok.Else returns FALSE
; ===============================================================================================

plUpdateImports proc
	pushad
	
	lea esi,offset ImportStruct
	assume esi:ptr PL_IMPORTS_INFO
	mov ebx,dword ptr [valNumOfApis]
	xor edx,edx
	
	imul ebx,ebx,4h
	
	mov [esi].plIATDirSize,ebx
	push dword ptr [ptrIAT]
	pop [esi].plIATDirRVA
	
	push dword ptr [ptrImportDir]
	pop [esi].plImportDirRVA
	
	mov ebx,dword ptr [valNumOfDescriptors]
	imul ebx,ebx,14h
	mov [esi].plImportDirSize,ebx
	
	invoke plUpdateImportsInfo,addr ImportStruct
	
	popad
	mov eax,TRUE
	ret
plUpdateImports endp



comment ~
-----

plZeroMemory
plChangeEP
plOpenFile
plCloseFile
plUpdatePEInfo	
plRVAToOffset
plGetPeInfo
plSaveToNewFile
plInsertWatermark
plDeleteSection
plFindSection
plGetSectionInfo
plUpdateSectionInfo
plAddSection
plSetFileSize
plEnumImportFunctions
plOffsetToRVA
plAddImportFunction
plEnumSections
plEnumExportFunctions
plMapOffsetToRVA
plRVAToMapOffset
plLocateMapOffset
plLocateOffset
plGetExportsInfo
plUpdateExportsInfo
plGetImportsInfo
plUpdateImportsInfo



plAlignFile		
plFindFreeSpace				
plDiskDumpSection		
plAlignMode		




~