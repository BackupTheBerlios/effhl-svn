/*
 *  Copyright (C) 2004 - 2005 Ivan Zlatev <pumqara@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define LITTLE_ENDIAN

#define PL_NOTFOUND -2
#define PL_ERROR -1
#define PL_SUCCESS 0
#define PL_READ_ONLY 1
#define PL_READ_WRITE 2

#define MAX_FILENAME_LENGHT 300

typedef struct file_struct
{
       FILE* handle;
       uint8_t name[MAX_FILENAME_LENGHT];
       uint8_t* buffer;
       uint32_t size;
} pl_file;


typedef struct pe_info
{
        uint32_t EntryPoint;    
        uint32_t ImageBase;
        uint32_t SizeOfImage;
	uint32_t SizeOfCode;
        uint32_t SizeOfHeaders;
        uint32_t FileAlignment;
        uint32_t CheckSum;
        uint32_t SectionAlignment;
        uint16_t NumberOfSections;
} pl_peinfo;


typedef struct pointers
{
        uint8_t* MZHeader;
        uint8_t* PeHeader;
        uint8_t* SectionsStart;
        uint8_t* OptionalHeader;
        uint8_t* DirectoriesStart;
} pl_pointers;


typedef struct sect_info
{
	uint8_t Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t RawSize;
	uint32_t RawAddress;
	uint32_t Characteristics;
	uint8_t* PtrSection;
} pl_sectioninfo;

typedef struct exports_info
{
	uint32_t ExportsDirRVA;
	uint32_t ExportsDirSize;
	uint32_t Base;
	uint32_t NumberOfFunctions;
	uint32_t NumberOfNames;
	uint32_t FunctionsRVA;
	uint32_t NamesRVA;
	uint32_t OrdinalsRVA;
	
	uint8_t* ptrExportsDir;
	uint8_t* ptrFunctions;
	uint8_t* ptrNames;
	uint8_t* ptrOrdinals;	
} pl_exportsinfo;

typedef struct imports_info
{
	uint32_t ImportsDirRVA;
	uint32_t ImportsDirSize;
	uint8_t* ptrImportsDir;
	
	uint32_t NumberOfDlls;
	
	uint32_t IATDirRVA;
	uint32_t IATDirSize;
	uint8_t* ptrIATDir;
} pl_importsinfo;
	

uint32_t plOpenFile( pl_file* plFile, uint32_t Mode);
uint32_t plCloseFile(pl_file* plFile);
uint32_t plChangeEP(pl_file* plFile, uint32_t EntryPoint);
uint32_t plGetPeInfo(pl_file* plFile, pl_peinfo* PeInfo, pl_pointers* Pointers);
uint32_t plCheckPe(pl_file* plFile);
uint32_t plSetPeInfo(pl_file* plFile, pl_peinfo* PeInfo);
uint32_t plGetSectionInfo(pl_file* plFile, pl_sectioninfo* SectionInfo, uint16_t NumberOfSection);
uint32_t plSetSectionInfo(pl_file* plFile, pl_sectioninfo* SectionInfo, uint16_t NumberOfSection);
uint32_t plRVAToOffset(pl_file* plFile, uint32_t RVA);
uint32_t plRVAToMapOffset(pl_file* plFile, uint32_t RVA);
uint32_t plVAToMapOffset(pl_file* plFile, uint32_t VA);
uint32_t plVAToOffset(pl_file* plFile, uint32_t VA);
uint32_t plOffsetToRVA(pl_file* plFile, uint32_t Offset);
uint32_t plMapOffsetToRVA(pl_file* plFile, uint32_t MapOffset);
uint32_t plMapOffsetToVA(pl_file* plFile, uint32_t MapOffset);
uint32_t plOffsetToVA(pl_file* plFile, uint32_t Offset);
uint32_t plOffsetToMapOffset(pl_file* plFile, uint32_t Offset);
uint32_t plMapOffsetToOffset(pl_file* plFile, uint32_t MapOffset);
uint32_t plSetFileSize(pl_file* plFile, uint32_t NewSize);
uint32_t plSaveFile(pl_file* plFile);
uint32_t plAddSection(pl_file* plFile, uint8_t* Name, uint32_t RawSize, uint32_t VirtualSize);
uint32_t plDeleteLastSection(pl_file* plFile);
uint32_t plGetExportsInfo(pl_file* plFile, pl_exportsinfo* ExportsInfo);
uint32_t plSetExportsInfo(pl_file* plFile, pl_exportsinfo* ExportsInfo);
uint32_t plGetImportsInfo(pl_file* plFile, pl_importsinfo* ImportsInfo);
uint32_t plSetImportsInfo(pl_file* plFile, pl_importsinfo* ImportsInfo);

