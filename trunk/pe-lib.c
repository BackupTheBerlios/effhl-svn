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

/* The code of the PeLibrary */

/* TODO uint32_t ... PL_ERROR = -1 ?!!?
 * TODO uint32_t -> uint8_t* / void* za vsi4ko s MapOffset?
 * XXX memalign ? -> moi malloc, koqto da pravi taka 4e faila da se zarejda na 4byte boundary?
 * TODO chracteristics za plAddSection(xxx)
 * XXX Auto update *info* structures sled SetInfo ?
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe.h"
#include "pe-lib.h"
#include "config.h"

/*=======================================================================
 *
 *
 *
 *=======================================================================*/
uint32_t plOpenFile( pl_file* plFile, uint32_t Mode)
{
    FILE* hFile;
    uint32_t filesize;
    char* pfile;
    
    
    
    if(plFile == NULL) { return PL_ERROR; }
    
    plFile->handle = NULL;
    plFile->buffer = NULL;
    plFile->size = 0;
    
    if(Mode == PL_READ_ONLY)
    {
            hFile = fopen(plFile->name,"rb");
            if(hFile == NULL) { return PL_ERROR; }

            fseek(hFile,0,SEEK_END);
            filesize = ftell(hFile);
            rewind(hFile);
            
            pfile = malloc(filesize+1);
            if(pfile == NULL) { return PL_ERROR; }
            fread(pfile,1,filesize,hFile);
            
            plFile->handle = hFile;
            plFile->buffer = pfile;
            plFile->size = filesize;
	    if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }

    }
    else if(Mode == PL_READ_WRITE)
    {
            hFile = fopen(plFile->name,"rb+"); 
            if(hFile == NULL) { return PL_ERROR; }
            
            fseek(hFile,0,SEEK_END);
            filesize = ftell(hFile);
            rewind(hFile);
            
            pfile = malloc(filesize+1);
            if(pfile == NULL) { return PL_ERROR; }

            fread(pfile,1,filesize,hFile);

            plFile->handle = hFile;            
            plFile->buffer = pfile;
            plFile->size = filesize;
	    if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
    }
    
    return PL_SUCCESS;  
}

/*=======================================================================
 *plCheckPe
 *
 * Guarantees that file:
 *  .has at least 1 section
 *  .has big enough header pre-section (bounds checks)
 *  .is opened correctly
 *  .last section isn't out of bounds
 *   
 *=======================================================================*/

uint32_t plCheckPe(pl_file* plFile)
{
         IMAGE_DOS_HEADER* mz;
         IMAGE_NT_HEADERS* pe;
	 IMAGE_SECTION_HEADER* sect;
	 
	 	 
         if(plFile->buffer == NULL || plFile->size == 0) { return PL_ERROR; }
         	
         if(plFile->size < sizeof(IMAGE_DOS_HEADER)) { return PL_ERROR; }
		
         if(plFile->buffer[0] != 'M' || plFile->buffer[1] != 'Z') { return PL_ERROR; }

         mz = (IMAGE_DOS_HEADER*)plFile->buffer;
	 
	 if( ((uint8_t*)mz +  mz->e_lfanew + sizeof(IMAGE_NT_HEADERS)) >= (plFile->size + plFile->buffer) )
         {
                return PL_ERROR;
         } 
  
	 
         pe = (IMAGE_NT_HEADERS*)((uint8_t*)mz +  mz->e_lfanew);
         
         if(pe->Signature != 0x00004550) { return PL_ERROR; }
	 	
         if(pe->OptionalHeader.SizeOfHeaders >= plFile->size) { return PL_ERROR; }

	 if(pe->FileHeader.NumberOfSections < 1) { return PL_ERROR; }
	 
	 sect = (IMAGE_SECTION_HEADER*)((uint8_t*)pe + sizeof(IMAGE_NT_HEADERS));

	 sect =(IMAGE_SECTION_HEADER*)((uint8_t*)sect
	         + pe->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) 
		 - sizeof(IMAGE_SECTION_HEADER));
	 
	 if(sect->PointerToRawData + sect->SizeOfRawData > plFile->size) { return PL_ERROR; }
	 
         return PL_SUCCESS;
}

/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plCloseFile(pl_file* plFile)
{
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
     	free(plFile->buffer);
     	fclose(plFile->handle);
     	plFile->buffer = NULL;
     	plFile->handle = NULL;

	return PL_SUCCESS;
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plChangeEP(pl_file* plFile, uint32_t EntryPoint)
{
    IMAGE_DOS_HEADER* mz;
    IMAGE_NT_HEADERS* pe;
    
    if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
    
    mz = (IMAGE_DOS_HEADER*)plFile->buffer;
    pe = (IMAGE_NT_HEADERS*)((uint8_t*)mz +  mz->e_lfanew);
    pe->OptionalHeader.AddressOfEntryPoint = EntryPoint;
       
    //********* The True Power of C*************
    //((IMAGE_NT_HEADERS*)( pfile->buffer + ((IMAGE_DOS_HEADER*)(pfile->buffer))->e_lfanew))->OptionalHeader.AddressOfEntryPoint = EntryPoint;
    return PL_SUCCESS;
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plGetPeInfo(pl_file* plFile, pl_peinfo* PeInfo, pl_pointers* Pointers)
{
         IMAGE_DOS_HEADER* mz;
         IMAGE_NT_HEADERS* pe;
    
         if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
         
         mz = (IMAGE_DOS_HEADER*)plFile->buffer;
	 pe = (IMAGE_NT_HEADERS*)((uint8_t*)mz +  mz->e_lfanew);
	 
         if(PeInfo != NULL)
         {
		 PeInfo->EntryPoint = pe->OptionalHeader.AddressOfEntryPoint;
		 PeInfo->ImageBase = pe->OptionalHeader.ImageBase;
		 PeInfo->SizeOfImage = pe->OptionalHeader.SizeOfImage;
		 PeInfo->SizeOfHeaders = pe->OptionalHeader.SizeOfHeaders;
		 PeInfo->FileAlignment = pe->OptionalHeader.FileAlignment;
		 PeInfo->SizeOfCode = pe->OptionalHeader.SizeOfCode;
		 PeInfo->CheckSum = pe->OptionalHeader.CheckSum;
		 PeInfo->SectionAlignment = pe->OptionalHeader.SectionAlignment;
		 PeInfo->NumberOfSections = pe->FileHeader.NumberOfSections;
         }
 
 	 if(Pointers != NULL)
	 {
		 Pointers->MZHeader = (uint8_t*)mz;
		 Pointers->PeHeader = (uint8_t*)pe;
	   	 Pointers->SectionsStart = (uint8_t*)( (uint8_t*)&pe->OptionalHeader
				                        + pe->FileHeader.SizeOfOptionalHeader );
 		 
		 Pointers->OptionalHeader = (uint8_t*)&pe->OptionalHeader;
		 Pointers->DirectoriesStart = (uint8_t*)&pe->OptionalHeader.DataDirectory[0]; 
	 }
		 
         return PL_SUCCESS;
}


/*=======================================================================
 *
 *
 * Should call again GetPeInfo after this one, cause of the pointers.
 *=======================================================================*/
uint32_t plSetPeInfo(pl_file* plFile, pl_peinfo* PeInfo)
{
         IMAGE_DOS_HEADER* mz;
         IMAGE_NT_HEADERS* pe;
    
         if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
         
         mz = (IMAGE_DOS_HEADER*)plFile->buffer;
	 pe = (IMAGE_NT_HEADERS*)((uint8_t*)mz +  mz->e_lfanew);
	 
         if(PeInfo != NULL)
         {
		 pe->OptionalHeader.AddressOfEntryPoint = PeInfo->EntryPoint;
		 pe->OptionalHeader.ImageBase = PeInfo->ImageBase;
		 pe->OptionalHeader.SizeOfImage = PeInfo->SizeOfImage;
		 pe->OptionalHeader.SizeOfHeaders = PeInfo->SizeOfHeaders;
		 pe->OptionalHeader.FileAlignment = PeInfo->FileAlignment;
		 pe->OptionalHeader.SizeOfCode = PeInfo->SizeOfCode;
		 pe->OptionalHeader.CheckSum = PeInfo->CheckSum;
		 pe->OptionalHeader.SectionAlignment = PeInfo->SectionAlignment;
		 pe->FileHeader.NumberOfSections = PeInfo->NumberOfSections;
         }
		 
         return PL_SUCCESS;
}



/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plGetSectionInfo(pl_file* plFile, pl_sectioninfo* SectionInfo, uint16_t NumberOfSection)
{
	
	pl_pointers Ptrs;
	uint8_t* section;
	IMAGE_SECTION_HEADER* secthdr;
	

	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	
	plGetPeInfo(plFile,NULL,&Ptrs);
	section = Ptrs.SectionsStart;
	section = section + (NumberOfSection * sizeof(IMAGE_SECTION_HEADER)) - sizeof(IMAGE_SECTION_HEADER);
	
	secthdr = (IMAGE_SECTION_HEADER*)section;

	memcpy(SectionInfo->Name,secthdr->Name,8);

	SectionInfo->VirtualSize = secthdr->Misc.VirtualSize;
	SectionInfo->VirtualAddress = secthdr->VirtualAddress;
	SectionInfo->RawSize = secthdr->SizeOfRawData;
	SectionInfo->RawAddress = secthdr->PointerToRawData;
	SectionInfo->Characteristics = secthdr->Characteristics;
	SectionInfo->PtrSection = plFile->buffer + secthdr->PointerToRawData;
	return PL_SUCCESS;
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plSetSectionInfo(pl_file* plFile, pl_sectioninfo* SectionInfo, uint16_t NumberOfSection)
{
	pl_pointers Ptrs;
	uint8_t* section;
	IMAGE_SECTION_HEADER* secthdr;
	

	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	
	plGetPeInfo(plFile,NULL,&Ptrs);
	section = Ptrs.SectionsStart;
	section = section + (NumberOfSection * sizeof(IMAGE_SECTION_HEADER)) - sizeof(IMAGE_SECTION_HEADER);
	
	secthdr = (IMAGE_SECTION_HEADER*)section;

	memccpy(&secthdr->Name,&SectionInfo->Name,1,8);

	secthdr->Misc.VirtualSize = SectionInfo->VirtualSize;
	secthdr->VirtualAddress = SectionInfo->VirtualAddress;
	secthdr->SizeOfRawData = SectionInfo->RawSize;
	secthdr->PointerToRawData = SectionInfo->RawAddress;
	secthdr->Characteristics = SectionInfo->Characteristics;
	SectionInfo->PtrSection = plFile->buffer + secthdr->PointerToRawData;
	return PL_SUCCESS;
}

/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plRVAToOffset(pl_file* plFile, uint32_t RVA)
{
	pl_sectioninfo SectionInfo;
	pl_peinfo PeInfo;
	pl_pointers Ptrs;
	uint16_t i;
	
       	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	
		// RVA is before the first section?
	plGetSectionInfo(plFile, &SectionInfo, 1);
	if(RVA >=0 && RVA < SectionInfo.VirtualAddress)
	{
		return RVA;
	}
	
		
	plGetPeInfo(plFile, &PeInfo, &Ptrs);
	
	for(i=1; i <= PeInfo.NumberOfSections; i++)
	{
		plGetSectionInfo(plFile, &SectionInfo, i);
		
		if(RVA >= SectionInfo.VirtualAddress && RVA < SectionInfo.VirtualAddress + SectionInfo.VirtualSize)
		{
			return (RVA - SectionInfo.VirtualAddress + SectionInfo.RawAddress);
		}
	}
	
	return PL_NOTFOUND;
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plRVAToMapOffset(pl_file* plFile, uint32_t RVA)
{
	uint32_t offset;
	
	offset = plRVAToOffset(plFile, RVA);
	if(offset == PL_ERROR) 
	{ 
		return PL_ERROR; 
	}
	else if(offset == PL_NOTFOUND)
	{
		return PL_NOTFOUND;
	}
	else
	{
		offset = (uint32_t)(plFile->buffer + offset);
		return offset;
	}
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plVAToMapOffset(pl_file* plFile, uint32_t VA)
{
	uint32_t offset;
	pl_peinfo PeInfo;
	
	if( plGetPeInfo(plFile, &PeInfo, NULL) == PL_ERROR ) { return PL_ERROR; }

	offset = plRVAToOffset(plFile, VA - PeInfo.ImageBase);
	if( offset == PL_ERROR ) 
	{
	       	return PL_ERROR; 
	}
	else if(offset == PL_NOTFOUND)
	{
		return PL_NOTFOUND;
	}
	else
	{
		offset = (uint32_t)(plFile->buffer + offset);
		return offset;
	}
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plVAToOffset(pl_file* plFile, uint32_t VA)
{
	uint32_t offset;
	pl_peinfo PeInfo;
	
	if( plGetPeInfo(plFile, &PeInfo, NULL) == PL_ERROR ) { return PL_ERROR; }

	offset = plRVAToOffset(plFile, VA - PeInfo.ImageBase);
	
	if(offset == PL_ERROR)
       	{ 
		return PL_ERROR; 
	}
	else if(offset == PL_NOTFOUND)
	{
		return PL_NOTFOUND;
	}
	else
	{
		return offset;
	}
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plOffsetToRVA(pl_file* plFile, uint32_t Offset)
{
	pl_sectioninfo SectionInfo;
	pl_peinfo PeInfo;
	pl_pointers Ptrs;
	uint16_t i;
	
       	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	
		// Offset is before the first section?
	plGetSectionInfo(plFile, &SectionInfo, 1);
	if(Offset >=0 && Offset < SectionInfo.RawAddress)
	{
		return Offset;
	}
	
		
	plGetPeInfo(plFile, &PeInfo, &Ptrs);
	
	for(i=1; i <= PeInfo.NumberOfSections; i++)
	{
		plGetSectionInfo(plFile, &SectionInfo, i);
		
		if(Offset >= SectionInfo.RawAddress && Offset < SectionInfo.RawAddress + SectionInfo.RawSize)
		{
			return (Offset - SectionInfo.RawAddress + SectionInfo.VirtualAddress);
		}
	}
	
	return PL_NOTFOUND;
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/


uint32_t plMapOffsetToRVA(pl_file* plFile, uint32_t MapOffset)
{
	uint32_t rva;
	
	rva = plOffsetToRVA(plFile, MapOffset - (uint32_t)plFile->buffer);
	if(rva == PL_ERROR)
	{
		return PL_ERROR;
	}
	else if(rva == PL_NOTFOUND)
	{
		return PL_NOTFOUND;
	}
	else
	{
		return rva;
	}
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plMapOffsetToVA(pl_file* plFile, uint32_t MapOffset)
{
	uint32_t va;
	pl_peinfo PeInfo;
	
	va = plOffsetToRVA(plFile, MapOffset - (uint32_t)plFile->buffer);
	if(va == PL_ERROR)
	{
		return PL_ERROR;
	}
	else if(va == PL_NOTFOUND)
	{
		return PL_NOTFOUND;
	}
	else
	{
		plGetPeInfo(plFile, &PeInfo, NULL);
		return (va + PeInfo.ImageBase);
	}
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plOffsetToVA(pl_file* plFile, uint32_t Offset)
{
	uint32_t va;
	pl_peinfo PeInfo;
	
	va = plOffsetToRVA(plFile, Offset);
	if(va == PL_ERROR)
	{
		return PL_ERROR;
	}
	else if(va == PL_NOTFOUND)
	{
		return PL_NOTFOUND;
	}
	else
	{
		plGetPeInfo(plFile, &PeInfo, NULL);
		return (va + PeInfo.ImageBase);
	}
}
	

/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plOffsetToMapOffset(pl_file* plFile, uint32_t Offset)
{
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }

	if(Offset + (uint32_t)plFile->buffer >= plFile->size + (uint32_t)plFile->buffer)
	{
		return PL_ERROR;
	}
	else
	{
		return Offset + (uint32_t)plFile->buffer;
	}
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plMapOffsetToOffset(pl_file* plFile, uint32_t MapOffset)
{
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }

	if((int32_t)(MapOffset - (uint32_t)plFile->buffer) < 0)
	{
		return PL_ERROR;
	}
	else
	{
		return MapOffset - (uint32_t)plFile->buffer;
	}
}


/*=======================================================================
 *
 * Returns the section number, where the RVA is Located
 * 0 Means Headers pre-section
 *
 *=======================================================================*/

uint16_t plLocateRVA(pl_file* plFile, uint32_t RVA)
{
	pl_sectioninfo SectionInfo;
	pl_peinfo PeInfo;
	pl_pointers Ptrs;
	uint16_t i;
	
       	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	
		// RVA is before the first section?
	plGetSectionInfo(plFile, &SectionInfo, 1);
	if(RVA >=0 && RVA < SectionInfo.VirtualAddress)
	{
		return 0;
	}
	
		
	plGetPeInfo(plFile, &PeInfo, &Ptrs);
	
	for(i=1; i <= PeInfo.NumberOfSections; i++)
	{
		plGetSectionInfo(plFile, &SectionInfo, i);
		
		if(RVA >= SectionInfo.VirtualAddress && RVA < SectionInfo.VirtualAddress + SectionInfo.VirtualSize)
		{
			return i;
		}
	}
	
	return PL_NOTFOUND;
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/
uint32_t plSetFileSize(pl_file* plFile, uint32_t NewSize)
{
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }

		plFile->size = NewSize;
		plFile->buffer = realloc(plFile->buffer, NewSize+1);
		return PL_SUCCESS;
}

/*=======================================================================
 *
 *
 *
 *=======================================================================*/
uint32_t plSaveFile(pl_file* plFile)
{
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	
	plFile->handle = freopen(plFile->name, "wb+", plFile->handle);

	// if(plFile-handle == NULL) { return PL_ERROR; }
	
	if(fwrite(plFile->buffer, 1, plFile->size, plFile->handle) < plFile->size)
	{
		return PL_ERROR;
	}
	else
	{
		plFile->handle = freopen(plFile->name, "rb+", plFile->handle);
		return PL_SUCCESS;
	}
}


/*=======================================================================
 *
 * TODO: Add Characteristics param???
 * XXX: uint8_t* Name ---- uint8_t Name[8];
 * XXX: Side effect is that it cuts the data at the end of the file, which
 *      isn't part of the last section - but this is more like compacting
 *      the pe.
 *=======================================================================*/
uint32_t plAddSection(pl_file* plFile, uint8_t* Name, uint32_t RawSize, uint32_t VirtualSize)
{
	pl_peinfo PeInfo;
	pl_pointers Ptrs;
	pl_sectioninfo prevSectionInfo;
	uint32_t gap;
	IMAGE_SECTION_HEADER* nsect;
	uint32_t nsize;
	uint32_t i;
	
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }

	plGetPeInfo(plFile, &PeInfo, &Ptrs);
	plGetSectionInfo(plFile, &prevSectionInfo, 1);
	
	// Check if there is space between the last section header and the start of the 1st section
	gap = prevSectionInfo.PtrSection - Ptrs.SectionsStart 
		                     + PeInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	
	if(gap < sizeof(IMAGE_SECTION_HEADER))
	{
		return PL_ERROR; // no space for new section header;
	}
	else
	{
		nsect = (IMAGE_SECTION_HEADER*)(Ptrs.SectionsStart 
		 	 + PeInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
		
		memcpy(nsect->Name, Name, 8);
		
		plGetSectionInfo(plFile, &prevSectionInfo, PeInfo.NumberOfSections);
		
		nsect->VirtualAddress = prevSectionInfo.VirtualAddress + prevSectionInfo.VirtualSize;
			// align virt.
		if(nsect->VirtualAddress % PeInfo.SectionAlignment != 0)
		{
			nsect->VirtualAddress +=  PeInfo.SectionAlignment - 
					           (nsect->VirtualAddress % PeInfo.SectionAlignment);
		}
		
		nsect->PointerToRawData = prevSectionInfo.RawAddress + prevSectionInfo.RawSize;
			// align raw
		if(nsect->PointerToRawData % PeInfo.FileAlignment != 0)
		{
			nsect->PointerToRawData += PeInfo.FileAlignment - 
				                    (nsect->PointerToRawData % PeInfo.FileAlignment);			
		}
		
		nsect->SizeOfRawData = RawSize;
		nsect->Misc.VirtualSize = VirtualSize;
		nsect->PointerToRelocations = 0;
		nsect->PointerToLinenumbers = 0;
		nsect->NumberOfRelocations = 0;
		nsect->NumberOfLinenumbers = 0;
		nsect->Characteristics = 0xE0000040;
		
		PeInfo.NumberOfSections++;
		
		PeInfo.SizeOfImage = nsect->Misc.VirtualSize + nsect->VirtualAddress;
		plSetPeInfo(plFile, &PeInfo);

		nsize = nsect->PointerToRawData + nsect->SizeOfRawData;
		
		if(plSetFileSize(plFile, nsize) == PL_ERROR) { return PL_ERROR; }

		// zero the data in the new section

		plGetSectionInfo(plFile, &prevSectionInfo, PeInfo.NumberOfSections);	
		
		for(i=0; i <= prevSectionInfo.RawSize; i++)
		{
			prevSectionInfo.PtrSection[i] = 0;
		}
		
		return PL_SUCCESS;
	}	
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plDeleteLastSection(pl_file* plFile)
{
	pl_peinfo PeInfo;
	pl_pointers Ptrs;
	pl_sectioninfo sect;
	IMAGE_SECTION_HEADER* dsect;
	uint32_t i;
	uint8_t* dsectch;
	
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }

	plGetPeInfo(plFile, &PeInfo, &Ptrs);
	plGetSectionInfo(plFile, &sect, PeInfo.NumberOfSections);
	
	dsect = (IMAGE_SECTION_HEADER*)(Ptrs.SectionsStart + PeInfo.NumberOfSections
		       	* sizeof(IMAGE_SECTION_HEADER) - sizeof(IMAGE_SECTION_HEADER));
	dsectch = Ptrs.SectionsStart + PeInfo.NumberOfSections
		       	* sizeof(IMAGE_SECTION_HEADER) - sizeof(IMAGE_SECTION_HEADER);
	
		// zero last section header
	for(i=0; i < sizeof(IMAGE_SECTION_HEADER); i++)
	{
		dsectch[i] = 0;
	}
	
		// fix pe header and filesize
	PeInfo.NumberOfSections--;
	PeInfo.SizeOfImage -= sect.VirtualSize;
	plSetPeInfo(plFile, &PeInfo);
	
	if(plSetFileSize(plFile, sect.RawAddress + sect.RawSize) == PL_ERROR) { return PL_ERROR; }

	return PL_SUCCESS;
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plGetExportsInfo(pl_file* plFile, pl_exportsinfo* ExportsInfo)
{
	pl_peinfo PeInfo;
	pl_pointers Ptrs;
	IMAGE_DATA_DIRECTORY* datadir;
	IMAGE_EXPORT_DIRECTORY* exp;
	
	
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	plGetPeInfo(plFile, NULL, &Ptrs);
	
	datadir = (IMAGE_DATA_DIRECTORY*)(Ptrs.DirectoriesStart);

	ExportsInfo->ExportsDirRVA = datadir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ExportsInfo->ExportsDirSize = datadir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	
	exp = (IMAGE_EXPORT_DIRECTORY*) plRVAToMapOffset(plFile, datadir->VirtualAddress);
	
	if((uint32_t)exp == PL_NOTFOUND) { return PL_ERROR; }

	ExportsInfo->NumberOfFunctions = exp->NumberOfFunctions;
	ExportsInfo->Base = exp->Base;
	ExportsInfo->NumberOfNames = exp->NumberOfNames;
	ExportsInfo->FunctionsRVA = exp->AddressOfFunctions;
	ExportsInfo->NamesRVA = exp->AddressOfNames;
	ExportsInfo->OrdinalsRVA = exp->AddressOfNameOrdinals;

	ExportsInfo->ptrExportsDir = (uint8_t*)(plRVAToMapOffset(plFile,ExportsInfo->ExportsDirRVA));
	ExportsInfo->ptrFunctions = (uint8_t*)(plRVAToMapOffset(plFile,ExportsInfo->FunctionsRVA));
	ExportsInfo->ptrNames = (uint8_t*)(plRVAToMapOffset(plFile,ExportsInfo->NamesRVA));
	ExportsInfo->ptrOrdinals = (uint8_t*)(plRVAToMapOffset(plFile,ExportsInfo->OrdinalsRVA));
	
	return PL_SUCCESS;
}

/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plSetExportsInfo(pl_file* plFile, pl_exportsinfo* ExportsInfo)
{
	pl_pointers Ptrs;
	IMAGE_DATA_DIRECTORY* datadir;
	IMAGE_EXPORT_DIRECTORY* exp;
	
	
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	plGetPeInfo(plFile, NULL, &Ptrs);
	
	datadir = (IMAGE_DATA_DIRECTORY*)(Ptrs.DirectoriesStart);

	datadir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = ExportsInfo->ExportsDirRVA;
	datadir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = ExportsInfo->ExportsDirSize;
	
	exp = (IMAGE_EXPORT_DIRECTORY*) plRVAToMapOffset(plFile, datadir->VirtualAddress);
	
	if((uint32_t)exp == PL_NOTFOUND) { return PL_ERROR; }

	exp->NumberOfFunctions = ExportsInfo->NumberOfFunctions;
	exp->Base = ExportsInfo->Base;
	exp->NumberOfNames = ExportsInfo->NumberOfNames;
	exp->AddressOfFunctions = ExportsInfo->FunctionsRVA;
        exp->AddressOfNames = ExportsInfo->NamesRVA;
	exp->AddressOfNameOrdinals = ExportsInfo->OrdinalsRVA;

	return PL_SUCCESS;
}

/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plGetImportsInfo(pl_file* plFile, pl_importsinfo* ImportsInfo)
{
	pl_pointers Ptrs;
	IMAGE_DATA_DIRECTORY* datadir;
	IMAGE_IMPORT_DESCRIPTOR* impdesc;
	uint32_t i;

	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	plGetPeInfo(plFile, NULL, &Ptrs);

	datadir = (IMAGE_DATA_DIRECTORY*)(Ptrs.DirectoriesStart);
	
	ImportsInfo->ImportsDirRVA = datadir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	ImportsInfo->ImportsDirSize = datadir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	ImportsInfo->ptrImportsDir = (uint8_t*)plRVAToMapOffset(plFile, ImportsInfo->ImportsDirRVA);
	
	
	ImportsInfo->IATDirRVA = datadir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	ImportsInfo->IATDirSize = datadir[IMAGE_DIRECTORY_ENTRY_IAT].Size;
	ImportsInfo->ptrIATDir = (uint8_t*)plRVAToMapOffset(plFile,ImportsInfo->IATDirRVA);
		
	if((uint32_t)ImportsInfo->ptrIATDir == PL_NOTFOUND || 
	   (uint32_t)ImportsInfo->ptrImportsDir == PL_NOTFOUND)
	{
		return PL_ERROR;
	}
	
	impdesc = (IMAGE_IMPORT_DESCRIPTOR*)ImportsInfo->ptrImportsDir;
	
	for(i=0; impdesc[i].u1.OriginalFirstThunk != 0 && impdesc[i].FirstThunk != 0; i++) { }

	ImportsInfo->NumberOfDlls = i;
	
	return PL_SUCCESS;
}



/*=======================================================================
 *
 *
 *
 *=======================================================================*/

uint32_t plSetImportsInfo(pl_file* plFile, pl_importsinfo* ImportsInfo)
{
	pl_pointers Ptrs;
	IMAGE_DATA_DIRECTORY* datadir;
	IMAGE_IMPORT_DESCRIPTOR* impdesc;

	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	plGetPeInfo(plFile, NULL, &Ptrs);

	datadir = (IMAGE_DATA_DIRECTORY*)(Ptrs.DirectoriesStart);
	
	datadir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = ImportsInfo->ImportsDirRVA;
	datadir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = ImportsInfo->ImportsDirSize;
	
	datadir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = ImportsInfo->IATDirRVA;
	datadir[IMAGE_DIRECTORY_ENTRY_IAT].Size = ImportsInfo->IATDirSize;
	
	return PL_SUCCESS;
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/
uint32_t plCreateImportTable(pl_file* plFile, uint32_t MaxApiNameLenght)
{
	pl_pointers Ptrs;
	IMAGE_DATA_DIRECTORY* datadir;
	IMAGE_IMPORT_DESCRIPTOR* impdesc;
	
	if(plCheckPe(plFile) == PL_ERROR) { return PL_ERROR; }
	
	
	return PL_SUCCESS;
}

/*=======================================================================
 *
 *
 *
 *=======================================================================*/


/*=======================================================================
 *
 *
 *
 *=======================================================================*/


/*=======================================================================
 *
 *
 *
 *=======================================================================*/



/*

uint8_t* pl_dwcopy(uint8_t* to, uint8_t* from)
{
        memccpy(to,from,1,4);
        return to;
}

uint8_t* pl_bcopy(uint8_t* to, uint8_t* from)
{
         memccpy(to,from,1,1);
         return to;
}

/// Copies a word (2 bytes) from - to
/// return value - nothing.
uint8_t* pl_wcopy(uint8_t* to, uint8_t* from)
{
         memccpy(to,from,1,2);
         return to;
}

*/
