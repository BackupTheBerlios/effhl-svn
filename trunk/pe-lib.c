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
#include "pe.h"
#include "pe-lib.h"




/*=======================================================================
 *
 *
 *
 *=======================================================================*/
int pl_open_file( pl_file* plFile, int mode)
{
    FILE* hFile;
    long filesize;
    char* pfile;
    
    if(mode == PL_READ_ONLY)
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

    }
    else if(mode == PL_READ_WRITE)
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
    }
    
    return PL_DONE;  
}


/*=======================================================================
 *
 *
 *
 *=======================================================================*/

void pl_close_file(pl_file* plFile)
{
     free(plFile->buffer);
     fclose(plFile->handle);
     plFile->buffer = NULL;
     plFile->handle = NULL;
}

int pl_change_ep(pl_file* pfile, unsigned int entrypoint)
{
    IMAGE_DOS_HEADER* mz = (IMAGE_DOS_HEADER*)pfile->buffer;
    IMAGE_NT_HEADERS* pe = (IMAGE_NT_HEADERS*)((char*)mz +  mz->e_lfanew);
    pe->OptionalHeader.AddressOfEntryPoint = entrypoint;
       
    //********* The True Power of C*************
    //((IMAGE_NT_HEADERS*)( pfile->buffer + ((IMAGE_DOS_HEADER*)(pfile->buffer))->e_lfanew))->OptionalHeader.AddressOfEntryPoint = entrypoint;
    return PL_DONE;
}

