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
#include <string.h>
#include "pe-lib.h"
#include "config.h"

int main(int argc, char *argv[])
{
  pl_file test;
  pl_importsinfo imp;
  
  strcpy((uint8_t*)&test.name,"test.exe");
  plOpenFile(&test, PL_READ_WRITE);
 
  plGetImportsInfo(&test, &imp);
  
  plCloseFile(&test);
  
  system("PAUSE");	
  return 0;
}
