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

#define PL_ERROR -1
#define PL_DONE 0
#define PL_READ_ONLY 1
#define PL_READ_WRITE 2

typedef struct file_struct
{
       FILE* handle;
       char name[300];
       char* buffer;
       unsigned int size;
} pl_file;

int pl_open_file( pl_file* plfile, int mode);
void pl_close_file(pl_file* plFile);
int pl_change_ep(pl_file* pfile, unsigned int entrypoint);
