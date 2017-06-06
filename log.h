/*
 *	The code is distributed under terms of the BSD license.
 *	Copyright (c) 2016 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/bsd-license
 */

#ifndef _LOG_H_
#define _LOG_H_

int log_str(char *str);
int log_print(int fd);
int log_init(int buffer_size);

#endif

