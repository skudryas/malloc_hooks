#!/bin/sh
gcc malloc_hooks.cpp backtrace_symbols.c -lstdc++ -lbfd -rdynamic -g
