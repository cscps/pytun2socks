//
// Created by cs on 2019/6/12.
//
#include <Python.h>

void PyInit_tabinit();

int main (int argc, char** argv){
    PyInit_tabinit();
    Py_Initialize();
    wchar_t* wchar_argv[argc];
    for (int i=0; i<argc; i++){
        size_t str_len = strlen(argv[i])+1;
        wchar_t* wt = malloc(sizeof(wchar_t) * str_len);
        for (int j=0; j<str_len; j++){
            wt[j] = argv[i][j];
        }
        wchar_argv[i] = wt;
    }
    if (argv) PySys_SetArgv(argc, wchar_argv);
    PyRun_SimpleString("import sys;sys.path.append('.'); print(sys.argv)");
    PyRun_SimpleString("import main; main.start()");
    return 0;
}