//
// Created by cs on 2019/6/12.
//
#include <Python.h>

int main (void){
    PyInit_tabinit();
    Py_Initialize();
    PyRun_SimpleString("import sys;sys.path.append('.'); print(1)");
    PyRun_SimpleString("import main; main.start()");
    return 0;
}