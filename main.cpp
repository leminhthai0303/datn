#include <iostream>
#include <winevt.h>
#include <windows.h>
#include <winbase.h>
#include <lmcons.h>

using namespace std;

int main (int argc, char *argv[]) {
  wchar_t username[UNLEN+1];
  DWORD username_len = UNLEN+1;
  GetUserName(username, &username_len);
  swprintf_s(username, L"C:\\Users\\%s\\Desktop\\test.evtx", username);

  LPCWSTR pPath = L"System";
  LPCWSTR pQuery = NULL;
  LPCWSTR pTargetLogFile = username; 
  return 0;
}
