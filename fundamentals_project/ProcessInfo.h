#include<stdio.h>
#include<Windows.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <iostream>
#include <inttypes.h>
#include <Zydis/Zydis.h>
#include <string>
#include <sstream>
#include <keystone/keystone.h>
#include <vector>
#include <winnt.h>
#include<math.h>
#include<fstream>
using namespace std;

struct PatchingData
{
	int location;
	DWORD expected;
	string patch;
};

class ProcessInfo
{
public:
	ProcessInfo();
	~ProcessInfo();
	ProcessInfo(HANDLE _handle, DWORD _dword);

	HANDLE GetHandle();
	DWORD GetProcess();

	void SetHandle(HANDLE _handle);
	void SetProcess(DWORD process);
private:
	HANDLE handle;
	DWORD process;
};
HANDLE GetHandle();
DWORD GetProcess();
void SetHandle(HANDLE _handle);
void SetProcess(DWORD process);


ProcessInfo FindProcessId(const char* processname);//This function finds the pid according to the processes name.

void PrintModuleName(HANDLE Handle);// This function prints the process name according to the handle -
								   //used when we don't have a direct processentry32 object.

/*void GetAllRXRWXProcesses(DWORD PID);//Prints all the RWX processes.

std::pair <LPVOID, DWORD> GetRWXByPid(DWORD Pid, LPVOID Address);// Basically the same as previous.*/

void ReadMemory(DWORD proc_id, DWORD lpAddress, void* buf, int len);

void WriteMemory(DWORD proc_id, DWORD lpAddress, void* buf, int len);

string BasicInput();

void GetAllSections(DWORD PID);

void ViewSection(ProcessInfo OurInfo, std::pair <LPVOID, DWORD> D);

void GetScreenshotSection(ProcessInfo OurInfo, std::pair <LPVOID, DWORD> D);

void ChangePermissionsOfSections(ProcessInfo OurInfo, std::pair <LPVOID, DWORD> D);

vector <string> AnalyzeString(string str);

bool ReadyForPatching(DWORD* DataSection, ProcessInfo _OurInfo, pair<LPVOID, DWORD> DataSectionInfo,
	vector<PatchingData> Data_Patching);

DWORD* GetDataSection(ProcessInfo OurInfo, std::pair<LPVOID, DWORD> D);

void EditSection(ProcessInfo OurInfo, std::pair <LPVOID, DWORD> DataSection, vector <PatchingData> Data_Patching);

void PEheaders(string path);

pair <LPVOID, DWORD> GetSectionByPid(DWORD Pid, LPVOID Address);

unsigned int str_to_hex(string str);

bool fileValid(const std::string& fileName);

bool FileExists(const string& filename);

LPWSTR ConvertString(const std::string& instr);

std::string* ZydisDA(DWORD* Total, DWORD memsize, DWORD lpAddress);//function's propuse is to print and return the assembly code

std::string keystoneAs(std::string CODE);

unsigned int rearrange(unsigned int val);

void patching(DWORD lpAddress, int place_to_change, DWORD*& Total, std::string* ins, std::string new_instruction);// make patching(for one instruction anytime)