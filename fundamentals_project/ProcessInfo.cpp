#include "ProcessInfo.h"
using namespace std;


bool  architecture_flag = false;
bool architecture;

ProcessInfo::ProcessInfo()
{
	process = NULL;
	handle = NULL;
}
ProcessInfo::~ProcessInfo()
{
}
ProcessInfo::ProcessInfo(HANDLE _handle, DWORD _dword)
{
	this->handle = _handle;
	this->process = _dword;
}
HANDLE ProcessInfo::GetHandle()
{
	return this->handle;
}
DWORD ProcessInfo::GetProcess()
{
	return this->process;
}
void ProcessInfo::SetHandle(HANDLE _handle)
{
	this->handle = _handle;
}
void ProcessInfo::SetProcess(DWORD process)
{
	this->process = process;
}

ProcessInfo FindProcessId(const char* processname)
{
	HANDLE hProcessSnap; // A handle is a refernce value to a resource that hides the real memory from the user.
	PROCESSENTRY32 pe32; //Describes an entry from a list of the processes residing in the system address space when a snapshot was taken (from microsoft docs).

	/*
	Change into processinfo.

	DWORD result = NULL; //Our finding.
	HANDLE process;*/

	ProcessInfo OurInfo;


	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //Takes a snapshot of all processes and assorted information related to them (threads, heaps, modules).
	/*
	Module - dll or exe.
	Each process consists of >= 1 module.
	*/
	if (INVALID_HANDLE_VALUE == hProcessSnap)
		return OurInfo;

	pe32.dwSize = sizeof(PROCESSENTRY32); // We need to define this, otherwise pe32 will fail.

	if (!(TRUE == Process32First(hProcessSnap, &pe32))) //pe32 becomes the first process by reference and returns true if successful.
	{
		CloseHandle(hProcessSnap); // closes the snapshot object
		printf("Failed to open the first Process.");
		return OurInfo;
	}

	//Go over each process until the requested one is found.
	do
	{
		_bstr_t b(pe32.szExeFile); // binary string - name of exe - represted in this form.
		if (0 == strcmp(processname, b))
		{
			printf("Our process %ls\n", pe32.szExeFile); // name
			printf("Our pid is %ld\n", pe32.th32ProcessID); // pid - ld is the correct print format.
			OurInfo.SetProcess(
				pe32.th32ProcessID
			); // pid
			OurInfo.SetHandle(
				OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID)
			);
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return OurInfo;
}

void PrintModuleName(HANDLE Handle)
{
	DWORD buffSize = 1024;
	CHAR buffer[1024];
	if (QueryFullProcessImageNameA(Handle, 0, buffer, &buffSize)) // gets process name by Handle into buffer.
	{
		std::cout << buffer << '\n';
	}
	else
	{
		printf("Error GetModuleBaseNameA : %lu", GetLastError());
	}
	CloseHandle(Handle);
}


void GetAllRXRWXProcesses(DWORD PID)
{
	MEMORY_BASIC_INFORMATION mbi = {}; // gives you the basic memory information the range of the pages in the virtual address space of a process.
	LPVOID offset = 0; // basically the same as void* - just so it can be easier for microsoft.
	HANDLE process = NULL; // the process each time.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // the general snapshot of the memory and processes.
	PROCESSENTRY32 processEntry = {}; // The current Process in the snapshot being examined.
	processEntry.dwSize = sizeof(PROCESSENTRY32); // we need to define this, otherwise it eill throw an error beacuse the size is unknowm.

	Process32First(snapshot, &processEntry); // gets the first process by ref into processEntry
	while (Process32Next(snapshot, &processEntry)) // runs on all the processes.
	{
		process = OpenProcess(MAXIMUM_ALLOWED, false, processEntry.th32ProcessID); // 
		if (processEntry.th32ProcessID == PID)
		{
			//Gets the memory info according to the process and offset.
			while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi)))
			{
				/*
				DWORD_PTR - for casting ptr to long.
				*/

				offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize); //gets the actual offset location.
				if (mbi.Protect == PAGE_EXECUTE_READWRITE // Type of protection - we are looking for RWX
					&& mbi.State == MEM_COMMIT //State of the Pages in the region, in this case - paging that have been allocated physical memory.
					&& mbi.Type == MEM_IMAGE // Mapped to an image section.
					)
				{
					std::wcout << processEntry.szExeFile << "\n";
					std::cout << "\tRWX: 0x" << std::hex << mbi.BaseAddress << "\n";
				}
				if (mbi.Protect == PAGE_EXECUTE_READ // Type of protection - we are looking for RX
					&& mbi.State == MEM_COMMIT //State of the Pages in the region, in this case - paging that have been allocated physical memory.
					&& mbi.Type == MEM_IMAGE // Mapped to an image section.
					)
				{
					std::wcout << processEntry.szExeFile << "\n";
					std::cout << "\tRX: 0x" << std::hex << mbi.BaseAddress << "\n";
				}
			}
			offset = 0;
		}
		CloseHandle(process);
	}
}

string ProtectOptions(DWORD Protect)
{
	string Text;
	switch (Protect)
	{
	case 0x1:
		Text = "PAGE_NOACCESS";
		break;
	case 0x2:
		Text = "PAGE_READONLY (R) ";
		break;
	case 0x4:
		Text = "PAGE_READWRITE (RW)";
		break;
	case 0x8:
		Text = "PAGE_WRITECOPY (WC)";
		break;
	case 0x10:
		Text = "PAGE_EXECUTE (X)";
		break;
	case 0x20:
		Text = "PAGE_EXECUTE_READ (RX)";
		break;
	case 0x40:
		Text = "PAGE_EXECUTE_READWRITE (RWX)";
		break;
	case 0x80:
		Text = "PAGE_EXECUTE_WRITECOPY (WCX)";
		break;

	default:
		Text = "Other Protection Option";
		break;
	}
	return Text;
}

string StateOptions(DWORD Protect)
{
	string Text;

	switch (Protect)
	{
	case 0x1000:
		Text = "MEM_COMMIT";
		break;
	case 0x2000:
		Text = "MEM_RESERVE";
		break;
	case 0x10000:
		Text = "MEM_FREE";
		break;
	default:
		Text = "Other State Option.";
		break;
	}

	return Text;
}

string TypeOptions(DWORD Protect)
{
	string Text;

	switch (Protect)
	{
	case 0x1000000:
		Text = "MEM_IMAGE";
		break;
	case 0x40000:
		Text = "MEM_MAPPED";
		break;
	case 0x20000:
		Text = "MEM_PRIVATE";
		break;
	default:
		Text = "Other State Option.";
		break;
	}
	return Text;
}

void PrintProtectOptions()
{
	printf("PAGE_NOACCESS - 0x01\n");
	printf("PAGE_READONLY - 0x02\n");
	printf("PAGE_READWRITE - 0x04\n");
	printf("PAGE_WRITECOPY - 0x08\n");
	printf("PAGE_EXECUTE - 0x10\n");
	printf("PAGE_EXECUTE_READ - 0x20\n");
	printf("PAGE_EXECUTE_READWRITE - 0x40\n");
	printf("PAGE_EXECUTE_WRITECOPY - 0x80\n");
}

void GetAllSections(DWORD PID)
{
	MEMORY_BASIC_INFORMATION mbi = {}; // gives you the basic memory information the range of the pages in the virtual address space of a process.
	LPVOID offset = 0; // basically the same as void* - just so it can be easier for microsoft.
	HANDLE process = NULL; // the process each time.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // the general snapshot of the memory and processes.
	PROCESSENTRY32 processEntry = {}; // The current Process in the snapshot being examined.
	processEntry.dwSize = sizeof(PROCESSENTRY32); // we need to define this, otherwise it eill throw an error beacuse the size is unknowm.

	Process32First(snapshot, &processEntry); // gets the first process by ref into processEntry
	while (Process32Next(snapshot, &processEntry)) // runs on all the processes.
	{
		process = OpenProcess(MAXIMUM_ALLOWED, false, processEntry.th32ProcessID);
		if (processEntry.th32ProcessID == PID)
		{
			//Gets the memory info according to the process and offset.
			wcout << processEntry.szExeFile << "\n";
			while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi)))
			{
				cout << "0x" << offset << endl;
				cout << "\tProtection: " << ProtectOptions(mbi.Protect) << endl;
				cout << "\tType: " << TypeOptions(mbi.Type) << endl;
				cout << "\tState: " << StateOptions(mbi.State) << endl;

				offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize); //gets the actual offset location.
			}
			offset = 0;
		}
		CloseHandle(process);
	}
}

pair <LPVOID, DWORD> GetRWXByPid(DWORD Pid, LPVOID Address)
{
	MEMORY_BASIC_INFORMATION mbi = {};

	LPVOID offset = 0;
	DWORD Previous_Offset = 0;
	DWORD OUR_SIZE = 0;
	LPVOID OurStartLocation;

	HANDLE process = NULL;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snapshot, &processEntry);
	while (Process32Next(snapshot, &processEntry))
	{
		if (processEntry.th32ProcessID == Pid)
		{
			process = OpenProcess(MAXIMUM_ALLOWED, false, processEntry.th32ProcessID);
			while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi))) // Ex
			{
				offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
				if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
				{
					if (mbi.BaseAddress == Address)
					{
						std::wcout << processEntry.szExeFile << "\n";
						std::cout << "\tRWX: 0x" << std::hex << mbi.BaseAddress << "\n";

						OurStartLocation = mbi.BaseAddress;
						OUR_SIZE = (DWORD)(offset)-(DWORD)(mbi.BaseAddress);
						goto EXIT;
					}
				}
				if (mbi.Protect == PAGE_EXECUTE_READ && mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
				{
					if (mbi.BaseAddress == Address)
					{
						VirtualProtectEx(process, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
						OurStartLocation = mbi.BaseAddress;
						OUR_SIZE = (DWORD)(offset)-(DWORD)(mbi.BaseAddress);
						std::wcout << processEntry.szExeFile << "\n";
						std::cout << "\tRX: 0x" << std::hex << mbi.BaseAddress << "\n";
						//std::cout << &mbi.Protect << "\n";
						goto EXIT;
					}
				}
				//Previous_Offset = (DWORD)offset;
			}
			offset = 0;
			CloseHandle(process);
			break;
		}
	}
EXIT:
	std::pair <LPVOID, DWORD> D(OurStartLocation, OUR_SIZE);
	return D;
}

pair <LPVOID, DWORD> GetSectionByPid(DWORD Pid, LPVOID Address)
{
	MEMORY_BASIC_INFORMATION mbi = {};

	LPVOID offset = 0;
	DWORD Previous_Offset = 0;
	DWORD OUR_SIZE = 0;
	LPVOID OurStartLocation;

	HANDLE process = NULL;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snapshot, &processEntry);
	while (Process32Next(snapshot, &processEntry))
	{
		if (processEntry.th32ProcessID == Pid)
		{
			process = OpenProcess(MAXIMUM_ALLOWED, false, processEntry.th32ProcessID);
			while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi))) // Ex
			{
				offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
				if (mbi.BaseAddress == Address)
				{
					/*std::wcout << processEntry.szExeFile << "\n";
					std::cout << "\tRWX: 0x" << std::hex << mbi.BaseAddress << "\n";
					*/

					OurStartLocation = mbi.BaseAddress;
					OUR_SIZE = (DWORD)(offset)-(DWORD)(mbi.BaseAddress);
					goto EXIT;
				}
			}
			offset = 0;
			CloseHandle(process);
			break;
		}
	}

EXIT:
	pair <LPVOID, DWORD> D(OurStartLocation, OUR_SIZE);
	return D;
}


void ReadMemory(DWORD proc_id, DWORD lpAddress, void* buf, int len)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
	SIZE_T written;
	ReadProcessMemory(hProcess, (LPVOID)lpAddress, buf, len, &written);
	CloseHandle(hProcess);
}

void WriteMemory(DWORD proc_id, DWORD lpAddress, void* buf, int len)
{
	/*LUID Luid;
	if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid) == FALSE)
	{
	 printf("LookupPrivilegeValueW");
	}*/
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
	SIZE_T written;
	WriteProcessMemory(hProcess, (LPVOID)lpAddress, buf, len, &written);
	CloseHandle(hProcess);
}


void ViewSection(ProcessInfo OurInfo, std::pair <LPVOID, DWORD> D)
{
	DWORD lpAddress = (DWORD)D.first;
	DWORD proc_id = OurInfo.GetProcess();
	DWORD dwTA[0x400];
	bool visualization = 0;
	cout << "for opcode enter [0] for assembly enter [1]" << endl;
	cin >> visualization;
	if (!visualization) {
		for (int j = 0; j < D.second / 0x400; j++)
		{
			ReadMemory(proc_id, lpAddress + j * 0x400, &dwTA, 0x400);
			for (int i = 0; i < 0x100; i += 4)
			{
				printf("0x%08x: %08x %08x %08x %08x\n", lpAddress + j * 0x400 + 4 * i, dwTA[i], dwTA[i + 1], dwTA[i + 2], dwTA[i + 3]);
			}

		}
	}
	else {
		for (int j = 0; j < D.second / 0x400; j++)
		{
			ReadMemory(proc_id, lpAddress + j * 0x400, &dwTA, 0x400);
		}
		ZydisDA(dwTA, D.second * 4, lpAddress);
	}
}

void EditSection(ProcessInfo OurInfo, std::pair <LPVOID, DWORD> DataSection, vector <PatchingData> Data_Patching)
{
	DWORD lpAddress = (DWORD)DataSection.first;
	DWORD proc_id = OurInfo.GetProcess();
	DWORD* Total = new DWORD[DataSection.second];

	for (int i = 0; i < size(Data_Patching); ++i)
	{

		for (int j = 0; j < DataSection.second / 0x400; j++)
		{
			DWORD dwTA[0x400];
			ReadMemory(proc_id, lpAddress + j * 0x400, &dwTA, 0x400);
			for (int i = 0; i < 0x100; i++)
			{
				Total[j * 0x100 + i] = dwTA[i];
			}
		}

		//write in the licato
		if (Data_Patching[i].patch.length() == 8 && Data_Patching[i].patch.find(" ") == string::npos)
		{
			Total[(int)((Data_Patching[i].location / 4))] = str_to_hex(Data_Patching[i].patch);
			for (int j = 0; j < DataSection.second / 0x400; j++)
			{
				DWORD dwTA[0x400];
				for (int n = 0; n < 0x100; n++)
				{
					dwTA[n] = Total[n + 0x100 * j];
				}
				WriteMemory(proc_id, lpAddress + j * 0x400, &dwTA, 0x400);
			}
		}
		else
		{
			string* ins = new string();
			ins = ZydisDA(Total, DataSection.second, lpAddress);
			patching(lpAddress, Data_Patching[i].location + lpAddress, *(&Total), ins, Data_Patching[i].patch);
			for (int j = 0; j < DataSection.second / 0x400; j++)
			{
				DWORD dwTA[0x400];
				for (int n = 0; n < 0x100; n++)
				{

					dwTA[n] = Total[n + 0x100 * j];
				}
				WriteMemory(proc_id, lpAddress + j * 0x400, &dwTA, 0x400);
			}
			delete[] ins;
		}
	}
	delete[] Total;
}

void ChangePermissionsOfSections(ProcessInfo OurInfo, std::pair <LPVOID, DWORD> D)
{
	int Options[9] = { 0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80 };

	PrintProtectOptions();
	DWORD Option;
	bool flag = false;

	do
	{
		printf("Choose a new protection value: 0x");
		scanf_s("%x", &Option);

		for (int i = 0; i < 10; i++)
			if (Options[i] == Option)
				flag = true;
	} while (!flag);


	MEMORY_BASIC_INFORMATION mbi = {};
	LPVOID offset = 0, OurStartLocation;
	DWORD Previous_Offset = 0, OUR_SIZE = 0;
	HANDLE process = NULL, snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	Process32First(snapshot, &processEntry);
	while (Process32Next(snapshot, &processEntry))
	{
		if (processEntry.th32ProcessID == OurInfo.GetProcess())
		{
			process = OpenProcess(MAXIMUM_ALLOWED, false, processEntry.th32ProcessID);
			while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi))) // Need Ex for the section
			{
				offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
				if (mbi.BaseAddress == (PVOID)D.first)
				{
					VirtualProtectEx(process, mbi.BaseAddress, mbi.RegionSize, Option, &mbi.Protect);
				}
			}
			offset = 0;
			CloseHandle(process);
			break;
		}
	}

}


string BasicInput()
{
	char input[80];
	string str;
	cout << "Enter the name of the program.\nEnter [-1] to exit.\n";
	scanf_s("%s", input, 80);
	for (int i = 0; i < 80; i++) {
		str = str + input[i];
	}
	return str;
}

//PeHeaders.

bool dirValid(const char* dirName)
{
	return (GetFileAttributesA(dirName) & FILE_ATTRIBUTE_DIRECTORY);
}


//https://stackoverflow.com/questions/12774207/fastest-way-to-check-if-a-file-exist-using-standard-c-c11-c
bool fileValid(const std::string&  fileName) {
	struct stat buffer;
	return (stat(fileName.c_str(), &buffer) == 0);
}


vector <string> AnalyzeString(string str)
{
	vector<string> v;
	stringstream ss(str);
	while (ss.good()) {
		string substr;
		getline(ss, substr, ',');
		v.push_back(substr);
	}
	return v;
}

bool ReadyForPatching(DWORD* DataSection, ProcessInfo _OurInfo, pair<LPVOID, DWORD> DataSectionInfo,
	vector<PatchingData> Data_Patching)
	//G is the section information,
//D is the information on the section, Data is the pacthing data 
{
	bool flag = true;
	for (int i = 0; i < Data_Patching.size(); ++i)
	{
		if (DataSection[(int)((Data_Patching[i].location / 4))] != Data_Patching[i].expected)
		{
			flag = false;
			break;
		}
	}
	if (flag)
	{
		for (int i = 0; i < Data_Patching.size(); ++i)
		{

			DataSection[Data_Patching[i].location] = str_to_hex(Data_Patching[i].patch);

		}
		EditSection(_OurInfo, DataSectionInfo, Data_Patching);

	}
	return flag;
}

DWORD* GetDataSection(ProcessInfo OurInfo, std::pair<LPVOID, DWORD> D)
{
	DWORD lpAddress = (DWORD)D.first;
	DWORD proc_id = OurInfo.GetProcess();
	DWORD* Total = new DWORD[D.second];
	char location[255];
	for (int j = 0; j < D.second / 0x400; j++)
	{
		DWORD dwTA[0x400];
		ReadMemory(proc_id, lpAddress + j * 0x400, &dwTA, 0x400);
		for (int i = 0; i < 0x100; i++)
		{
			Total[j * 0x100 + i] = dwTA[i];
		}
	}
	return Total;
}

void GetScreenshotSection(ProcessInfo OurInfo, std::pair <LPVOID, DWORD> D)
{
	DWORD lpAddress = (DWORD)D.first;
	DWORD proc_id = OurInfo.GetProcess();
	DWORD* Total = new DWORD[D.second];
	char location[255];


	for (int j = 0; j < D.second / 0x400; j++)
	{
		DWORD dwTA[0x400];
		ReadMemory(proc_id, lpAddress + j * 0x400, &dwTA, 0x400);
		for (int i = 0; i < 0x100; i++)
		{
			Total[j * 0x100 + i] = dwTA[i];
		}
	}

	printf("Enter the location where you'd like to save section %p to? Enter a folder.\n", D.first);
	scanf_s("%s", &location, 255); // change to cin?


	if (dirValid(location))
	{
		string file_name;

		cout << ("What would you like to name the file? ");
		cin >> file_name;

		string file_location = (string(location) + '\\' + string(file_name) + ".bin");

		if (!fileValid(file_location.c_str()))
		{
			ofstream wf(file_location, ios::out | ios::binary);
			if (!wf)
			{
				cout << "Cannot open file!" << endl;
			}

			else
			{
				for (int i = 0; i < D.second / 4; i++) // might be a problem - what if doesn't divide by 4.
					wf.write(reinterpret_cast<char*>(&Total[i]), sizeof(Total[i]));
				wf.close();
				/*if (!wf.good()) {
					cout << "Error occurred at writing time!" << endl;
				}*/
			}
		}
	}
	else
	{
		printf("%s", "Path is not valid.");
	}

	delete[] Total;
}



std::string* ZydisDA(DWORD* Total, DWORD memsize, DWORD lpAddress)
{
	int size = 0;//counter of instruction, in the end should be equal to memsize
	std::string* ins = new std::string[memsize];//the return array
	ZyanU8* data = new ZyanU8[ceil(memsize / 0x400) * 0x100 * 4];//store the opcode in int value bytes(and not ad DWORD)
	for (int j = 0; j < memsize / 0x400; j++)
	{
		for (int i = 0; i < 0x100; i++)
		{
			char buffer[9];
			sprintf_s(buffer, "%08x", Total[j * 0x100 + i]);
			int counter = 0;
			for (int n = 0; n < 8; n += 2)
			{
				unsigned int xfirst;//represent the mvb
				unsigned int xsecond;//represent the lvp
				std::stringstream sfirst;
				std::stringstream ssecond;
				sfirst << std::hex << *(buffer + n);
				ssecond << std::hex << *(buffer + n + 1);
				sfirst >> xfirst;//pass sfirst(stringstream) to unsigned(his unsigned "version")
				ssecond >> xsecond;
				data[size] = ZyanU8(xfirst * 16 + xsecond);//making byte from hex to int value
				++counter;
				++size;
			}
		}
	}
	// Initialize decoder context
	ZydisDecoder decoder;
	if (!architecture_flag)
	{
		cout << "which architecture do you wnat? for x86 enter [0], for x64 enter [1]" << endl;
		cin >> architecture;
		architecture_flag = true;
	}
	if (!architecture)
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
	else
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	// Initialize formatter. Only required when you actually plan to do instruction
	// formatting ("disassembling"), like we do here
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	// Loop over the instructions in our buffer.
	// The runtime-address (instruction pointer) is chosen arbitrary here in order to better
	// visualize relative addressing
	ZyanU64 runtime_address = lpAddress;
	ZyanUSize offset = 0;
	const ZyanUSize length = ceil(memsize / 0x400) * 0x100 * 4;
	ZydisDecodedInstruction instruction;
	while (offset != length)
	{
		ZydisDecoderDecodeBuffer(&decoder, data + offset, length - offset, &instruction);
		// Print current instruction pointer.
		printf("%016" PRIX64 "  ", runtime_address);

		// Format & print the binary instruction structure to human readable format
		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), runtime_address);
		puts(buffer);
		for (int i = 0; *(buffer + i); ++i)
			(ins + offset)->operator+=(*(buffer + i));
		offset += instruction.length;
		runtime_address += instruction.length;
	}
	delete[] data;
	return ins;
}

std::string keystoneAs(std::string CODE)//the code basicly token from https://www.keystone-engine.org/ with little addition
									   //(returned value and few rows)
{
	ks_engine* ks;
	ks_err err;
	size_t count;
	unsigned char* encode;
	size_t size;
	std::string opcodeRes = "";
	if (!architecture_flag)
	{
		cout << "which architecture do you wnat? for x86 enter [0], for x64 enter [1]";
		cin >> architecture;
		architecture_flag = true;
	}
	err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
	if (err != KS_ERR_OK) {
		printf("ERROR: failed on ks_open(), quit\n");
		return nullptr;
	}

	if (ks_asm(ks, CODE.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
		printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
			count, ks_errno(ks));
	}
	else {
		size_t i;
		//the code we have benn added
		for (i = 0; i < size; i++) {
			std::stringstream sfirst;
			sfirst << std::hex << int(encode[i]);
			opcodeRes.operator+=(sfirst.str());
			if (sfirst.str() == "0")
				opcodeRes.operator+=(sfirst.str());
		}
		printf("\n");
	}

	// NOTE: free encode after usage to avoid leaking memory
	ks_free(encode);

	// close Keystone instance when done
	ks_close(ks);

	return opcodeRes;
}

void patching(DWORD lpAddress, int location_to_change, DWORD*& Total, std::string* ins, std::string new_instruction)
{
	int real_location_to_change = (location_to_change - lpAddress);//location in one dimension array(Total)
	int counter_ins = 0;
	int counter = 0;//the location in the DWORD
	int buffer_location = real_location_to_change;//location in DWORD
	int buffer_Total = real_location_to_change;//location in Total
	char buffer[9];
	Total[(buffer_Total) / 4] = rearrange(Total[(buffer_Total) / 4]);
	do
	{
		if ((buffer_location * 2 + counter) % 8 == 0)//if we have passed to the next DWORD
		{
			counter = 0;//start new DWORD
			buffer_location = 0;//start new DWORD
			buffer_Total += 4;//go to the next DWORD
		}
		sprintf_s(buffer, "%08x", Total[(buffer_Total) / 4]);//buffer=the wanted DWORD
		//put nop as a prepare for patching
		buffer[(buffer_location % 4) * 2 + counter] = '9';
		buffer[(buffer_location % 4) * 2 + counter + 1] = '0';
		std::istringstream ss(&buffer[0]);
		ss >> std::hex >> Total[(buffer_Total) / 4];
		counter += 2;//go ahead in byte jump
		++counter_ins;
	} while (ins[real_location_to_change + counter_ins] == "");//while we arn't in the next instruction 


	ins[real_location_to_change] = new_instruction;//we want the change also in the ins array
	std::string temp = keystoneAs(ins[real_location_to_change]);//return the opcode of new_instruction
	buffer_location = real_location_to_change;
	buffer_Total = real_location_to_change;
	counter = 0;
	if (temp.length() / 2 <= counter_ins)//just if the patch is leagel
	{
		for (int i = 0; i < temp.length(); i += 2)
		{
			if ((buffer_location * 2 + counter) % 8 == 0)//if we have passed to the next WORD
			{
				counter = 0;//start new DWORD
				buffer_location = 0;//start new DWORD
				buffer_Total += 4;//go to the next DWORD
			}
			sprintf_s(buffer, "%08x", Total[(buffer_Total) / 4]);

			//put in buffer the instruction opcode
			buffer[(buffer_location % 4) * 2 + counter] = temp[i];
			buffer[(buffer_location % 4) * 2 + counter + 1] = temp[i + 1];
			std::istringstream ss(&buffer[0]);
			ss >> std::hex >> Total[buffer_Total / 4];
			counter += 2;//go ahead in byte jump
		}

		Total[(buffer_Total) / 4] = rearrange(Total[(buffer_Total) / 4]);
	}
	else
		printf_s("ileagal patch");
}

unsigned int str_to_hex(string str)
{
	unsigned int m_dwIP;
	std::istringstream ss(&str[0]);
	ss >> std::hex >> m_dwIP;
	return m_dwIP;
}

LPWSTR ConvertString(const std::string& instr)
{
	// Assumes std::string is encoded in the current Windows ANSI codepage
	int bufferlen = ::MultiByteToWideChar(CP_ACP, 0, instr.c_str(), instr.size(), NULL, 0);

	if (bufferlen == 0)
	{
		// Something went wrong. Perhaps, check GetLastError() and log.
		return 0;
	}

	// Allocate new LPWSTR - must deallocate it later
	LPWSTR widestr = new WCHAR[bufferlen + 1];

	::MultiByteToWideChar(CP_ACP, 0, instr.c_str(), instr.size(), widestr, bufferlen);

	// Ensure wide string is null terminated
	widestr[bufferlen] = 0;

	// Do something with widestr
	return widestr;
	//delete[] widestr;
}


void PEheaders(string path)
{
	const int MAX_FILEPATH = 255;
	char fileName[MAX_FILEPATH] = { 0 };
	memcpy_s(&fileName, MAX_FILEPATH, (void*)(path.c_str()), MAX_FILEPATH);
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS imageNTHeaders = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importSection = {};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
	PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;

	// open file

	file = CreateFileA(LPCSTR(path.c_str()), GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) printf("Could not read file");

	// allocate heap
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

	// read file bytes to memory
	ReadFile(file, fileData, fileSize, &bytesRead, NULL);


	// IMAGE_DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;
	printf("******* DOS HEADER *******\n");
	printf("\t0x%x\t\tMagic number\n", dosHeader->e_magic);
	printf("\t0x%x\t\tBytes on last page of file\n", dosHeader->e_cblp);
	printf("\t0x%x\t\tPages in file\n", dosHeader->e_cp);
	printf("\t0x%x\t\tRelocations\n", dosHeader->e_crlc);
	printf("\t0x%x\t\tSize of header in paragraphs\n", dosHeader->e_cparhdr);
	printf("\t0x%x\t\tMinimum extra paragraphs needed\n", dosHeader->e_minalloc);
	printf("\t0x%x\t\tMaximum extra paragraphs needed\n", dosHeader->e_maxalloc);
	printf("\t0x%x\t\tInitial (relative) SS value\n", dosHeader->e_ss);
	printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t0x%x\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t0x%x\t\tChecksum\n", dosHeader->e_csum);
	printf("\t0x%x\t\tInitial IP value\n", dosHeader->e_ip);
	printf("\t0x%x\t\tInitial (relative) CS value\n", dosHeader->e_cs);
	printf("\t0x%x\t\tFile address of relocation table\n", dosHeader->e_lfarlc);
	printf("\t0x%x\t\tOverlay number\n", dosHeader->e_ovno);
	printf("\t0x%x\t\tOEM identifier (for e_oeminfo)\n", dosHeader->e_oemid);
	printf("\t0x%x\t\tOEM information; e_oemid specific\n", dosHeader->e_oeminfo);
	printf("\t0x%x\t\tFile address of new exe header\n", dosHeader->e_lfanew);

	// IMAGE_NT_HEADERS
	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileData + dosHeader->e_lfanew);
	printf("\n******* NT HEADERS *******\n");
	printf("\t%x\t\tSignature\n", imageNTHeaders->Signature);

	// FILE_HEADER
	printf("\n******* FILE HEADER *******\n");
	printf("\t0x%x\t\tMachine\n", imageNTHeaders->FileHeader.Machine);
	printf("\t0x%x\t\tNumber of Sections\n", imageNTHeaders->FileHeader.NumberOfSections);
	printf("\t0x%x\tTime Stamp\n", imageNTHeaders->FileHeader.TimeDateStamp);
	printf("\t0x%x\t\tPointer to Symbol Table\n", imageNTHeaders->FileHeader.PointerToSymbolTable);
	printf("\t0x%x\t\tNumber of Symbols\n", imageNTHeaders->FileHeader.NumberOfSymbols);
	printf("\t0x%x\t\tSize of Optional Header\n", imageNTHeaders->FileHeader.SizeOfOptionalHeader);
	printf("\t0x%x\t\tCharacteristics\n", imageNTHeaders->FileHeader.Characteristics);

	// OPTIONAL_HEADER
	printf("\n******* OPTIONAL HEADER *******\n");
	printf("\t0x%x\t\tMagic\n", imageNTHeaders->OptionalHeader.Magic);
	printf("\t0x%x\t\tMajor Linker Version\n", imageNTHeaders->OptionalHeader.MajorLinkerVersion);
	printf("\t0x%x\t\tMinor Linker Version\n", imageNTHeaders->OptionalHeader.MinorLinkerVersion);
	printf("\t0x%x\t\tSize Of Code\n", imageNTHeaders->OptionalHeader.SizeOfCode);
	printf("\t0x%x\t\tSize Of Initialized Data\n", imageNTHeaders->OptionalHeader.SizeOfInitializedData);
	printf("\t0x%x\t\tSize Of UnInitialized Data\n", imageNTHeaders->OptionalHeader.SizeOfUninitializedData);
	printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("\t0x%x\t\tBase Of Code\n", imageNTHeaders->OptionalHeader.BaseOfCode);
	//printf("\t0x%x\t\tBase Of Data\n", imageNTHeaders->OptionalHeader.BaseOfData);
	printf("\t0x%x\t\tImage Base\n", imageNTHeaders->OptionalHeader.ImageBase);
	printf("\t0x%x\t\tSection Alignment\n", imageNTHeaders->OptionalHeader.SectionAlignment);
	printf("\t0x%x\t\tFile Alignment\n", imageNTHeaders->OptionalHeader.FileAlignment);
	printf("\t0x%x\t\tMajor Operating System Version\n", imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion);
	printf("\t0x%x\t\tMinor Operating System Version\n", imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t0x%x\t\tMajor Image Version\n", imageNTHeaders->OptionalHeader.MajorImageVersion);
	printf("\t0x%x\t\tMinor Image Version\n", imageNTHeaders->OptionalHeader.MinorImageVersion);
	printf("\t0x%x\t\tMajor Subsystem Version\n", imageNTHeaders->OptionalHeader.MajorSubsystemVersion);
	printf("\t0x%x\t\tMinor Subsystem Version\n", imageNTHeaders->OptionalHeader.MinorSubsystemVersion);
	printf("\t0x%x\t\tWin32 Version Value\n", imageNTHeaders->OptionalHeader.Win32VersionValue);
	printf("\t0x%x\t\tSize Of Image\n", imageNTHeaders->OptionalHeader.SizeOfImage);
	printf("\t0x%x\t\tSize Of Headers\n", imageNTHeaders->OptionalHeader.SizeOfHeaders);
	printf("\t0x%x\t\tCheckSum\n", imageNTHeaders->OptionalHeader.CheckSum);
	printf("\t0x%x\t\tSubsystem\n", imageNTHeaders->OptionalHeader.Subsystem);
	printf("\t0x%x\t\tDllCharacteristics\n", imageNTHeaders->OptionalHeader.DllCharacteristics);
	printf("\t0x%x\t\tSize Of Stack Reserve\n", imageNTHeaders->OptionalHeader.SizeOfStackReserve);
	printf("\t0x%x\t\tSize Of Stack Commit\n", imageNTHeaders->OptionalHeader.SizeOfStackCommit);
	printf("\t0x%x\t\tSize Of Heap Reserve\n", imageNTHeaders->OptionalHeader.SizeOfHeapReserve);
	printf("\t0x%x\t\tSize Of Heap Commit\n", imageNTHeaders->OptionalHeader.SizeOfHeapCommit);
	printf("\t0x%x\t\tLoader Flags\n", imageNTHeaders->OptionalHeader.LoaderFlags);
	printf("\t0x%x\t\tNumber Of Rva And Sizes\n", imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes);

	// DATA_DIRECTORIES
	printf("\n******* DATA DIRECTORIES *******\n");
	printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[0].Size);
	printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[1].Size);

	// SECTION_HEADERS
	printf("\n******* SECTION HEADERS *******\n");
	// get offset to first section headeer
	DWORD sectionLocation = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	// get offset to the import directory RVA
	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// print section data
	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		printf("\t%s\n", sectionHeader->Name);
		printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
		printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
		printf("\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
		printf("\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
		printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
		printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
		printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
		printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
		printf("\t\t0x%x\tCharacteristics\n", sectionHeader->Characteristics);

		// save section that contains import directory table
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}
		sectionLocation += sectionSize;
	}

	// get file offset to import table
	rawOffset = (DWORD)fileData + importSection->PointerToRawData;

	// get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

	printf("\n******* DLL IMPORTS *******\n");
	for (; importDescriptor->Name != 0; importDescriptor++) {
		// imported dll modules
		printf("\t%s\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
		thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
		thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));

		// dll exported functions
		for (; thunkData->u1.AddressOfData != 0; thunkData++) {
			if (thunkData->u1.AddressOfData > 0x80000000) {
				printf("\t\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
			}
			else {
				printf("\t\t%s\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
			}
		}
	}
}
unsigned int rearrange(unsigned int val) {
	return (val & 0xff000000) >> CHAR_BIT * 3 |
		(val & 0x00ff0000) >> CHAR_BIT |
		(val & 0x0000ff00) << CHAR_BIT |
		(val & 0x000000ff) << CHAR_BIT * 3;
}