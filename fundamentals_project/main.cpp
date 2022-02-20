#include<stdio.h>
#include<Windows.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <iostream>
#include <stdlib.h>
#include<fstream>
#include "ProcessInfo.h"
using namespace std;
void usleep(__int64 usec)
{
	HANDLE timer;
	LARGE_INTEGER ft;
	ft.QuadPart = -(10 * usec); // Convert to 100 nanosecond interval, negative value indicates relative time
	timer = CreateWaitableTimer(NULL, TRUE, NULL);
	SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
	WaitForSingleObject(timer, INFINITE);
	CloseHandle(timer);
}


int main()
{
	vector<PatchingData> patchingData;
	string input;
	PatchingData temp;
	int temp_location;
	DWORD temp_expected;
	char temp_patchWORD[20];
	istream tempStream();

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	unsigned int second = 1000000;
	string path;
	string processName;
	bool creatLoader;
	LPVOID x;
	pair<LPVOID, DWORD> D;
	LPCWSTR _Path;
	ProcessInfo OurInfo;
	int Option = -2;
	LPVOID BaseAddress = 0;


	cout << "woul'd you like to create a loader, enter [1] if you want, else enter [0]" << endl;
	cin >> creatLoader;
	if (!creatLoader)
	{
		goto START;
	}


	cout << "please enter path" << endl;
	cin >> path;
	while (!fileValid(path.c_str()))
	{
		cout << "please enter path" << endl;
		cin >> path;
	}

	_Path = (LPCWSTR)ConvertString(path);
	CreateProcess(_Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);


	do
	{
		cout << "please enter process name" << endl;
		cin >> processName;

		OurInfo = FindProcessId(processName.c_str()); // get general

	} while (!OurInfo.GetHandle());


	GetAllSections(OurInfo.GetProcess());
	printf("Choose a section: 0x");
	cin >> hex >> BaseAddress; // maybe problem.
	while (BaseAddress < 0)
	{
		cin >> hex >> BaseAddress;
	}

	D = GetSectionByPid(OurInfo.GetProcess(), BaseAddress);

	if (D.second) {
		cout << "Enter the bytes to alter on startup - offset, current byte, requested byte:, for stop entering enter -1 " << endl;
		do {
			cin >> hex >> x;
			temp_location = (int)x;
			if (temp_location != -1)
			{

				cin >> temp_expected;
				cin.ignore();
				cin.getline(temp_patchWORD, 20);
				temp.location = temp_location;
				temp.expected = temp_expected;
				temp.patch = temp_patchWORD;
				patchingData.push_back(temp);
				cout << "-----------------" << endl;
			}

		} while (temp_location != -1);
		while (true)
		{
			auto G = GetDataSection(OurInfo, D);
			if (ReadyForPatching(G, OurInfo, D, patchingData))
			{
				break;
			}
			ResumeThread(pi.hThread);
			usleep(0.002 * second);
			SuspendThread(pi.hThread);
		}
	}

	ResumeThread(pi.hThread);


START:
	if (!creatLoader)
		input.operator=(BasicInput());
	//while (input.compare("-1"))//return 0 if they are equal 
	//{

	if (!creatLoader)
	{
		OurInfo = FindProcessId(input.c_str()); // get general
	}

	if (OurInfo.GetHandle() && OurInfo.GetProcess())
	{
		//GetAllSections(OurInfo.GetProcess());
		if (!creatLoader)
		{
			printf("Choose a section: 0x");
			cin >> hex >> BaseAddress; // maybe problem.
			pair <LPVOID, DWORD> D = GetSectionByPid(OurInfo.GetProcess(), BaseAddress);
		}

		//note - need a better breakup here some are general to program and some are specific to section.

		if (D.second)
		{
			do {
				printf("What would you like to do with the section 0x%x?\n", BaseAddress);
				printf("[0] Exit.\n");
				printf("[1] View section.\n"); // Works!
				printf("[2] Edit Section.\n"); //Works! Need to add capstone and zydis
				printf("[3] Change Permissions of area.\n"); // Works!
				printf("[4] Take a screenshot of the process.\n"); // Works!
				printf("[5] View the PE headers.\n"); // Doesn't work. - assume it works for israel.

				scanf_s("%d", &Option);

				switch (Option)
				{
				case 0:
					input = "0";
					break;
				case 1:
					ViewSection(OurInfo, D);
					break;
				case 2:
					patchingData.clear();
					cout << ("Enter the bytes to alter - offset, current byte, requested byte:, for stop entering enter -1 ");
					do {
						cin >> hex >> x;
						temp_location = (int)x;
						if (temp_location != -1)
						{
							cin >> temp_expected;
							cin.ignore();
							cin.getline(temp_patchWORD, 20);
							temp.location = temp_location;
							temp.expected = temp_expected;
							temp.patch = temp_patchWORD;
							patchingData.push_back(temp);
						}

					} while (temp_location != -1);

					EditSection(OurInfo, D, patchingData);
					break;
				case 3:
					ChangePermissionsOfSections(OurInfo, D);
					break;
				case 4:
					GetScreenshotSection(OurInfo, D);
					break;
				case 5:
					if (!path.empty())
					{
						TerminateProcess(OurInfo.GetHandle(), 0);
						Sleep(100);
						PEheaders(path);
						goto EXIT;
					}
					break;
				default:
					printf("Please Enter a valid option.\n");
					break;
				}
			} while (Option);
		}
	}

	//input.operator=(BasicInput());
//}
EXIT:
	TerminateProcess(OurInfo.GetHandle(), 0);
	return 0;
}