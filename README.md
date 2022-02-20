# AES-I-Hot-Patcher
Runtime memory patcher

Each program that runs on a computer has processes. The goal of our project is to be able to tamper with those processes by will. This can be used for a variety of purposes starting with viewing memory for pure scientific interest, to inspecting a program for possible malware to bypassing security checks in applications and so on. Our development is to be used only for good and positive purposes and we hope you will enjoy using it just as much as we did to create it.
Introduction:
If you look up how many processes are running on your computer at any given moment, you will probably see that there are more than 200. Each of these processes has memory section in which reside its data and information as well as memory sections used and imported by various dlls.
It is important that people will be able to know what resides in each memory section and to have an easy and accessible way to edit it and view it and change their permissions if needed. 
We plan to create a product that can find all sections in the memory of a program that is in runtime, choose which one to alter, view the disassembly of such an area, and have an ability to change during runtime the functionality of the program.  
We plan to be able to locate each such area in the memory using fairly low-level libraries such as windows.h. Our thought is to locate a program by its name, find its process id (pid), use that pid to locate the relevant memory areas, present the content of the memory area, and give the user a wide variety of options to do with the project currently including viewing the memory, change protection settings on a specific area, altering the memory with opcodes, altering with explicit assembly commands.
We wish to provide emulation for a tool called “Process hacker 2” in some of its perspectives. 
The core functionality of the project is written in C\C++.
The route of action we plan to take to change the protection settings is to use functions provided to us by the windows.h library. We plan to use frameworks such as capstone and zydis to view the assembly and disassembly. The suggested plan of action to change memory is to write specific bytes into the memory at requested and specifically designated areas by the user.
Methods used:
We have used the functions ReadProcessMemoy and WriteProcessMemory and Virtual*Ex (virtualQueryEx for example) and have built better and more accessible functions on top of them that let our users’ access whatever they need to access and do in an easy and user-friendly way.

The main functions of the program are:
1.	We start off with getting the information about some process. We want this because in the future we will use its pid (process id – a unique number that identify a process).
2.	After that we will print out to the string each section in the process and prints out the protection, type, and state of the section. We will then ask a user to input some memory section that the user would like to work on. 
3.	The ability to view a section – we used ReadMemoryProcess and associated assorted functions to help us with that.
4.	The ability to write information to a section – we used WriteMemoryProcess and associated assorted functions to help us with that.
5.	The ability to change the protections of each section in the memory – we used VirtualProtectEx and associated assorted functions to help us with that.
6.	The ability to save a section to memory as a .bin file (“memory screenshot”) to a location that has been entered by the user – we used ReadMemoryProcess and associated assorted functions to help us with that.
7.	Prints out all the PE headers of the file that has been inputted, we used assorted data structures that are imported from the windows.h.
8.	Creates an automatic runtime patcher – we will create a suspended process that has created memory sections but has not written anything to them and we will start it up extremely slowly and when all bytes in certain locations are equal to some data that has been inputted by the user we will patch the file so when it starts to run we will already receive the patched function functionality -useful for bypassing some anti reversing and some types of malware.



Need to link with following dlls:
1. capstone.dll
2. zydis.dll
3. keystone.dll
