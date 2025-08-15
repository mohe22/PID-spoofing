
---

# Parent PID Spoofing in C++

This repository contains a C++ implementation of the **Parent PID (Process ID) Spoofing** technique on Windows. This program demonstrates how to create a new process (`cmd.exe`) and make it appear as if it were launched by a different, specified parent process.

This technique is often used in red teaming and malware development to evade detection by security products (like EDRs) that rely on parent-child process relationships to identify malicious activity. For example, a legitimate `svchost.exe` process should not be spawning `cmd.exe`. By spoofing the parent to be `explorer.exe`, the action might appear more legitimate to monitoring tools.

For a more detailed explanation of this technique, please see the accompanying blog post:
**[PID Spoofing Explained](https://portfolio-three-alpha-27.vercel.app/Blogs/pid-spoofing)**

<img width="900" height="183" alt="image" src="https://github.com/user-attachments/assets/8567f6de-4e00-4898-afd3-0bcd3cd360a9" />


## How It Works

The core of this technique relies on the `CreateProcess` API and its ability to accept an extended attribute list. By using the `EXTENDED_STARTUPINFO_PRESENT` flag, we can pass a `STARTUPINFOEX` structure that contains a list of attributes for the new process.

The key steps are:
1.  **Get a Handle to the Target Parent:** The program first obtains a handle to the process we want to impersonate as the parent. This requires `PROCESS_CREATE_PROCESS` rights.
2.  **Initialize an Attribute List:** It creates a `PROC_THREAD_ATTRIBUTE_LIST` large enough to hold one attribute.
3.  **Set the Parent Process Attribute:** It updates the attribute list with the `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` attribute, pointing it to the handle of our chosen target parent.
4.  **Create the Spoofed Process:** The program calls `CreateProcessW` with the `EXTENDED_STARTUPINFO_PRESENT` flag, passing in the prepared attribute list. This tells the Windows kernel to assign the specified parent to the new process instead of the actual parent (our program).
5.  **Verification:** After creation, the program uses the `CreateToolhelp32Snapshot` method to verify that the new process's parent PID matches the target PID.
6.  **Cleanup:** Finally, it meticulously closes all handles and frees all allocated memory to prevent resource leaks.

## Prerequisites

-   A Windows operating system (tested on Windows 10/11).
-   A C++ compiler that supports the Windows API, such as the one included with Visual Studio (MSVC) or MinGW-w64.

## Compilation

### Using Visual Studio (MSVC)

You can compile this code directly from the Developer Command Prompt for Visual Studio.


```bash
g++ pid-spoof.cpp -o pid-spoof.exe 
```
*   `-o pid-spoof.exe`: Sets the name of the output executable.

## Usage

The program requires one command-line argument: the Process ID (PID) of the target process you wish to set as the parent.

1.  Find the PID of a process you want to use as the spoofed parent (e.g., `explorer.exe`). You can find this using Task Manager or Process Explorer.
2.  Run the compiled executable from the command line, providing the PID.

**Example:**

Let's say the PID of `explorer.exe` is `4824`.

```cmd
C:\> pid-spoof.exe 4824
```

### Expected Output

```
[*] Target Parent PID to spoof: 4824
[+] Successfully opened handle to target parent process.
[+] Successfully set the parent process attribute.
[+] Process created successfully with PID: 8916
[*] Verifying parent PID...
[+] Parent PID according to snapshot: 4824
[+] SUCCESS: Parent PID appears to be spoofed correctly.
[*] Cleaning up resources...
[*] Cleanup complete. Exiting.
```

A new `cmd.exe` window will appear. Using a tool like **Process Hacker** or **Process Explorer**, you can inspect this new `cmd.exe` (PID `8916` in this example) and confirm that its parent process is listed as `explorer.exe` (PID `4824`), not `pid-spoof.exe`.



