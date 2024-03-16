**I finally got .NETv4 to work, and here's what ended up being the solution.***

If we check what versions of `.NET` are supported on our target host:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, version

PSChildName Version
----------- -------
Client      4.7.03190
Full        4.7.03190
Client      4.0.0.0
```

So it would seem that versions under 4.0 aren't supported on this host.

Here's what I discovered.  The generated .js contains a serialized object. In fact, for the staged technique, it's the same object that is based on the project located in `SharpShooter/CSharpShooter`.  Examining the SharpShooter.cs:
```cs
Line 172:
compilerInfo.Add("CompilerVersion", "v3.5");
Line 181:
parameters.CompilerOptions = "/unsafe /platform:x86";
```

Basically, the staged version generates a [-o name].payload is essentially an encoded or serialized version of `SharpShooter/templates/Shellcode.cs`, then proceeds to use csc.exe to compile it on the target computer after downloading the .payload stage.

WScript exits immediately because csc can't compile using CompilerVersion 3.5; it doesn't exist on the target.

Here is the solution.

I created a copy of the folder `SharpShooter/CSharpShooter` and named it `SharpShooter/CSharpShooter`v4. I then made the following changes:
```cs
Line 172:
compilerInfo.Add("CompilerVersion", "v4.0");
Line 181:
parameters.CompilerOptions = "/unsafe /platform:x64";
```

The change to `/platform`, may or may not even be needed, who knows.

Then, load up the project in Visual Studio.  On the menu bar, go to Project -> SharpShooter properties.  In the drop-down for Target Framework, change this to ".NET Framework 4".  Build the project, then find the SharpShooterAssembly.dll in an expected build place.

To be clear, the Target Framework defined in Visual Studio on the project is going to be relevant to wscript, the CompilerVersion flag is going to be relevant to csc.exe.

Next, generate a payload using DotNetToJScript and the SharpShooterAssembly.dll we built.  We don't care so much about the options provided as they don't affect the serialization much, but here's what I used:
```shell
.\DotNetToJScript.exe SharpShooterAssembly.dll -c SharpShooter -l JScript -v v4 -o demo.js
```

From the demo.js above, we want to take the serialized object definition ("var serialized_obj"), copy it, and replace the one defined in SharpShooter/templates/SharpShooterv4.js.

Now generate your SharpShooter staged payload, being sure to supply `-v v4` and if following the above example, `-l JScript`.

Finally, profit.

The same procedure can be applied to your --stageless by doing the same things as above with `SharpShooter/CSharpShooter`Stageless and SharpShooter/templates/stagelessv4.js
