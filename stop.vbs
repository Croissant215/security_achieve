Option Explicit
Dim fs, shell, root, python
Set fs = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
root = fs.GetParentFolderName(WScript.ScriptFullName)
python = root & "\.venv\Scripts\pythonw.exe"
If Not fs.FileExists(python) Then
    MsgBox "Python environment missing. Follow the installation steps in README.md first.", 16, "Security Lab"
    WScript.Quit 1
End If
shell.Run Chr(34) & python & Chr(34) & " " & Chr(34) & root & "\launcher.pyw" & Chr(34) & " stop", 0, False
