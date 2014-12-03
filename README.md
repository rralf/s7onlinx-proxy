s7onlinx-proxy
==============

Description
==============

Replaces the s7onlinx.dll of Siemens TIA Portal and PLCSIM, acts as a transparent proxy, sniffs packets and dumps them in a format, that wireshark is able to dissect.

Small modifications on this software can also modify the packet content.

ONLY USE THIS SOFTWARE IT IF YOU REALLY KNOW WHAT YOU ARE DOING. THIS MIGHT DESTROY YOUR TIA INSTALLATION. DO NOT HESITATE TO CONTACT ME IF YOU HAVE FURTHER QUESTIONS.

Compilation
==============

Import it in Visual Studio, compile. The result will be the dll "s7onlinx.dll".

Replacing the proxy dll
==============
 - Go to "C:\Windows\SysWOW64\"
 - Rename the original "s7onlinx.dll" to s7onlinx_.dll (some processes might still use that dll, kill those processes)
 - Place the new dll in "C:\Windows\SysWOW64\"
 - Create the folder "C:\Temp"

Using the Proxy
==============
Just start your TIA project. Dumps and a logfile will be save in "C:\Temp".
Each process using this dll will generate its own logfile and three capture files:
  - Receive Capture
  - Send Capture
  - Amalgamation Capture (including both, received and sent packets)

Opening captures with wireshark
==============
  - Close TIA Studio to release all file handles.
  - Install the latest beta s7comm-plus dissector from http://sourceforge.net/projects/s7commwireshark/
  - Open one of the capture sfiles in wireshark
  - For the first time, go to Edit->Preferences Protocols->DLT_USER. Edit the "Encapsulation Tables". Add a new "DLT" (147). Choose "tpkt" as Payload protocol. Apply.
  - Have fun.
 
Author
==============
Ralf Ramsauer
