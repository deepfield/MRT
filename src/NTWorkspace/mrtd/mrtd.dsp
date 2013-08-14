# Microsoft Developer Studio Project File - Name="mrtd" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=mrtd - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mrtd.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mrtd.mak" CFG="mrtd - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mrtd - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "mrtd - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mrtd - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386

!ELSEIF  "$(CFG)" == "mrtd - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /ZI /I "../../include" /I "F:/IPv6Kit/in" /I "F:\Platform SDK\Include" /I "H:\Platform SDK\Include" /I "F:\NTDDK\inc" /I "H:\NTDDK\inc" /I "C:\IPv6Kit\inc" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D "NT" /FR /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 wship6.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib iphlpapi.lib /debug /machine:IX86 /libpath:"f:\IPv6kit/lib" /libpath:"F:\Platform SDK\Lib" /libpath:"C:\IPv6Kit\lib"
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "mrtd - Win32 Release"
# Name "mrtd - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\lib\mrt\alist.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\struct\array.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_attr\as_alist.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_attr\as_regexp.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_attr\aspath.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_attr\bgp_attr.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_proto\bgp_dump.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_proto\bgp_dump2.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_attr\bgp_msg.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_proto\bgp_pdu.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_proto\bgp_sm.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_proto\bgp_thread.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_proto\bgp_timer.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_proto\bgp_util.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\config\bgpconf.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\buffer.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\config\commconf.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\kernel\common.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_attr\community.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\compat.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\config\config_file.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\connect.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\filter\filter.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\gateway.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\struct\hash.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\hashfn.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\io\io.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\kernel\kernel_uii.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\link_state.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\struct\linked_list.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\config\load.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\lsa_database.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\mrt.c
# End Source File
# Begin Source File

SOURCE=..\..\programs\mrtd\mrtd.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\config\multiconf.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\struct\New.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\nexthop.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\kernel\nt.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\timer\nt_alarm.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\ospf_config.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\ospf_database.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\ospf_hello.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\ospf_interface.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\ospf_neighbor.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\ospf_netmap.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\ospf_packet.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\ospf_thread.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\ospf\ospf_uii.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\prefix.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\radix\radix.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\reboot.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\rib\rib.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\rib\rib_uii.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\rip\rip2.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\rip\rip_proto.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\config\ripconf.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\rip\ripng.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\route_util.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\config\rtmapconf.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\schedule.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\select.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\timer\signal.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\kernel\socket.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\struct\stack.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\timer\timer.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\trace.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\user.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\user_old.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\user_util.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\util.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\mrt\vars.c
# End Source File
# Begin Source File

SOURCE=..\..\lib\bgp_proto\view.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\include\alist.h
# End Source File
# Begin Source File

SOURCE=..\..\include\api6.h
# End Source File
# Begin Source File

SOURCE=..\..\include\array.h
# End Source File
# Begin Source File

SOURCE=..\..\include\aspath.h
# End Source File
# Begin Source File

SOURCE=..\..\include\assert.h
# End Source File
# Begin Source File

SOURCE=..\..\include\bgp.h
# End Source File
# Begin Source File

SOURCE=..\..\include\bgp_proto.h
# End Source File
# Begin Source File

SOURCE=..\..\include\buffer.h
# End Source File
# Begin Source File

SOURCE=..\..\include\cache.h
# End Source File
# Begin Source File

SOURCE=..\..\include\community.h
# End Source File
# Begin Source File

SOURCE=..\..\include\config.h
# End Source File
# Begin Source File

SOURCE=..\..\include\config_file.h
# End Source File
# Begin Source File

SOURCE=..\..\include\defs.h
# End Source File
# Begin Source File

SOURCE=..\..\include\dvmrp.h
# End Source File
# Begin Source File

SOURCE=..\..\include\filter.h
# End Source File
# Begin Source File

SOURCE=..\..\include\flist.h
# End Source File
# Begin Source File

SOURCE=..\..\include\hash.h
# End Source File
# Begin Source File

SOURCE=..\..\include\igmp.h
# End Source File
# Begin Source File

SOURCE=..\..\include\interface.h
# End Source File
# Begin Source File

SOURCE=..\..\include\io.h
# End Source File
# Begin Source File

SOURCE=..\..\include\linked_list.h
# End Source File
# Begin Source File

SOURCE=..\..\include\monitor.h
# End Source File
# Begin Source File

SOURCE=..\..\include\mrt.h
# End Source File
# Begin Source File

SOURCE=..\..\include\mrt_errno.h
# End Source File
# Begin Source File

SOURCE=..\..\include\mrt_thread.h
# End Source File
# Begin Source File

SOURCE=..\..\include\New.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ntconfig.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ospf_proto.h
# End Source File
# Begin Source File

SOURCE=..\..\include\pim.h
# End Source File
# Begin Source File

SOURCE=..\..\include\rip.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ripng.h
# End Source File
# Begin Source File

SOURCE=..\..\include\trace.h
# End Source File
# Begin Source File

SOURCE=..\..\include\user.h
# End Source File
# Begin Source File

SOURCE=..\..\include\version.h
# End Source File
# Begin Source File

SOURCE=..\..\include\view.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=..\icon1.ico
# End Source File
# Begin Source File

SOURCE=..\Script1.rc
# End Source File
# End Group
# End Target
# End Project
