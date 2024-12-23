// Copyright (c) 2024 fibodevy https://github.com/fibodevy
// License: MIT

program ckscheck;

uses SysUtils, Classes, Registry, Windows;

function NtQuerySystemInformation(
  SystemInformationClass: ULONG;
  SystemInformation: Pointer;
  SystemInformationLength: ULONG;
  ReturnLength: PULONG
): LONG; stdcall; external 'ntdll.dll';

function IsUserAnAdmin: BOOL; stdcall; external 'shell32.dll';

type
  TSystemCodeIntegrityInformation = record
    Length: ULONG;
    CodeIntegrityOptions: ULONG;
  end;

  tkv = record
    k: string;
    v: dword;
  end;

const
  SystemCodeIntegrityInformation = 103;

  codeintegrity: array[0..10] of tkv = (
    (k: 'CODEINTEGRITY_OPTION_ENABLED';                      v: $00000001),
    (k: 'CODEINTEGRITY_OPTION_TESTSIGN';                     v: $00000002),
    (k: 'CODEINTEGRITY_OPTION_UMCI_ENABLED';                 v: $00000004),
    (k: 'CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED';       v: $00000008),
    (k: 'CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED';  v: $00000010),
    (k: 'CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED';            v: $00000080),
    (k: 'CODEINTEGRITY_OPTION_FLIGHTING_ENABLED';            v: $00000200),
    (k: 'CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED';            v: $00000400),
    (k: 'CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED';  v: $00000800),
    (k: 'CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED'; v: $00001000),
    (k: 'CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED';             v: $00002000)
  );

var
  syskey: string = 'SYSTEM';
  update: boolean = false;
  updateandclose: boolean = false;
  update_license: integer = 1;
  update_policy_cks: integer = 1;

// REF
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/slmem/productpolicy.htm
type
  tpolicyheader = packed record
    size: dword;
    sizeofvalues: dword;
    sizeofendmarker: dword;
    unknown: dword;
    unknown2: dword;
  end;

  tpolicyvalue = packed record
    size: word;
    namesize: word;
    datatype: word;
    datasize: word;
    flags: dword;
    unknown: dword;
  end;

type
  TREG = (
    REG_NONE                       = 0,  // No value type
    REG_SZ                         = 1,  // Unicode null terminated string
    REG_EXPAND_SZ                  = 2,  // Unicode null terminated string (with environmental variable references)
    REG_BINARY                     = 3,  // Free form binary
    REG_DWORD                      = 4,  // 32-bit number
    REG_DWORD_BIG_ENDIAN           = 5,  // 32-bit number
    REG_LINK                       = 6,  // Symbolic link (Unicode)
    REG_MULTI_SZ                   = 7,  // Multiple Unicode strings, delimited by \0, terminated by \0\0
    REG_RESOURCE_LIST              = 8,  // Resource list in resource map
    REG_FULL_RESOURCE_DESCRIPTOR   = 9,  // Resource list in hardware description
    REG_RESOURCE_REQUIREMENTS_LIST = 10,
    REG_QWORD                      = 11 // 64-bit number
  );

procedure append(var s: string; data: pointer; len: dword);
var
  i: integer;
begin
  i := length(s);
  setlength(s, i+len);
  move(data^, s[1+i], len);
end;

const
  //conWhite  = 7;
  conWhite  = 15; // brighter white
  conGreen  = 10;
  conRed    = 12;
  conYellow = 14;
  conBlue   = 3;
  conGray   = 8;

procedure writecolor(s: string; color: dword);
begin
  SetConsoleTextAttribute(StdOutputHandle, color);
  write(s);
  SetConsoleTextAttribute(StdOutputHandle, conWhite);
end;

procedure writelncolor(s: string; color: dword);
begin
  SetConsoleTextAttribute(StdOutputHandle, color);
  writeln(s);
  SetConsoleTextAttribute(StdOutputHandle, conWhite);
end;

procedure check_codeintegrity;
var
  ci: TSystemCodeIntegrityInformation;
  r: LONG;
  d: dword;
  i: integer;
begin                         
  writeln('Checking Code Integrity via NtQuerySystemInformation...');
  write('Code Integrity: ');
  ci.Length := SizeOf(ci);
  r := NtQuerySystemInformation(SystemCodeIntegrityInformation, @ci, sizeof(ci), @d);
  if r = 0 then begin
    if (ci.CodeIntegrityOptions and 1) <> 0 then begin
      writecolor('ENABLED', conGreen);
    end else begin
      writecolor('DISABLED', conRed);
    end;
    writeln(' (val = 0x', inttohex(ci.CodeIntegrityOptions, 8), ')');

    if ci.CodeIntegrityOptions <> 0 then begin
      for i := 0 to high(codeintegrity) do begin
        if (ci.CodeIntegrityOptions and codeintegrity[i].v) <> 0 then begin
          writelncolor(' - 0x'+inttohex(codeintegrity[i].v)+' '+codeintegrity[i].k, conYellow);
        end;
      end;
    end;
  end else begin
    writelncolor('Check failed! NtQuerySystemInformation() return code 0x'+inttohex(r, 8), conRed);
  end;
end;

procedure check_cilicensed;
var
  r: TRegistry;
  val: integer;
  s: string;
begin
  if not IsUserAnAdmin then begin
    writelncolor('To read the "License" value, administrative privileges are required. Please run the app as an administrator.', conRed);
    exit;
  end;

  writeln('Checking CI\Protected\Licensed...');
  write('Licensed: ');

  r := TRegistry.Create;
  try
    try
      r.RootKey := HKEY_LOCAL_MACHINE;
      r.OpenKey(syskey+'\ControlSet001\Control\CI\Protected', false);
      if not r.ValueExists('Licensed') then begin
        writelncolor('"Licensed" value doesnt exist.', conRed);
      end else if (r.GetDataType('Licensed') <> rdInteger) then begin
        WriteStr(s, TREG(r.GetDataType('Licensed')));
        writelncolor('"Licensed" is of invalid type ('+s+').', conRed);
      end else begin
        val := r.ReadInteger('Licensed');
        if val <> 0 then writecolor('LICENSED', conGreen) else writecolor('NOT LICENSED', conRed);
        writeln(' (val = '+inttostr(val)+')');
      end;
    except
      writelncolor('An error occurred while accessing the registry.', conRed);
    end;
  finally
    r.Free;
  end;

  if update then begin
    write('Updating... ');
    if val = update_license then
      writelncolor('No need to update.', conGreen)
    else begin
      try
        r := TRegistry.Create;
        try
          r.RootKey := HKEY_LOCAL_MACHINE;
          r.OpenKey(syskey+'\ControlSet001\Control\CI\Protected', false);
          if r.ValueExists('Licensed') then begin
            r.WriteInteger('Licensed', update_license);
            writelncolor('Success! "License" updated to '+inttostr(update_license), conGreen)
          end else begin                                                                  
            r.WriteInteger('Licensed', update_license);
            writelncolor('Success! "License" created with value '+inttostr(update_license), conGreen);
          end;
        except
          on e: Exception do writelncolor(e.Message, conRed);
        end;
      finally
        r.Free;
      end;
    end;
  end;
end;

function productpolicy_read_data(key: string): string;
var
  r: TRegistry;
  dump, data: string;
  name: widestring;
  i: integer;    
  ph: tpolicyheader;
  pv: tpolicyvalue;
begin
  result := '';
  r := TRegistry.Create;
  try
    try
      r.RootKey := HKEY_LOCAL_MACHINE;
      r.OpenKey(syskey+'\ControlSet001\Control\ProductOptions', false);
      setlength(dump, 1024*64); // ProductPolicy has a limit of 64 KB
      setlength(dump, r.ReadBinaryData('ProductPolicy', dump[1], length(dump)));

      // header
      move(dump[1], ph, sizeof(ph));
      i := 1+sizeof(ph);
      while i < ph.size-ph.sizeofendmarker do begin
        move(dump[i], pv, sizeof(pv));
        // name
        setlength(name, pv.namesize div 2);
        move(dump[i+sizeof(pv)], name[1], pv.namesize);
        // data
        setlength(data, pv.datasize);
        move(dump[i+sizeof(pv)+pv.namesize], data[1], pv.datasize);
        // next entry
        inc(i, pv.size);

        if name = key then begin
          result := data;
          exit;
        end;
      end;
    except
    end;
  finally
    r.Free;
  end;
end;

function asdword(s: string): dword;
begin
  if length(s) <> 4 then exit(INVALID_HANDLE_VALUE);
  result := pdword(@s[1])^;
end;

procedure check_productpolicy;
var
  dump, data, newpolicy: string;
  name: widestring;
  i, c, pad: integer;
  ph: tpolicyheader;
  pv: tpolicyvalue;
  r: TRegistry;
  cks: dword;
  cksupdated: boolean = false;
  cksfound: boolean = false;
begin
  if not IsUserAnAdmin then begin
    writelncolor('To read the "ProductPolicy" data, administrative privileges are required. Please run the app as an administrator.', conRed);
    exit;
  end;

  r := TRegistry.Create;
  try
    try
      r.RootKey := HKEY_LOCAL_MACHINE;
      r.OpenKey(syskey+'\ControlSet001\Control\ProductOptions', false);
      setlength(dump, 1024*64); // ProductPolicy has a limit of 64 KB
      setlength(dump, r.ReadBinaryData('ProductPolicy', dump[1], length(dump)));

      writeln('ProductPolicy size: ', length(dump));
      writeln('Parsing data...');

      // header
      move(dump[1], ph, sizeof(ph));

      // new policy
      if update then begin
        newpolicy := '';
        append(newpolicy, @ph, sizeof(ph));
      end;

      i := 1+sizeof(ph);
      c := 0;
      while i < ph.size-ph.sizeofendmarker do begin
        inc(c);
        move(dump[i], pv, sizeof(pv));
        // name
        setlength(name, pv.namesize div 2);
        move(dump[i+sizeof(pv)], name[1], pv.namesize);
        // data
        setlength(data, pv.datasize);
        move(dump[i+sizeof(pv)+pv.namesize], data[1], pv.datasize);
        // next entry
        inc(i, pv.size);

        if name = 'CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners' then begin
          cks := pdword(@data[1])^;
          cksfound := true;
          // set new CKS if updating
          if update then begin
            pdword(@data[1])^ := update_policy_cks;
            cksupdated := true;
          end;
        end;

        // update newpolicy
        if update then begin
          append(newpolicy, @pv, sizeof(pv));
          append(newpolicy, @name[1], length(name)*2);
          append(newpolicy, @data[1], length(data));
          // padding
          pad := pv.size-(sizeof(pv)+pv.namesize+pv.datasize);
          while pad > 0 do begin
            newpolicy += #0;
            dec(pad);
          end;
        end;

        // print policy
        //writeln(name);
      end;

      writeln('ProdutPolicy entries count: ', c);

      if cksfound then begin
        write('CustomKernelSigners: ');
        if cks <> 0 then
          writecolor('ENABLED', conGreen)
        else
          writecolor('DISABLED', conRed);
        writeln(' (val = '+inttostr(cks)+')');
      end else
        writelncolor('CustomKernelSigners not found!', conRed);
    except
      writelncolor('An error occurred while accessing the registry.', conRed);
    end;
  finally  
    r.Free;
  end;

  if update then begin
    write('Updating... ');

    if cks = 1 then
      writelncolor('No need to update.', conGreen)
    else begin
      if update then begin
        if not cksfound then begin
          // Since CKS if not found in ProductPolicy, we will add it
          write('CKS policy not found, creating it...');
          name := 'CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners';
          pv.namesize := length(name)*2;
          pv.datatype := integer(REG_DWORD);
          pv.datasize := 4;
          pv.flags := 0;
          pv.unknown := 0;
          pv.size := sizeof(pv)+length(name)*4+pv.datasize;
          append(newpolicy, @pv, sizeof(pv));
          append(newpolicy, @name[1], pv.namesize);
          setlength(data, 4);
          pdword(@data[1])^ := 1;
          // add new value
          append(newpolicy, @data[1], 4);
          // update the header
          ph.sizeofvalues += pv.size;
          ph.size += pv.size;
          move(ph, newpolicy[1], sizeof(ph));
          // now the CKS is found
          cksfound := true;
          cksupdated := true;
          // but what about padding?
          // ---
          writelncolor('CKS policy appended to ProductOptions', conGreen);
        end;

        // end marker, dword($45)
        newpolicy += #$45#0#0#0;
      end;

      try
        r := TRegistry.Create;
        try
          r.RootKey := HKEY_LOCAL_MACHINE;
          r.OpenKey(syskey+'\ControlSet001\Control\ProductOptions', false);
          r.WriteBinaryData('ProductPolicy', newpolicy[1], length(newpolicy));
          sleep(1); // this is all that is required to restore CKS to 0 by the kernel
          if asdword(productpolicy_read_data('CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners')) = update_policy_cks then
            writecolor('Success! CustomKernelSigners updated to '+inttostr(update_policy_cks), conGreen)
          else
            writecolor('Failure. The value was changed but the OS immediately restored it.', conRed);
          writeln;
        except
          on e: Exception do writelncolor(e.Message, conRed);
        end;
      finally
        r.Free;
      end;

      // dump newpolicy
      //with TMemoryStream.Create do begin
      //  Write(newpolicy[1], length(newpolicy));
      //  SaveToFile('newpolicy.txt');
      //  Free;
      //end;
    end;
  end;
end;

procedure clearconsole;
var
  cbi: TConsoleScreenBufferInfo;
  consize, d: DWORD;
  coord: TCoord;
begin
  if not GetConsoleScreenBufferInfo(StdOutputHandle, cbi) then exit;
  coord.X := 0;
  coord.Y := 0;
  consize := cbi.dwSize.X*cbi.dwSize.Y;
  FillConsoleOutputCharacter(StdOutputHandle, ' ', consize, coord, d);
  FillConsoleOutputAttribute(StdOutputHandle, cbi.wAttributes, consize, coord, d);
  SetConsoleCursorPosition(StdOutputHandle, coord);
  SetConsoleTextAttribute(StdOutputHandle, conWhite);
end;

procedure dothings;
begin
  if update then begin
    writelncolor('Updating the License and CustomKernelSigners entry in ProductPolicy...', conBlue);
    writeln;
  end;

  check_codeintegrity;
  writeln;

  check_cilicensed;
  writeln;

  check_productpolicy;
  writeln;
end;

procedure printhelp;
begin
  writelncolor('1) Run "ckscheck check" to only read without applying any updates.', conWhite);
  writelncolor('2) Run "ckscheck check myhive" to read values from "HKLM\myhive" instead of "HKLM\SYSTEM"', conWhite);
  writelncolor('3) Run "ckscheck update" to apply updates and exit the app without waiting for user interaction.', conWhite);
  writelncolor('4) Run "ckscheck update myhive" to make changes to "HKLM\myhive" instead of "HKLM\SYSTEM".', conWhite);
  writelncolor('   This way you can edit the registry of another Windows installation by loading its hive file to HKLM.', conWhite);
end;

begin
  if ParamStr(1) = 'update' then begin
    update := true;
    updateandclose := true;
  end;

  if ParamStr(2) <> '' then begin
    syskey := ParamStr(2);
    writelncolor('Using registry key "'+syskey+'" instead of "SYSTEM".', conBlue);
    writeln;
  end;

  dothings;

  // if requested by param, just apply updates and close
  if updateandclose or (ParamStr(1) = 'check') then begin
    writelncolor('Done.', conBlue);
    exit;
  end;

  // give user an option to apply the updates
  if not update and IsUserAnAdmin then begin
    writelncolor('Press <enter> to update the License and ProductPolicy...', conBlue);
    readln;
    update := true;
    clearconsole;
    dothings;   
    writelncolor('Done. Press <enter> to close.', conBlue);
    readln;
    exit;
  end;

  printhelp;

  readln;
end.

