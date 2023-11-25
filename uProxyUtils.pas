unit uProxyUtils;

{$mode objfpc}{$H+}

interface

uses SysUtils, Classes;

type

  { TProxyUtils }

  TProxyUtils = class
  private
    function GetSignature: TBytes;

    function GetV1Header(AIPFrom, AIPTo: string; APortFrom, APortTo, AType, AProtocol: Integer): string;
    function GetV2Header(AIPFrom, AIPTo: string; APortFrom, APortTo, AType, AProtocol: Integer): string;

    function GetInfoV1(AHeader: TBytesStream): string;
    function GetInfoV1TCP(AHeader: string): string;
    function GetInfoV1UDP(AHeader: string): string;
    function GetInfoV2(AHeader: TBytesStream): string;
  public
    class function GetHeader(AIPFrom: string; APortFrom, AType, AVersion: Integer): string;
    class function GetInfo(AHeader: string): string;
  end;

function BytesStreamToHexStr(BytesStream: TBytesStream): string;
function HexStringToBytesStream(HexString: string): TBytesStream;

implementation

uses Sockets, SynCommons, IdIPAddress, IdGlobal;

const
  IPV4Server = '127.0.0.1';
  IPV4ServerPort = 443;
  IPV6Server = '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff';
  IPV6ServerPort = 443;

function BytesStreamToHexStr(BytesStream: TBytesStream): string;
var
  Bytes: TBytes;
  I: Integer;
begin
  Bytes := nil;
  // Get the TBytes array from the TBytesStream
  SetLength(Bytes, BytesStream.Size);
  BytesStream.Position := 0;
  BytesStream.ReadBuffer(Bytes[0], BytesStream.Size);

  // Convert TBytes to hexadecimal string
  Result := '';
  for I := 0 to High(Bytes) do
    Result := Result + IntToHex(Bytes[I], 2);
end;

function HexStringToBytesStream(HexString: string): TBytesStream;
var
  HexLength, BytesCount: Integer;
  Bytes: TBytes;
begin
  HexLength := Length(HexString);
  BytesCount := HexLength div 2;
  Bytes := nil;

  SetLength(Bytes, BytesCount);
  HexToBin(PChar(HexString), @Bytes[0], BytesCount);

  Result := TBytesStream.Create;
  Result.Write(Bytes[0], BytesCount);
end;

{ TProxyUtils }

function TProxyUtils.GetSignature: SysUtils.TBytes;
begin
  Result := nil; // don't reallocate TBytes data from a previous call
  SetLength(result, 12);
  Result[0] := $0D;
  Result[1] := $0A;
  Result[2] := $0D;
  Result[3] := $0A;
  Result[4] := $00;
  Result[5] := $0D;
  Result[6] := $0A;
  Result[7] := $51;
  Result[8] := $55;
  Result[9] := $49;
  Result[10] := $54;
  Result[11] := $0A;
end;

function TProxyUtils.GetV1Header(AIPFrom, AIPTo: string; APortFrom, APortTo, AType, AProtocol: Integer): string;
var
  ProxyType, Proxy: string;
  Header: TBytesStream;
begin
  if AProtocol = 0 then
    ProxyType := 'TCP4'
  else
    ProxyType := 'TCP6';

  if AType = 0 then
    Proxy := Format('PROXY %s %s %d %s %d'#13#10, [ProxyType, AIPFrom, APortFrom, AIPTo, APortTo])
  else
    Proxy := Format('CLIENT=%s:%d PROXY=%s:%d', [AIPFrom, APortFrom, AIPTo, APortTo]);

  Header := TBytesStream.Create;
  try
    Header.WriteAnsiString(Proxy);
    Result := BytesStreamToHexStr(Header);
  finally
    Header.Free;
  end;
end;

function TProxyUtils.GetV2Header(AIPFrom, AIPTo: string; APortFrom, APortTo, AType, AProtocol: Integer): string;
var
  Header: TBytesStream;
  Sign: Byte;
  AddrFrom, AddrTo: TInetSockAddr;
  AddrFrom6, AddrTo6: TInetSockAddr6;
begin
  Result := '';

  Header := TBytesStream.Create;
  try
    // 0 - 11: Signature
    for Sign in GetSignature do
      Header.WriteByte(Sign);

    //Header.WriteByte($0D);
    //Header.WriteByte($0A);
    //Header.WriteByte($0D);
    //Header.WriteByte($0A);
    //Header.WriteByte($00);
    //Header.WriteByte($0D);
    //Header.WriteByte($0A);
    //Header.WriteByte($51);
    //Header.WriteByte($55);
    //Header.WriteByte($49);
    //Header.WriteByte($54);
    //Header.WriteByte($0A);
    // 12: protocol version and command
    Header.WriteByte($21);

    if AProtocol = 0 then //IPV4
    begin
      AddrFrom.sin_family := AF_INET;
      AddrFrom.sin_addr := StrToNetAddr(AIPFrom);
      AddrFrom.sin_port := htons(APortFrom);

      AddrTo.sin_family := AF_INET;
      AddrTo.sin_addr := StrToNetAddr(AIPTo);
      AddrTo.sin_port := htons(APortTo);

      //13: Family and protocol:
      // $11: TCP over IPv4
      // $12: UDP over IPv4
      if AType = 0 then
        Header.WriteByte($11)
      else
        Header.WriteByte($12);

      //14-15: Length
      Header.WriteWord(SizeOf(AddrFrom));

      //16 - Length: Source and destination addresses
      Header.Write(AddrFrom, SizeOf(AddrFrom)); // Source address (IPv4)
      Header.Write(AddrTo, SizeOf(AddrTo)); // Destination address (IPv4)
    end
    else if AProtocol = 1 then //IPV6
    begin
      AddrFrom6.sin6_family := AF_INET6;
      AddrFrom6.sin6_addr := StrToNetAddr6(AIPFrom);
      AddrFrom6.sin6_port := htons(APortFrom);

      AddrTo6.sin6_family := AF_INET;
      AddrTo6.sin6_addr := StrToNetAddr6(AIPTo);
      AddrTo6.sin6_port := htons(APortTo);

      //13: Family and protocol:
      // $21: TCP over IPv6
      // $22: UDP over IPv6
      if AType = 0 then
        Header.WriteByte($21)
      else
        Header.WriteByte($22);

      //14-15: Length
      Header.WriteWord(SizeOf(AddrFrom6));

      //16 - Length: Source and destination addresses
      Header.Write(AddrFrom6, SizeOf(AddrFrom6)); // Source address (IPv6)
      Header.Write(AddrTo6, SizeOf(AddrTo6)); // Destination address (IPv6)
    end;

    Result := BytesStreamToHexStr(Header);
  finally
    Header.Free;
  end;
end;

function TProxyUtils.GetInfoV1(AHeader: TBytesStream): string;
var
  Header: string;
begin
  AHeader.Position := 0;
  Header := AHeader.ReadAnsiString;
  if Pos('CLIENT=', Header) > 0 then
    Result := GetInfoV1UDP(Header)
  else
    Result := GetInfoV1TCP(Header);
end;

function TProxyUtils.GetInfoV1TCP(AHeader: string): string;
var
  sl: TStringList;
  json: TDocVariantData;
begin
  Result := '';
  sl := TStringList.Create;
  try
    sl.Delimiter := ' ';
    sl.DelimitedText := AHeader;

    if sl.Count > 0 then
    begin
      json.InitFast;
      try
        json.AddValue('VERSION', 1);
        json.AddValue('INET_PROTOCOL', sl[1]);
        json.AddValue('CLIENT_IP', sl[2]);
        json.AddValue('CLIENT_PORT', sl[4]);
        json.AddValue('PROXY_IP', sl[3]);
        json.AddValue('PROXY_PORT', sl[5]);
        Result := json.ToJSON('', '', jsonHumanReadable);
      finally
        json.Clear;
      end;
    end;
  finally
    sl.Free;
  end;
end;

function TProxyUtils.GetInfoV1UDP(AHeader: string): string;
var
  sl: TStringList;
  json: TDocVariantData;
begin
  Result := '';
  sl := TStringList.Create;
  try
    sl.Delimiter := ' ';
    sl.DelimitedText := AHeader;

    if sl.Count > 0 then
    begin
      json.InitFast;
      try
        json.AddValue('VERSION', 1);
        json.AddValue('CLIENT', copy(sl[0], pos('CLIENT=', sl[0]) + 7, length(sl[0])));
        json.AddValue('PROXY', copy(sl[1], pos('PROXY=', sl[1]) + 6, length(sl[1])));
        Result := json.ToJSON('', '', jsonHumanReadable);
      finally
        json.Clear;
      end;
    end;
  finally
    sl.Free;
  end;
end;

function TProxyUtils.GetInfoV2(AHeader: TBytesStream): string;
var
  ReadByte: Byte;
  Json: TDocVariantData;
  SizeAddr: Integer;
  IsIPV4: Boolean;

  AddrFrom, AddrTo: TInetSockAddr;
  AddrFrom6, AddrTo6: TInetSockAddr6;
begin
  Json.InitFast;
  try
    json.AddValue('VERSION', 2);
    AHeader.Position := 13;
    ReadByte := AHeader.ReadByte;

    // $11: TCP over IPv4
    // $12: UDP over IPv4
    // $21: TCP over IPv6
    // $22: UDP over IPv6
    IsIPV4 := ReadByte in [$11, $12];
    case ReadByte of
      $11, $21: Json.AddValue('INET_PROTOCOL', 'TCP');
      $12, $22: Json.AddValue('INET_PROTOCOL', 'UDP');
    end;

    SizeAddr := AHeader.ReadWord;
    if IsIPV4 then
    begin
      AHeader.Read(AddrFrom, SizeAddr);
      AHeader.Read(AddrTo, SizeAddr);

      json.AddValue('CLIENT_IP', Sockets.NetAddrToStr(AddrFrom.sin_addr));
      json.AddValue('CLIENT_PORT', Sockets.NToHs(AddrFrom.sin_port));
      json.AddValue('PROXY_IP', Sockets.NetAddrToStr(AddrTo.sin_addr));
      json.AddValue('PROXY_PORT', Sockets.NToHs(AddrTo.sin_port));
    end
    else
    begin
      AHeader.Read(AddrFrom6, SizeAddr);
      AHeader.Read(AddrTo6, SizeAddr);

      json.AddValue('CLIENT_IP', Sockets.NetAddrToStr6(AddrFrom6.sin6_addr));
      json.AddValue('CLIENT_PORT', Sockets.NToHs(AddrFrom6.sin6_port));
      json.AddValue('PROXY_IP', Sockets.NetAddrToStr6(AddrTo6.sin6_addr));
      json.AddValue('PROXY_PORT', Sockets.NToHs(AddrTo6.sin6_port));
    end;

    Result := Json.ToJSON('', '', jsonHumanReadable);
  finally
    Json.Clear;
  end;
end;

class function TProxyUtils.GetHeader(AIPFrom: string; APortFrom, AType, AVersion: Integer): string;
var
  IPAddress: TIdIPAddress;
  ProxyUtils: TProxyUtils;
begin
  Result := '';
  ProxyUtils := TProxyUtils.Create;
  try
    IPAddress := TIdIPAddress.MakeAddressObject(AIPFrom);
    try
      if IPAddress.AddrType = Id_IPv4 then
      begin
        if AVersion = 0 then
        begin
          Result := ProxyUtils.GetV1Header(AIPFrom, IPV4Server, APortFrom, IPV4ServerPort, AType, 0);
        end
        else
        begin
          Result := ProxyUtils.GetV2Header(AIPFrom, IPV4Server, APortFrom, IPV4ServerPort, AType, 0);
        end;
      end
      else if IPAddress.AddrType = Id_IPv6 then
      begin
        if AVersion = 0 then
        begin
          Result := ProxyUtils.GetV1Header(AIPFrom, IPV6Server, APortFrom, IPV6ServerPort, AType, 1);
        end
        else
        begin
          Result := ProxyUtils.GetV2Header(AIPFrom, IPV4Server, APortFrom, IPV4ServerPort, AType, 1);
        end;
      end
      else
        raise Exception.Create('Invalid IP Address');
    finally
      IPAddress.Free;
    end;
  finally
    ProxyUtils.Free;
  end;
end;

class function TProxyUtils.GetInfo(AHeader: string): string;
var
  Header: TBytesStream;
  ReadByte: Byte;
  Json: TDocVariantData;

  signature: TBytes;
  sign: Byte;
  isV1: Boolean;
  ProxyUtils: TProxyUtils;
begin
  ProxyUtils := TProxyUtils.Create;
  try
    Json.InitFast;
    try
      Header := HexStringToBytesStream(AHeader);
      try
        Header.Position := 0;
        isV1 := True;
        signature := ProxyUtils.GetSignature;
        while Header.Position < 11 do
        begin
          sign := signature[Header.Position];
          ReadByte := Header.ReadByte;
          isV1 := sign <> ReadByte;
          if isV1 then
            Break;
        end;

        if isV1 then
          Result := ProxyUtils.GetInfoV1(Header)
        else
          Result := ProxyUtils.GetInfoV2(Header);
      finally
        Header.Free;
      end;
    finally
      Json.Clear;
    end;
  finally
    ProxyUtils.Free;
  end;
end;

end.
