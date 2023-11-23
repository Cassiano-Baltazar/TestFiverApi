unit FiverApi;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Sockets, HTTPDefs, base64, IdGlobal, IdIPAddress, SynCommons;

type
  TType = (TTCP, TUDP);
  { TFiverApi }

  TFiverApi = class
  private
    //Encode
    function GetHeaderUDPV1(AIP, APort: string): string;
    function GetHeaderUDPV2(AIP, APort: string): string;
    function GetHeaderV2(AIP, APort: string): string;
    function GetProxyHeader(AIP, APort: string; AVersion: Integer; AType: TType): string;
    function GetProxyHeaderTCPIPV4(AIP, APort: string; AVersion: Integer): string;
    function GetProxyHeaderUDPIPV4(AIP, APort: string; AVersion: Integer): string;
    function GetProxyHeaderTCPIPV6(AIP, APort: string; AVersion: Integer): string;
    function GetProxyHeaderUDPIPV6(AIP, APort: string; AVersion: Integer): string;

    //Decode
    function DecodeHeader(AHeader: string): string;
    function DecodeV1(AHeader: string): string;
    function DecodeV1UDP(AHeader: string): string;
    function DecodeV2(AHeader: string): string;
  public
    class procedure EncodeProxy(ARequest: TRequest; AResponse: TResponse);
    class procedure DecodeProxy(ARequest: TRequest; AResponse: TResponse);
  end;

implementation

const
  ProxyString = 'PROXY %s %s %s %s %s'#13#10;
  IPV4Server = '127.0.0.1';
  IPV4ServerPort = '80';
  IPV6Server = '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff';
  IPV6ServerPort = '80';

function BigEndianWord(value: Word): AnsiString;
begin
  Result := '';
  SetLength(Result, 2);
  Result[1] := AnsiChar((value shr 8) and $FF);
  Result[2] := AnsiChar(value and $FF);
end;

function StreamToBase64(const AStream: TMemoryStream; out Base64: String): Boolean;
var
  Str: String;
begin
  Result := False;
  if AStream.Size = 0 then
    Exit;
  AStream.Position := 0;
  try
    SetLength(Str, AStream.Size div SizeOf(Char));
    AStream.ReadBuffer(Pointer(Str)^, AStream.Size div SizeOf(Char));
    Base64 := EncodeStringBase64(Str);
    Result := Length(Base64) > 0;
  except
    on E: Exception do
      WriteLn(E.Message);
  end;
end;

function Base64ToStream(const ABase64: String; var AStream: TMemoryStream): Boolean;
var
  Str: String;
begin
  Result := False;
  if Length(Trim(ABase64)) = 0 then
    Exit;
  try
    Str := DecodeStringBase64(ABase64);
    AStream.Write(Pointer(Str)^, Length(Str) div SizeOf(Char));
    AStream.Position := 0;
    Result := AStream.Size > 0;
  except
    on E: Exception do
      WriteLn(E.Message);
  end;
end;

{ TFiverApi }

function TFiverApi.GetHeaderUDPV1(AIP, APort: string): string;
var
  IPAddress: TIdIPAddress;
begin
  IPAddress := TIdIPAddress.MakeAddressObject(AIP);
  try
    if IPAddress.AddrType = Id_IPv4 then
    begin
      Result := Format('CLIENT=%s:%s PROXY=%s:%s', [AIP, APort, IPV4Server, IPV4ServerPort]);
    end
    else if IPAddress.AddrType = Id_IPv6 then
    begin
      Result := Format('CLIENT=%s:%s PROXY=%s:%s', [AIP, APort, IPV6Server, IPV6ServerPort]);
    end
    else
      raise Exception.Create('Invalid IP Address');
  finally
    IPAddress.Free;
  end;
end;

function TFiverApi.GetHeaderUDPV2(AIP, APort: string): string;
begin
  Result := AIP + ':' + APort;
end;

function TFiverApi.GetHeaderV2(AIP, APort: string): string;
var
  ip, port: AnsiString;
  protocol: Byte;
  length: Word;
  IPAddress: TIdIPAddress;

  header: TMemoryStream;
  signature: Word;
  versionCmd: Byte;
begin
  IPAddress := TIdIPAddress.MakeAddressObject(AIP);
  try
    header := TMemoryStream.Create;
    try
      // Signature: 0x0D0A
      signature := $0D0A;
      header.Write(signature, SizeOf(signature));

      // Version and command: 0x21 (binary 0010 0001)
      versionCmd := $21;
      header.Write(versionCmd, SizeOf(versionCmd));

      if IPAddress.AddrType = Id_IPv4 then
      begin
        // Family and protocol: 0x11 (binary 0001 0001)
        header.WriteByte($11);

        // Length: 0x0010 (binary 0000 0000 0001 0000)
        header.WriteWord(12);

        // Source and destination addresses
        header.WriteAnsiString(AIP); // Source address (IPv4)
        header.WriteAnsiString(IPV4Server); // Destination address (IPv4)
        header.WriteAnsiString(APort); // Source port
        header.WriteAnsiString(IPV4ServerPort); // Destination port
      end
      else if IPAddress.AddrType = Id_IPv6 then
      begin
        // Family and protocol: 0x11 (binary 0001 0001)
        header.WriteByte($21);

        // Length: 0x0010 (binary 0000 0000 0001 0000)
        header.WriteWord(28);

        // Source and destination addresses
        header.WriteAnsiString(AIP); // Source address (IPv4)
        header.WriteAnsiString(IPV6Server); // Destination address (IPv4)
        header.WriteAnsiString(APort); // Source port
        header.WriteAnsiString(IPV6ServerPort); // Destination port
      end;

      StreamToBase64(header, Result);
    finally
      header.Free;
    end;
  finally
    IPAddress.Free;
  end;
end;

function TFiverApi.GetProxyHeader(AIP, APort: string; AVersion: Integer; AType: TType): string;
var
  IPAddress: TIdIPAddress;
begin
  if not(AVersion in [1, 2]) then
    raise Exception.Create('Invalid Proxy Protocol version. Supported versions are 1 and 2.');

  IPAddress := TIdIPAddress.MakeAddressObject(AIP);
  try
    if IPAddress.AddrType = Id_IPv4 then
    begin
      if AType = TTCP then
        Result := GetProxyHeaderTCPIPV4(AIP, APort, AVersion)
      else
        Result := GetProxyHeaderUDPIPV4(AIP, APort, AVersion);
    end
    else if IPAddress.AddrType = Id_IPv6 then
    begin
      if AType = TTCP then
        Result := GetProxyHeaderTCPIPV6(AIP, APort, AVersion)
      else
        Result := GetProxyHeaderUDPIPV6(AIP, APort, AVersion);
    end
    else
      raise Exception.Create('Invalid IP Address');
  finally
    IPAddress.Free;
  end;
end;

function TFiverApi.GetProxyHeaderTCPIPV4(AIP, APort: string; AVersion: Integer): string;
begin
  if AVersion = 1 then
  begin
    Result := Format(ProxyString, ['TCP4', AIP, IPV4Server, APort, IPV4ServerPort]);
  end
  else if AVersion = 2 then
  begin
    Result := GetHeaderV2(AIP, APort);
  end;
end;

function TFiverApi.GetProxyHeaderUDPIPV4(AIP, APort: string; AVersion: Integer): string;
begin
  if AVersion = 1 then
  begin
    Result := GetHeaderUDPV1(AIP, APort);
  end
  else if AVersion = 2 then
  begin
    Result := GetHeaderUDPV2(AIP, APort);
  end;
end;

function TFiverApi.GetProxyHeaderTCPIPV6(AIP, APort: string; AVersion: Integer): string;
begin
  if AVersion = 1 then
  begin
    Result := Format(ProxyString, ['TCP6', AIP, IPV6Server, APort, IPV6ServerPort]);
  end
  else if AVersion = 2 then
  begin
    Result := GetHeaderV2(AIP, APort);
  end;
end;

function TFiverApi.GetProxyHeaderUDPIPV6(AIP, APort: string; AVersion: Integer): string;
begin
  if AVersion = 1 then
  begin
    Result := GetHeaderUDPV1(AIP, APort);
  end
  else if AVersion = 2 then
  begin
    Result := GetHeaderUDPV2(AIP, APort);
  end;
end;

function TFiverApi.DecodeHeader(AHeader: string): string;
begin
  if pos('PROXY ', AHeader) > 0 then
    Result := DecodeV1(AHeader)
  else if pos('CLIENT=', AHeader) > 0 then
    Result := DecodeV1UDP(AHeader)
  else
    Result := DecodeV2(AHeader);
end;

function TFiverApi.DecodeV1(AHeader: string): string;
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
        json.AddValue('INET_PROTOCOL', sl[1]);
        json.AddValue('CLIENT_IP', sl[2]);
        json.AddValue('CLIENT_PORT', sl[4]);
        json.AddValue('PROXY_IP', sl[3]);
        json.AddValue('PROXY_PORT', sl[5]);
        Result := json.ToJSON;
      finally
        json.Clear;
      end;
    end;
  finally
    sl.Free;
  end;
end;

function TFiverApi.DecodeV1UDP(AHeader: string): string;
var
  sl: TStringList;
  json: TDocVariantData;
  Client, Server: string;
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
        json.AddValue('CLIENT', copy(sl[0], pos('CLIENT=', sl[0]) + 7, length(sl[0])));
        json.AddValue('PROXY', copy(sl[1], pos('PROXY=', sl[1]) + 6, length(sl[1])));
        Result := json.ToJSON;
      finally
        json.Clear;
      end;
    end;
  finally
    sl.Free;
  end;
end;

function TFiverApi.DecodeV2(AHeader: string): string;
begin
  Result := AHeader;
end;

class procedure TFiverApi.EncodeProxy(ARequest: TRequest; AResponse: TResponse);
var
  vFiverApi: TFiverApi;
  Json: Variant;
begin
  vFiverApi := TFiverApi.Create;
  try
    Json := _JsonFast(ARequest.Content);
    try
      AResponse.Content := vFiverApi.GetProxyHeader(Json.IP, Json.Port, Json.Version, Json.TypeProtocol);
      AResponse.Code := 200;
      AResponse.ContentType := 'application/json';
      AResponse.ContentLength := Length(AResponse.Content);
      AResponse.SendContent;
    finally
      TDocVariantData(Json).Clear;
    end;
  finally
    vFiverApi.Free;
  end;
end;

class procedure TFiverApi.DecodeProxy(ARequest: TRequest; AResponse: TResponse);
var
  vFiverApi: TFiverApi;
begin
  vFiverApi := TFiverApi.Create;
  try
    AResponse.Content := vFiverApi.DecodeHeader(ARequest.Content);
    AResponse.Code := 200;
    AResponse.ContentType := 'application/json';
    AResponse.ContentLength := Length(AResponse.Content);
    AResponse.SendContent;
  finally
    vFiverApi.Free;
  end;
end;

end.

