unit FiverApi;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Sockets, HTTPDefs, IdGlobal, IdIPAddress, SynCommons;

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
begin
  IPAddress := TIdIPAddress.MakeAddressObject(AIP);
  try
    if IPAddress.AddrType = Id_IPv4 then
    begin
      // Proxy Protocol v2 header format
      protocol := Sockets.AF_INET;  // AF_INET (IPv4)
      // 12 for IPv4
      length := 12;

      // Convert IP addresses to binary format
      ip := NetAddrToStr(StrToHostAddr(AIP));
      ip += NetAddrToStr(StrToHostAddr(IPV4Server));

      // Add ports
      port := BigEndianWord(StrToInt(APort)) + BigEndianWord(StrToInt(IPV4ServerPort));
    end
    else if IPAddress.AddrType = Id_IPv6 then
    begin
      protocol := Sockets.AF_INET6;  // AF_INET6 (IPv6)
      // 16 for IPv6
      length := 28;

      // Convert IP addresses to binary format
      ip += NetAddrToStr6(StrToHostAddr6(AIP));
      ip += NetAddrToStr6(StrToHostAddr6(IPV6Server));

      // Add ports
      port := BigEndianWord(StrToInt(APort)) + BigEndianWord(StrToInt(IPV6ServerPort));
    end
    else
      raise Exception.Create('Invalid IP Address');

    Result := #13#10#13#10#0#13#10#81#85#73#84#10 + AnsiChar(protocol) + AnsiChar(length) + ip + port;
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

