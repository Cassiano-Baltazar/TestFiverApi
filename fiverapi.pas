unit FiverApi;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Sockets, HTTPDefs, base64, IdGlobal, IdIPAddress, SynCommons;

type
  TType = (TTCP, TUDP);
  { TFiverApi }

  TFiverApi = class
  public
    class procedure EncodeProxy(ARequest: TRequest; AResponse: TResponse);
    class procedure DecodeProxy(ARequest: TRequest; AResponse: TResponse);
  end;

implementation

uses uProxyUtils;

{ TFiverApi }

class procedure TFiverApi.EncodeProxy(ARequest: TRequest; AResponse: TResponse);
var
  vFiverApi: TFiverApi;
  Json: Variant;
begin
  vFiverApi := TFiverApi.Create;
  try
    Json := _JsonFast(ARequest.Content);
    try
      AResponse.Content := TProxyUtils.GetHeader(Json.IP, Json.Port, Json.TypeProtocol, Json.Version);
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
    AResponse.Content := TProxyUtils.GetInfo(ARequest.Content);
    AResponse.Code := 200;
    AResponse.ContentType := 'application/json';
    AResponse.ContentLength := Length(AResponse.Content);
    AResponse.SendContent;
  finally
    vFiverApi.Free;
  end;
end;

end.

