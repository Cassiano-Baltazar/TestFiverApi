program FiverApiTest;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  SysUtils, fphttpapp, HTTPDefs, httproute, FiverApi;

procedure CatchAllEndPoint(ARequest: TRequest; AResponse: TResponse);
begin
  AResponse.Content := 'This endpoint is not available';
  AResponse.Code := 404;
  AResponse.ContentType := 'text/plain';
  AResponse.ContentLength := Length(AResponse.Content);
  AResponse.SendContent;
end;

procedure ProxyEncodeEndPoint(ARequest: TRequest; AResponse: TResponse);
begin
  TFiverApi.EncodeProxy(ARequest, AResponse);
end;

procedure ProxyDecodeEndPoint(ARequest: TRequest; AResponse: TResponse);
begin
  TFiverApi.DecodeProxy(ARequest, AResponse);
end;


begin
  Application.Port := 8080;
  HTTPRouter.RegisterRoute('/ProxyEncode', rmPost, @ProxyEncodeEndPoint);
  HTTPRouter.RegisterRoute('/ProxyDecode', rmPost, @ProxyDecodeEndPoint);
  HTTPRouter.RegisterRoute('/catchall', rmAll, @CatchAllEndPoint, True);
  Application.Threaded := True;
  Application.Initialize;
  WriteLn('Server is ready at localhost:' + IntToStr(Application.Port));
  Application.Run;
end.

