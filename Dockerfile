#Build Stage
FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /app

COPY Moneteer.Identity.sln .
COPY Moneteer.Identity/Moneteer.Identity.csproj ./Moneteer.Identity/
COPY Moneteer.Identity.Domain/Moneteer.Identity.Domain.csproj ./Moneteer.Identity.Domain/
RUN dotnet restore

COPY . .

RUN dotnet publish Moneteer.Identity/Moneteer.Identity.csproj -c Release -o /publish

#Runtime Image Stage
FROM microsoft/dotnet:2.1-aspnetcore-runtime
WORKDIR /public
COPY --from=build /publish .
CMD ASPNETCORE_URLS=http://*:$PORT dotnet Moneteer.Identity.dll