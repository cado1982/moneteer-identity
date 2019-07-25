#Build Stage
FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /app

# Setup NodeJs
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get install -y gnupg2 && \
    wget -qO- https://deb.nodesource.com/setup_6.x | bash - && \
    apt-get install -y build-essential nodejs
# End setup

COPY Moneteer.Identity.sln .
COPY Moneteer.Identity/Moneteer.Identity.csproj ./Moneteer.Identity/
COPY Moneteer.Identity.Domain/Moneteer.Identity.Domain.csproj ./Moneteer.Identity.Domain/
RUN dotnet restore

WORKDIR /app/Moneteer.Identity
COPY Moneteer.Identity/package.json .
RUN npm install

COPY Moneteer.Identity/Styles Styles/
COPY Moneteer.Identity/gulpfile.js .
RUN npm run gulp-build

WORKDIR /app
COPY . .

RUN dotnet publish -c Release -o /publish --no-restore

#Runtime Image Stage
FROM microsoft/dotnet:2.1-aspnetcore-runtime
WORKDIR /public
COPY --from=build /publish .
ENV ASPNETCORE_URLS http://+:5000
EXPOSE 5000
ENTRYPOINT ["dotnet", "Moneteer.Identity.dll"]