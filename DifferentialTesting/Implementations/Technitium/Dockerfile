FROM mcr.microsoft.com/dotnet/sdk:9.0

LABEL maintainer="sivakakarla@microsoft.com"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update 

RUN  apt-get install -y \
    curl \
    dnsutils \
    git \
    software-properties-common

RUN git clone --depth 1 https://github.com/TechnitiumSoftware/TechnitiumLibrary.git TechnitiumLibrary

RUN  git clone --depth 1 https://github.com/TechnitiumSoftware/DnsServer.git DnsServer

RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj -c Release
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.IO/TechnitiumLibrary.IO.csproj -c Release
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.Security.Cryptography/TechnitiumLibrary.Security.Cryptography.csproj -c Release
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.Security.OTP/TechnitiumLibrary.Security.OTP.csproj -c Release
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.Net.UPnP/TechnitiumLibrary.Net.UPnP.csproj -c Release
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.Net.Mail/TechnitiumLibrary.Net.Mail.csproj -c Release
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.Net.BitTorrent/TechnitiumLibrary.Net.BitTorrent.csproj -c Release
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.Net.Tor/TechnitiumLibrary.Net.Tor.csproj -c Release
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj -c Release
RUN dotnet build TechnitiumLibrary/TechnitiumLibrary/TechnitiumLibrary.csproj -c Release

RUN dotnet publish DnsServer/DnsServerApp/DnsServerApp.csproj -c Release

CMD ["/bin/bash", "-c", "while :; do sleep 10; done"]
