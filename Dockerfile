# Dockerfile kali-m1

# Official base image
FROM kalilinux/kali-rolling

# Apt
# RUN apt -y update && apt -y upgrade && apt -y autoremove && apt clean

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm-256color

# Install Kali Full / Apt stuff
RUN rm -fR /var/lib/apt/ && \
    apt-get clean && \
    apt-get update -y && \
    echo 'VERSION_CODENAME=kali-rolling' >> /etc/os-release

RUN apt install -y \
    # kali-linux-full \
    # kali-tools-hardware \
    # kali-tools-crypto-stego \
    kali-tools-exploitation \
    kali-tools-post-exploitation
    # kali-tools-forensics

RUN apt-get install -y software-properties-common --fix-missing

# Tools
RUN apt install aircrack-ng build-essential colordiff colortail crackmapexec crunch curl \
    dirb dirbuster dnsenum dnsrecon dnsutils dos2unix \ 
    enum4linux exploitdb ftp git gobuster hashcat hping3 \ 
    hydra impacket-scripts john joomscan libssl-dev libffi-dev man masscan metasploit-framework \ 
    mimikatz nasm ncat netcat-traditional nikto nmap patator \ 
    php powersploit proxychains proxychains4 python3-pip \ 
    python2 python3 python3-dev recon-ng responder samba samdump2 smbclient \ 
    smbmap snmp socat strace sqlmap sslscan sslstrip theharvester tmux tor vim \ 
    wafw00f weevely wfuzz wget whois wordlists wpscan xrdp zsh \ 
    -y --no-install-recommends

RUN apt install checksec screen \ 
    -y --no-install-recommends

# RUN python3 -m pip install impacket

# Tor refresh every 5 requests
RUN echo MaxCircuitDirtiness 10 >> /etc/tor/torrc && \
    update-rc.d tor enable

# Use random proxy chains / round_robin_chain for pc4
RUN sed -i 's/^strict_chain/#strict_chain/g;s/^#random_chain/random_chain/g' /etc/proxychains.conf && \
    sed -i 's/^strict_chain/#strict_chain/g;s/^round_robin_chain/round_robin_chain/g' /etc/proxychains4.conf

# ngrok
RUN curl https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz > /tmp/ngrok.tgz && \
    tar zxvf /tmp/ngrok.tgz -C /usr/local/bin && \
    chmod +x /usr/local/bin/ngrok

# GEF - https://gef.readthedocs.io/en/master/
RUN bash -c "$(curl -fsSL http://gef.blah.cat/sh)"

# RUN git clone https://github.com/1N3/Sn1per /tmp/Sn1per && bash /tmp/Sn1per/install.sh

# PWNtools
RUN python3 -m pip install --upgrade pwntools

# Seclists
# RUN git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# Default powerline10k theme, no plugins installed
RUN sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.1.2/zsh-in-docker.sh)" -- \
    -t fishy \
    -p git \
    -p ssh-agent \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    -p https://github.com/zsh-users/zsh-syntax-highlighting

# Aliases for bash and zsh
RUN echo "alias l='ls -al'" | tee -a /root/.bashrc /root/.zshrc
RUN echo "alias nse='ls /usr/share/nmap/scripts | grep '" | tee -a /root/.bashrc /root/.zshrc
RUN echo "alias scan-range='nmap -T5 -n -sn'" | tee -a /root/.bashrc /root/.zshrc
RUN echo "alias http-server='python3 -m http.server 8080'" | tee -a /root/.bashrc /root/.zshrc
RUN echo "alias php-server='php -S 127.0.0.1:8080 -t .'" | tee -a /root/.bashrc /root/.zshrc
RUN echo "alias ftp-server='python -m pyftpdlib -u \"admin\" -P \"S3cur3d_Ftp_3rv3r\" -p 2121'" | tee -a /root/.bashrc /root/.zshrc
RUN echo "alias binwalkall=`binwalk --dd='.*'`" | tee -a /root/.bashrc /root/.zshrc

# Fix ZSH slowness in git repos
RUN git config --global oh-my-zsh.hide-status 1
RUN git config --global oh-my-zsh.hide-dirty 1

# # install offical packages
# RUN echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list && \
#     echo "deb http://ftp2.nluug.nl/os/Linux/distr/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list && \
#     # echo "deb http://http.kali.org/kali kali-bleeding-edge main contrib non-free" >> /etc/apt/sources.list && \
#     apt -y update && apt -y upgrade && \
#     echo "wireshark-common wireshark-common/install-setuid boolean true" | \
#         debconf-set-selections && \
#     DEBIAN_FRONTEND=noninteractive apt install --yes --no-install-recommends \
#     # basic
#     man-db software-properties-common wget build-essential git unzip curl atool \
#     file build-essential ssh tree vim unrar less fuse psmisc htop \
#     # shells
#     zsh zsh-autosuggestions zsh-syntax-highlighting bash-completion \
#     # programming
#     python3 python3-pip python2 cargo python3-dev default-jdk npm golang shfmt shellcheck \
#     python-is-python3 \
#     # recon / web
#     gobuster dirb dirbuster nikto whatweb wkhtmltopdf burpsuite zaproxy ffuf \
#     nmap wfuzz finalrecon sqlmap wpscan sslscan smtp-user-enum feroxbuster \
#     # cracking / bruteforce
#     hcxtools hashcat hashcat-utils john hydra name-that-hash \
#     # binary exploitation
#     strace ltrace binwalk ghidra \
#     # exploitation
#     metasploit-framework exploitdb pwncat nuclei \
#     # gui/vnc
#     kali-desktop-xfce dbus-x11 x11vnc xvfb novnc \
#     # network
#     nfs-common netcat-traditional tnftp lftp iproute2 iputils-ping telnet net-tools snmp \
#     wireshark traceroute tcpdump chisel tor proxychains \
#     # dns
#     dnsrecon whois dnsutils \
#     # windows
#     crackmapexec python3-impacket enum4linux passing-the-hash samba smbclient \
#     smbmap responder impacket-scripts bloodhound rlwrap evil-winrm nbtscan windows-binaries \
#     # other
#     remmina remmina-plugin-rdp remmina-plugin-vnc firefox-esr seclists wordlists grc ranger \
#     xclip fzf ripgrep cewl jq redis-tools default-mysql-server \
#     # TODO check
#     swaks libssl-dev libffi-dev sipvicious tnscmd10g \
#     onesixtyone && \ 
#     # clear apt cache/packages
#     apt -y autoclean && apt -y autoremove && apt -y clean

# install python packages
RUN python3 -m pip install search-that-hash pwntools pyftpdlib virtualenv && \
    python3 -m pip install git+https://github.com/Tib3rius/AutoRecon.git && \
    python3 -m pip install git+https://github.com/calebstewart/paramiko && \
    # python3 -m pip install ciphey --upgrade && \
    wget -O /tmp/get-pip.py "https://bootstrap.pypa.io/pip/2.7/get-pip.py" && python2 /tmp/get-pip.py && rm /tmp/get-pip.py && \
    python3 -m pip install -U pyopenssl

# clone usefull repos
RUN mkdir -p /opt/repos && \
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/repos/PayloadsAllTheThings && \
    # git clone https://github.com/samratashok/nishang.git /opt/repos/nishang && \
    # git clone https://github.com/FireFart/dirtycow.git /opt/repos/dirtycow && \
    # git clone https://github.com/dirkjanm/krbrelayx.git /opt/repos/krbrelayx && \
    # git clone https://github.com/rebootuser/LinEnum.git /opt/repos/LinEnum && \
    # git clone https://github.com/mzet-/linux-exploit-suggester.git /opt/repos/linux-exploit-suggester && \
    # git clone https://github.com/diego-treitos/linux-smart-enumeration.git /opt/repos/linux-smart-enumeration && \
    git clone https://github.com/CISOfy/lynis.git /opt/repos/lynis && \
    # git clone https://github.com/ivan-sincek/php-reverse-shell.git /opt/repos/php-reverse-shell && \
    # git clone https://github.com/mostaphabahadou/postenum.git /opt/repos/postenum && \
    git clone https://github.com/PowerShellMafia/PowerSploit.git /opt/repos/PowerSploit && \
    # git clone https://github.com/diegocr/netcat.git /opt/repos/netcat && \
    # git clone https://github.com/Greenwolf/ntlm_theft /opt/repos/ntlm_theft && \
    git clone https://github.com/bitsadmin/wesng /opt/repos/wesng

# files for external usage
RUN mkdir -p /opt/external && \
    apt install -y jq && \ 
    wget -O /tmp/chisel_linux64.gz "$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | jq -r '.assets[].browser_download_url' | grep 'chisel_.*_linux_amd64')" && gunzip /tmp/chisel_linux64.gz && mv /tmp/chisel_linux64 /opt/external && \
    wget -O /tmp/chisel_linux86.gz "$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | jq -r '.assets[].browser_download_url' | grep 'chisel_.*_linux_386')" && gunzip /tmp/chisel_linux86.gz && mv /tmp/chisel_linux86 /opt/external && \
    wget -O /tmp/chisel_win64.gz "$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | jq -r '.assets[].browser_download_url' | grep 'chisel_.*_windows_amd64')" && gunzip /tmp/chisel_win64.gz && mv /tmp/chisel_win64 /opt/external/chisel_win64.exe && \
    wget -O /tmp/chisel_win86.gz "$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | jq -r '.assets[].browser_download_url' | grep 'chisel_.*_windows_386')" && gunzip /tmp/chisel_win86.gz && mv /tmp/chisel_win86 /opt/external/chisel_win86.exe && \
    wget -O /opt/external/pspy32 "$(curl -s https://api.github.com/repos/DominicBreuker/pspy/releases/latest | jq -r '.assets[].browser_download_url' | grep 'pspy32$')" && \
    wget -O /opt/external/pspy32s "$(curl -s https://api.github.com/repos/DominicBreuker/pspy/releases/latest | jq -r '.assets[].browser_download_url' | grep 'pspy32s')" && \
    wget -O /opt/external/pspy64 "$(curl -s https://api.github.com/repos/DominicBreuker/pspy/releases/latest | jq -r '.assets[].browser_download_url' | grep 'pspy64$')" && \
    wget -O /opt/external/pspy64s "$(curl -s https://api.github.com/repos/DominicBreuker/pspy/releases/latest | jq -r '.assets[].browser_download_url' | grep 'pspy64s')" && \
    wget -O /opt/external/linpeas.sh "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'linpeas.sh')" && \
    wget -O /opt/external/linpeas_linux_386 "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'linpeas_linux_386')" && \
    wget -O /opt/external/linpeas_linux_amd64 "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'linpeas_linux_amd64')" && \
    wget -O /opt/external/winPEAS.bat "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'winPEAS.bat')" && \
    wget -O /opt/external/winPEASany.exe "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'winPEASany.exe')" && \
    wget -O /opt/external/winPEASany_ofs.exe "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'winPEASany_ofs.exe')" && \
    wget -O /opt/external/winPEASx64.exe "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'winPEASx64.exe')" && \
    wget -O /opt/external/winPEASx64_ofs.exe "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'winPEASx64_ofs.exe')" && \
    wget -O /opt/external/winPEASx86.exe "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'winPEASx86.exe')" && \
    wget -O /opt/external/winPEASx86_ofs.exe "$(curl -s https://api.github.com/repos/carlospolop/PEASS-ng/releases/latest | jq -r '.assets[].browser_download_url' | grep 'winPEASx86_ofs.exe')" && \
    wget -O /tmp/sysint.zip 'https://download.sysinternals.com/files/SysinternalsSuite.zip' && unzip /tmp/sysint.zip -d /opt/external && rm /opt/external/*.chm /opt/external/*.txt /tmp/sysint.zip && \
    mkdir /tmp/mimi && wget -O /tmp/mimi/mimikatz.zip "$(curl -s https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest | jq -r '.assets[].browser_download_url' | grep 'mimikatz_.*.zip')" && \
    unzip /tmp/mimi/mimikatz.zip -d /tmp/mimi && cp /tmp/mimi/Win32/mimikatz.exe /opt/external/mimikatz32.exe && cp /tmp/mimi/Win32/mimilove.exe /opt/external/mimilove.exe && cp /tmp/mimi/x64/mimikatz.exe /opt/external/mimikatz64.exe && rm -rf /tmp/mimi && \
    wget -O /opt/external/traitor-386 "$(curl -s https://api.github.com/repos/liamg/traitor/releases/latest | jq -r '.assets[].browser_download_url' | grep 'traitor-386')" && \
    wget -O /opt/external/traitor-amd64 "$(curl -s https://api.github.com/repos/liamg/traitor/releases/latest | jq -r '.assets[].browser_download_url' | grep 'traitor-amd64')" && \
    wget -O /opt/external/SharpWeb.exe "$(curl -s https://api.github.com/repos/djhohnstein/SharpWeb/releases/latest | jq -r '.assets[].browser_download_url' | grep '.*.exe')" && \
    mkdir -p /opt/external/SharpCollection && git clone https://github.com/Flangvik/SharpCollection /opt/external/SharpCollection && \
    wget -O /opt/external/PrivescCheck.ps1 https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1 && \
    wget -O /opt/external/SharpHound.exe https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe && \
    wget -O /opt/external/JuicyPotato.exe https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe && \
    # wget -O /opt/external/nmap-setup.exe https://nmap.org"$(curl --silent https://nmap.org/dist/ | grep "installer for Windows" | cut -d '"' -f 4)" && \
    # wget -O /opt/external/putty32.exe https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe && \
    # wget -O /opt/external/putty64.exe https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe && \
    git clone https://github.com/expl0itabl3/Toolies /opt/external/Toolies


# Seclists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists

# Create unprivileged user
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap && \
    sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen && \
    # setup metasploit database
    service postgresql start && msfdb init && \
    # create user
    echo "kali ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers && \
    useradd --create-home --shell /bin/zsh --user-group --groups sudo kali && \
    echo "kali:kali" | chpasswd && \
    mkdir -p /etc/zsh/zshrc.d && \
    printf 'if [ -d /etc/zsh/zshrc.d ]; then\n  for i in /etc/zsh/zshrc.d/*; do\n    if [ -r $i ]; then\n      . $i\n    fi\n  done\n  unset i\nfi' >> /etc/zsh/zshrc && \
    tar -xf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
        -C /usr/share/seclists/Passwords/Leaked-Databases/ && \
    git clone https://github.com/wolfcw/libfaketime /tmp/libfaketime && make -C /tmp/libfaketime/src install && rm -rf /tmp/libfaketime

# other tools
RUN mkdir -p /usr/local/bin && \
    apt install -y npm

# RUN wget -O /tmp/rustscan.deb "$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/tags/2.0.1 | jq -r '.assets[].browser_download_url' | grep 'rustscan_.*_amd64')" && apt install /tmp/rustscan.deb && rm /tmp/rustscan.deb && \
#     wget -O /tmp/nvim.deb "$(curl -s https://api.github.com/repos/neovim/neovim/releases/latest | jq -r '.assets[].browser_download_url' | grep -E 'nvim\-linux64\.deb$')" && apt install /tmp/nvim.deb && rm /tmp/nvim.deb && \
#     wget -O /tmp/findomain.zip https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux.zip && unzip /tmp/findomain.zip -d /usr/local/bin && rm /tmp/findomain.zip && chmod +x /usr/local/bin/findomain
    
RUN wget -O /usr/local/bin/gitdumper.sh https://raw.githubusercontent.com/internetwache/GitTools/master/Dumper/gitdumper.sh && chmod +x /usr/local/bin/gitdumper.sh && \
    wget -O /usr/local/bin/extractor.sh https://raw.githubusercontent.com/internetwache/GitTools/master/Extractor/extractor.sh && chmod +x /usr/local/bin/extractor.sh && \
    wget -O /usr/local/bin/gitfinder.py https://raw.githubusercontent.com/internetwache/GitTools/master/Finder/gitfinder.py && chmod +x /usr/local/bin/gitfinder.py && \
    wget -O /usr/local/bin/enum4linux-ng.py https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/enum4linux-ng.py && chmod +x /usr/local/bin/enum4linux-ng.py && \
    wget -O /usr/local/bin/kerbrute "$(curl -s https://api.github.com/repos/ropnop/kerbrute/releases/latest | jq -r '.assets[].browser_download_url' | grep 'linux_amd64')" && chmod +x /usr/local/bin/kerbrute && \
    npm install -g yarn
    
RUN git clone https://github.com/pwndbg/pwndbg /home/kali/.pwndbg && cd /home/kali/.pwndbg && /home/kali/.pwndbg/setup.sh && echo "source /home/kali/.pwndbg/gdbinit.py" >> /home/kali/.gdbinit && \
    chown -R kali:kali /home/kali && \
    # chown -R kali:kali /usr/share/zaproxy && \
    apt -y autoclean && apt -y autoremove && apt -y clean

# Install kali desktop
ARG KALI_DESKTOP=xfce
RUN apt-get -y install tightvncserver dbus dbus-x11 novnc net-tools

RUN systemctl enable xrdp.service && \
    systemctl enable xrdp-sesman.service

# code-server
RUN mkdir -p /opt/code-server && \
    curl -Ls https://api.github.com/repos/codercom/code-server/releases/latest | grep "browser_download_url.*linux" | cut -d ":" -f 2,3 | tr -d \"  | xargs curl -Ls | tar xz -C /opt/code-server --strip 1 && \
    echo 'export PATH=/opt/code-server:$PATH' >> /etc/profile


RUN apt -y install --no-install-recommends xorg xorgxrdp xrdp ; \
            echo "rm -rf /var/run/xrdp >/dev/null 2>&1" >> /startkali.sh ; \
            echo "/etc/init.d/xrdp start" >> /startkali.sh ; \
            sed -i s/^port=3389/port=${RDP_PORT}/ /etc/xrdp/xrdp.ini ; \
            adduser xrdp ssl-cert ; \
            if [ "xfce" = "${DESKTOP_ENVIRONMENT:-xfce}" ] ; \
            then \
                echo xfce4-session > /home/${UNAME}/.xsession ; \
                chmod +x /home/${UNAME}/.xsession ; \
            fi ;

RUN service xrdp start

# ENV USER kali

ENV VNCEXPOSE 0
ENV VNCPORT 5900
ENV VNCPWD disfigure-iguana-vice8
# ENV VNCDISPLAY 1920x1080
ENV VNCDISPLAY 2560x1600
ENV VNCDEPTH 16

ENV NOVNCPORT 8080
# Entrypoint

# Set working directory to /root
WORKDIR /root
WORKDIR /home/kali

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]

# If you need proxychains over Tor just activate tor service with: service tor start

# Open shell
CMD ["/bin/zsh"]
# CMD ["/bin/bash", "--init-file", "/etc/profile"]
