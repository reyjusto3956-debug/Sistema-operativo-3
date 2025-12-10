=========================================================================================================================
PRACTICAS DE SEGURIDAD – ROCkY LINUX / RED HAT
Autor: r20241244
Interfaz usada: ens160
IP del sistema: 10.0.0.148/24
=========================================================================================================================
=========================================================================================================================
PRÁCTICA 1 — Cifrado de archivos con GPG2
=========================================================================================================================
Instalación y creación del archivo a cifrar
sudo dnf install gnupg2
nano archivo.txt

Contenido del archivo (ejemplo):
r20241244
Archivo de prueba para cifrado.

Cifrado y descifrado
Cifrar archivo
gpg2 -c archivo.txt

Ver archivo cifrado (binario)
cat archivo.txt.gpg

Descifrar archivo
gpg2 -d archivo.txt.gpg

Descifrar y guardar en un archivo
gpg2 -d archivo.txt.gpg > decrypted.txt

Explicación

-c → modo simétrico (requiere contraseña).

gpg2 -d → descifra y muestra por pantalla.

Se recomienda guardar contraseñas fuertes y no usar claves simples.

=========================================================================================================================
PRÁCTICA 2 — Manejo de firewall-cmd e iptables
=========================================================================================================================
Instalación de servicios Web y FTP
sudo dnf install httpd vsftpd -y
sudo systemctl enable httpd vsftpd --now

Archivo web de prueba
sudo nano /var/www/html/index.html


Contenido:

<h1>PROBANDO FIREWALL</h1>

================================
Uso de iptables
================================
Detener firewalld temporalmente
sudo systemctl stop firewalld

Bloquear/permitir puertos
Bloquear HTTP (80)
sudo iptables -A INPUT -p tcp --dport 80 -j DROP


Eliminar regla:

sudo iptables -D INPUT -p tcp --dport 80 -j DROP

Bloquear FTP (21)
sudo iptables -A INPUT -p tcp --dport 21 -j DROP


Eliminar:

sudo iptables -D INPUT -p tcp --dport 21 -j DROP

Bloquear SSH (22)
sudo iptables -A INPUT -p tcp --dport 22 -j DROP


Eliminar:

sudo iptables -D INPUT -p tcp --dport 22 -j DROP

================================
Uso de firewall-cmd (Firewalld)
================================
Permitir HTTP
sudo firewall-cmd --add-port=80/tcp --permanent
sudo firewall-cmd --reload

Eliminar regla
sudo firewall-cmd --remove-port=80/tcp --permanent
sudo firewall-cmd --reload

Permitir FTP
sudo firewall-cmd --add-port=21/tcp --permanent
sudo firewall-cmd --reload

Permitir SSH
sudo firewall-cmd --add-port=22/tcp --permanent
sudo firewall-cmd --reload

=========================================================================================================================
PRÁCTICA 3 — Instalación de IDS Snort 3
=========================================================================================================================
Habilitar repositorios
sudo dnf config-manager --set-enabled powertools
sudo dnf install epel-release -y

Configurar librerías
sudo nano /etc/ld.so.conf.d/local.conf


Agregar:

/usr/local/lib
/usr/local/lib64


Actualizar:

sudo ldconfig

Instalación de paquetes de compilación
sudo dnf install -y gcc flex bison zlib zlib-devel libpcap libpcap-devel \
pcre pcre-devel tcpdump openssl openssl-devel hwloc hwloc-devel cmake git make autoconf automake \
libtool libnet libnet-devel libyaml libyaml-devel doxygen rpm-build libmnl libmnl-devel nano which

sudo dnf groupinstall "Development Tools" -y
sudo dnf install check-devel -y

Instalar libdnet
cd /tmp
wget https://github.com/ofalk/libdnet/archive/refs/tags/libdnet-1.16.tar.gz
tar -xvzf libdnet-1.16.tar.gz
cd libdnet-libdnet-1.16
./configure --prefix=/usr
make
sudo make install

Instalar libdaq
git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make
sudo make install
sudo ldconfig

Clonar e instalar Snort 3
git clone https://github.com/snort3/snort3
cd snort3

Variables de entorno
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:$PKG_CONFIG_PATH
export CFLAGS="-O3"
export CXXFLAGS="-O3 -fno-rtti"

Configurar Snort
./configure_cmake.sh --prefix=/usr/local/snort --enable-tcmalloc
cd build
make -j$(nproc)
sudo make install
sudo ldconfig


Crear enlace:

sudo ln -s /usr/local/snort/bin/snort /usr/bin/snort


Ver versión:

snort -V

Configurar Snort (HOME_NET)

Editar:

sudo nano /usr/local/snort/etc/snort/snort.lua


Cambiar la línea a:

HOME_NET = '10.0.0.148/24'


Probar configuración:

snort -T -c /usr/local/snort/etc/snort/snort.lua

Modo promiscuo en tu interfaz ens160
sudo ip link set dev ens160 promisc on

Reglas locales de Snort
sudo nano /usr/local/snort/etc/snort/local.rules


Agregar:

alert icmp any any -> $HOME_NET any (msg:"ICMP Detected"; sid:10000001;)

alert tcp any any -> $HOME_NET 80 (msg:"HTTP Detected"; sid:10000002;)

alert tcp any any -> $HOME_NET 22 (msg:"SSH Detected"; sid:10000003;)

alert tcp any any -> $HOME_NET 8080 (msg:"HTTP-ALT Detected"; sid:10000004;)

alert tcp any any -> $HOME_NET 21 (msg:"FTP Detected"; sid:10000005;)

Ejecutar Snort
sudo snort -c /usr/local/snort/etc/snort/snort.lua \
-R /usr/local/snort/etc/snort/local.rules \
-i ens160 -A alert_fast -s 65535 -k none

=========================================================================================================================
PRÁCTICA 4 — Configuración de 2FA en SSH
=========================================================================================================================
Instalar dependencias
sudo dnf install epel-release -y
sudo dnf install google-authenticator qrencode -y

Configurar Google Authenticator

Ejecutar desde tu usuario:

google-authenticator

Configurar PAM
sudo nano /etc/pam.d/sshd


Agregar al inicio:

auth required pam_google_authenticator.so

Configurar el demonio SSH
sudo nano /etc/ssh/sshd_config


Editar:

PasswordAuthentication yes
ChallengeResponseAuthentication yes
UsePAM yes

Reiniciar el servicio
sudo systemctl restart sshd

=========================================================================================================================
DOCUMENTO COMPLETO FINALIZADO
=========================================================================================================================
